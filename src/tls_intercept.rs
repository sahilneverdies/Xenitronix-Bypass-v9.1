//! tls_intercept.rs — TLS MITM interception engine.
//!
//! Architecture:
//!   - Runs on VPS (Linux) at omega.vexanode.cloud:2039
//!   - BlueStacks is configured to use VPS as HTTP proxy
//!   - BlueStacks has the mitmproxy CA cert installed (via C# installer)
//!   - This module loads mitmproxy-ca.pem (cert + privkey) from disk
//!   - For every HTTPS CONNECT, generates a per-hostname cert signed by our CA
//!   - BlueStacks trusts it because the CA is installed in Android system store
//!   - Full HTTPS interception: decrypt → patch → re-encrypt

use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use rcgen::{
    Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info};

use crate::config::{CA_PEM_PATH, CA_PEM_PATH_DEFAULT};

// ═══════════════════════════════════════════════════════════════
//  CA AUTHORITY  — loaded once at startup
// ═══════════════════════════════════════════════════════════════

pub struct CertAuthority {
    /// rcgen CA Certificate (used to sign per-host certs)
    ca_cert: Certificate,
    /// CA keypair (needed for signing)
    ca_key:  KeyPair,
    /// Raw CA DER bytes (included in TLS chain sent to clients)
    ca_der:  CertificateDer<'static>,
    /// Per-hostname ServerConfig cache (avoids keygen on every connection)
    cache:   DashMap<String, Arc<ServerConfig>>,
    /// TLS config for connecting to real upstream servers
    client_tls: Arc<ClientConfig>,
}

impl CertAuthority {
    /// Load from disk. Searches:
    ///   1. `./mitmproxy-ca.pem`  (same dir as binary)
    ///   2. `~/.mitmproxy/mitmproxy-ca.pem`
    pub fn load() -> Result<Arc<Self>> {
        let pem_bytes = Self::find_ca()?;
        let pem_str = std::str::from_utf8(&pem_bytes)?;

        // ── Parse private key ──────────────────────────────────
        let ca_key = KeyPair::from_pem(pem_str)
            .context("Failed to parse CA private key from mitmproxy-ca.pem")?;

        // ── Parse CA cert DER (for chain) ──────────────────────
        let ca_der: CertificateDer<'static> = {
            let mut reader = BufReader::new(pem_bytes.as_slice());
            let der = rustls_pemfile::certs(&mut reader)
                .next()
                .ok_or_else(|| anyhow!("No cert found in mitmproxy-ca.pem"))?
                .context("Failed to read cert DER")?;
            der
        };

        // ── Build rcgen CA cert from params ────────────────────
        // We reconstruct params from the known mitmproxy CA values
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::OrganizationName, "mitmproxy");
        ca_params.distinguished_name.push(DnType::CommonName, "mitmproxy");
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];

        let ca_cert = ca_params
            .self_signed(&ca_key)
            .context("Failed to reconstruct CA cert from params")?;

        // ── Client TLS config (for upstream connections) ────────
        let client_tls = Self::build_client_config(&ca_der)?;

        info!("[TLS] CA loaded — mitmproxy cert ready for per-host signing");
        Ok(Arc::new(Self {
            ca_cert,
            ca_key,
            ca_der,
            cache: DashMap::new(),
            client_tls: Arc::new(client_tls),
        }))
    }

    fn find_ca() -> Result<Vec<u8>> {
        // 1. Same directory as binary
        if Path::new(CA_PEM_PATH).exists() {
            info!("[TLS] Loading CA from ./{CA_PEM_PATH}");
            return Ok(std::fs::read(CA_PEM_PATH)?);
        }
        // 2. ~/.mitmproxy/mitmproxy-ca.pem
        if let Some(home) = dirs::home_dir() {
            let p = home.join(CA_PEM_PATH_DEFAULT);
            if p.exists() {
                info!("[TLS] Loading CA from {}", p.display());
                return Ok(std::fs::read(&p)?);
            }
        }
        Err(anyhow!(
            "CA cert not found!\n\
             Place mitmproxy-ca.pem next to the xenitronix binary on your VPS.\n\
             (or it auto-loads from ~/.mitmproxy/mitmproxy-ca.pem)"
        ))
    }

    /// Get (or generate+cache) a TlsAcceptor for a given hostname.
    pub fn get_acceptor(&self, host: &str) -> Result<TlsAcceptor> {
        let hostname = host.split(':').next().unwrap_or(host).to_string();

        if let Some(cfg) = self.cache.get(&hostname) {
            debug!("[TLS] Cache hit: {hostname}");
            return Ok(TlsAcceptor::from(cfg.clone()));
        }

        debug!("[TLS] Generating cert for {hostname}");
        let cfg = Arc::new(self.make_server_config(&hostname)?);
        self.cache.insert(hostname, cfg.clone());
        Ok(TlsAcceptor::from(cfg))
    }

    /// Generate a per-hostname TLS ServerConfig signed by our CA.
    fn make_server_config(&self, hostname: &str) -> Result<ServerConfig> {
        // Build per-host cert params
        let mut params = CertificateParams::new(vec![hostname.to_string()])
            .context("Invalid hostname for cert")?;

        params.distinguished_name.push(DnType::CommonName, hostname);
        params.distinguished_name.push(DnType::OrganizationName, "mitmproxy");
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after  = rcgen::date_time_ymd(2027, 12, 31);

        // Fresh key for this hostname
        let host_key = KeyPair::generate().context("Failed to generate host key")?;

        // Sign with our CA cert + CA key
        let host_cert = params
            .signed_by(&host_key, &self.ca_cert, &self.ca_key)
            .context("Failed to sign host cert with CA")?;

        let cert_der = CertificateDer::from(host_cert.der().to_vec());
        let key_der  = PrivateKeyDer::try_from(host_key.serialize_der())
            .map_err(|e| anyhow!("Key serialization error: {e}"))?;

        // Chain: [host_cert, ca_cert] — client verifies chain up to installed CA
        let chain = vec![cert_der, self.ca_der.clone()];

        let server_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key_der)
            .context("Failed to build ServerConfig")?;

        Ok(server_cfg)
    }

    /// TLS connector for upstream (real game server) connections.
    pub fn make_connector(&self) -> TlsConnector {
        TlsConnector::from(self.client_tls.clone())
    }

    fn build_client_config(ca_der: &CertificateDer<'static>) -> Result<ClientConfig> {
        let mut root_store = RootCertStore::empty();
        // Trust standard internet CAs
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Also trust our own CA (in case game servers use self-signed certs)
        let _ = root_store.add(ca_der.clone());

        Ok(ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth())
    }
}
