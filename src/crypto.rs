//! crypto.rs — AES-128-CBC encrypt/decrypt (mirrors Python pycryptodome usage).

use aes::Aes128;
use aes::cipher::KeyIvInit;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use cbc::{Decryptor, Encryptor};
use block_padding::Pkcs7;
use anyhow::{Context, Result};

use crate::config::{AES_KEY, AES_IV};

type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;

/// Decrypt AES-128-CBC + PKCS7.  
/// Accepts a lowercase hex string.
pub fn aes_decrypt(cipher_hex: &str) -> Result<Vec<u8>> {
    let cipher_bytes = hex::decode(cipher_hex.trim())
        .with_context(|| format!("aes_decrypt: bad hex input (len={})", cipher_hex.len()))?;
    aes_decrypt_bytes(&cipher_bytes)
}

pub fn aes_decrypt_bytes(cipher_bytes: &[u8]) -> Result<Vec<u8>> {
    let block_size = 16usize;

    // Pad to block boundary if needed (mirrors Python behaviour)
    let mut buf = cipher_bytes.to_vec();
    if buf.len() % block_size != 0 {
        let pad = block_size - (buf.len() % block_size);
        buf.resize(buf.len() + pad, 0);
    }

    let decryptor = Aes128CbcDec::new(&AES_KEY.into(), &AES_IV.into());
    let result = decryptor.decrypt_padded_mut::<Pkcs7>(&mut buf);

    match result {
        Ok(plaintext) => Ok(plaintext.to_vec()),
        Err(_) => {
            // Fallback: return raw decrypted bytes without unpadding
            // (mirrors Python's try/except ValueError → return decrypted)
            let mut buf2 = cipher_bytes.to_vec();
            if buf2.len() % block_size != 0 {
                let pad = block_size - (buf2.len() % block_size);
                buf2.resize(buf2.len() + pad, 0);
            }
            let decryptor2 = Aes128CbcDec::new(&AES_KEY.into(), &AES_IV.into());
            decryptor2
                .decrypt_padded_mut::<block_padding::NoPadding>(&mut buf2)
                .map(|b| b.to_vec())
                .map_err(|_| anyhow::anyhow!("aes_decrypt: decryption failed"))
        }
    }
}

/// Encrypt AES-128-CBC + PKCS7. Returns lowercase hex string.
pub fn encrypt_api(plain: &[u8]) -> Result<String> {
    let block_size = 16usize;
    let pad_len = block_size - (plain.len() % block_size);
    let padded_len = plain.len() + pad_len;

    let mut buf = vec![0u8; padded_len];
    buf[..plain.len()].copy_from_slice(plain);

    let encryptor = Aes128CbcEnc::new(&AES_KEY.into(), &AES_IV.into());
    let ciphertext = encryptor
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plain.len())
        .map_err(|e| anyhow::anyhow!("encrypt_api: padding error: {:?}", e))?;

    Ok(hex::encode(ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let plaintext = b"Hello, Xenitronix!";
        let encrypted = encrypt_api(plaintext).unwrap();
        let decrypted = aes_decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }
}
