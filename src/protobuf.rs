//! protobuf.rs — Manual protobuf varint encoder/decoder + CrEaTe_ProTo equivalent.
//!
//! This is a schema-less protobuf parser (like the Python `protobuf_decoder` library).
//! It handles wire types: varint (0), 64-bit (1), length-delimited (2), 32-bit (5).

use std::collections::BTreeMap;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
//  DATA TYPES
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "wire_type", content = "data")]
pub enum ProtoData {
    #[serde(rename = "varint")]
    Varint(i64),
    #[serde(rename = "string")]
    Str(String),
    #[serde(rename = "bytes")]
    Bytes(Vec<u8>),
    #[serde(rename = "length_delimited")]
    LenDelim(ProtoFields),
    #[serde(rename = "fixed64")]
    Fixed64(u64),
    #[serde(rename = "fixed32")]
    Fixed32(u32),
}

/// A parsed protobuf message: field_number → data.
/// Uses BTreeMap so field ordering is stable during re-encode.
pub type ProtoFields = BTreeMap<u32, ProtoData>;

// ═══════════════════════════════════════════════════════════════
//  VARINT ENCODE / DECODE
// ═══════════════════════════════════════════════════════════════

/// Encode an unsigned integer as a protobuf varint.
pub fn encode_varint(mut n: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    loop {
        let mut byte = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
    out
}

/// Decode a varint from `buf` starting at `pos`. Returns (value, new_pos).
fn decode_varint(buf: &[u8], pos: usize) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut i = pos;
    loop {
        if i >= buf.len() {
            bail!("varint: unexpected end of buffer at pos={i}");
        }
        let b = buf[i] as u64;
        i += 1;
        result |= (b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            bail!("varint: overflow");
        }
    }
    Ok((result, i))
}

// ═══════════════════════════════════════════════════════════════
//  DECODE (get_available_room equivalent)
// ═══════════════════════════════════════════════════════════════

/// Parse raw protobuf bytes (not hex) into `ProtoFields`.
pub fn decode_proto_bytes(buf: &[u8]) -> Result<ProtoFields> {
    let mut fields = ProtoFields::new();
    let mut pos = 0usize;

    while pos < buf.len() {
        // Tag = field_number << 3 | wire_type
        let (tag, new_pos) = decode_varint(buf, pos)?;
        pos = new_pos;
        let wire_type = (tag & 0x07) as u8;
        let field_num = (tag >> 3) as u32;

        match wire_type {
            // Varint
            0 => {
                let (val, new_pos) = decode_varint(buf, pos)?;
                pos = new_pos;
                fields.insert(field_num, ProtoData::Varint(val as i64));
            }
            // 64-bit fixed
            1 => {
                if pos + 8 > buf.len() {
                    bail!("fixed64: not enough bytes");
                }
                let val = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                pos += 8;
                fields.insert(field_num, ProtoData::Fixed64(val));
            }
            // Length-delimited (string, bytes, embedded message)
            2 => {
                let (len, new_pos) = decode_varint(buf, pos)?;
                pos = new_pos;
                let len = len as usize;
                if pos + len > buf.len() {
                    bail!("LEN: not enough bytes (need {len}, have {})", buf.len() - pos);
                }
                let data = &buf[pos..pos + len];
                pos += len;

                // Try to interpret as UTF-8 string first, then as nested message, then raw bytes
                let proto_data = if let Ok(s) = std::str::from_utf8(data) {
                    ProtoData::Str(s.to_string())
                } else if let Ok(nested) = decode_proto_bytes(data) {
                    if nested.is_empty() {
                        ProtoData::Bytes(data.to_vec())
                    } else {
                        ProtoData::LenDelim(nested)
                    }
                } else {
                    ProtoData::Bytes(data.to_vec())
                };
                fields.insert(field_num, proto_data);
            }
            // 32-bit fixed
            5 => {
                if pos + 4 > buf.len() {
                    bail!("fixed32: not enough bytes");
                }
                let val = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
                pos += 4;
                fields.insert(field_num, ProtoData::Fixed32(val));
            }
            wt => {
                bail!("Unknown wire type {wt} at pos={}", pos - 1);
            }
        }
    }

    Ok(fields)
}

/// Parse from hex string (mirrors Python `get_available_room(hex_string)`).
pub fn decode_proto_hex(hex_str: &str) -> Result<ProtoFields> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| anyhow::anyhow!("decode_proto_hex: {e}"))?;
    decode_proto_bytes(&bytes)
}

// ═══════════════════════════════════════════════════════════════
//  ENCODE (CrEaTe_ProTo equivalent)
// ═══════════════════════════════════════════════════════════════

/// Encode a length-delimited field: tag + varint(len) + data.
fn encode_len_delimited(field_num: u32, data: &[u8]) -> Vec<u8> {
    let tag = encode_varint(((field_num as u64) << 3) | 2);
    let len = encode_varint(data.len() as u64);
    let mut out = tag;
    out.extend(len);
    out.extend_from_slice(data);
    out
}

/// Encode a varint field: tag + varint(value).
fn encode_varint_field(field_num: u32, val: u64) -> Vec<u8> {
    let tag = encode_varint(((field_num as u64) << 3) | 0);
    let mut out = tag;
    out.extend(encode_varint(val));
    out
}

/// Serialize `ProtoFields` back to protobuf bytes (CrEaTe_ProTo).
pub fn encode_proto(fields: &ProtoFields) -> Vec<u8> {
    let mut out = Vec::new();
    for (&field_num, data) in fields {
        match data {
            ProtoData::Varint(v) => {
                out.extend(encode_varint_field(field_num, *v as u64));
            }
            ProtoData::Str(s) => {
                out.extend(encode_len_delimited(field_num, s.as_bytes()));
            }
            ProtoData::Bytes(b) => {
                out.extend(encode_len_delimited(field_num, b));
            }
            ProtoData::LenDelim(nested) => {
                let nested_bytes = encode_proto(nested);
                out.extend(encode_len_delimited(field_num, &nested_bytes));
            }
            ProtoData::Fixed64(v) => {
                let tag = encode_varint(((field_num as u64) << 3) | 1);
                out.extend(tag);
                out.extend_from_slice(&v.to_le_bytes());
            }
            ProtoData::Fixed32(v) => {
                let tag = encode_varint(((field_num as u64) << 3) | 5);
                out.extend(tag);
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════
//  HELPERS — field access
// ═══════════════════════════════════════════════════════════════

/// Get the integer value of a varint field, if present.
pub fn get_varint(fields: &ProtoFields, field_num: u32) -> Option<i64> {
    match fields.get(&field_num)? {
        ProtoData::Varint(v) => Some(*v),
        _ => None,
    }
}

/// Get the string value of a string field, if present.
pub fn get_str<'a>(fields: &'a ProtoFields, field_num: u32) -> Option<&'a str> {
    match fields.get(&field_num)? {
        ProtoData::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

/// Set a varint field (insert or replace).
pub fn set_varint(fields: &mut ProtoFields, field_num: u32, val: i64) {
    fields.insert(field_num, ProtoData::Varint(val));
}

/// Set a string field (insert or replace).
pub fn set_str(fields: &mut ProtoFields, field_num: u32, val: impl Into<String>) {
    fields.insert(field_num, ProtoData::Str(val.into()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        for &n in &[0u64, 1, 127, 128, 300, 65535, 1_000_000] {
            let encoded = encode_varint(n);
            let (decoded, _) = decode_varint(&encoded, 0).unwrap();
            assert_eq!(decoded, n, "round-trip failed for {n}");
        }
    }

    #[test]
    fn proto_round_trip() {
        let mut fields = ProtoFields::new();
        fields.insert(1, ProtoData::Varint(12345));
        fields.insert(2, ProtoData::Str("hello world".into()));
        fields.insert(7, ProtoData::Str("1.123.1".into()));

        let encoded = encode_proto(&fields);
        let decoded = decode_proto_bytes(&encoded).unwrap();

        assert_eq!(get_varint(&decoded, 1), Some(12345));
        assert_eq!(get_str(&decoded, 2), Some("hello world"));
        assert_eq!(get_str(&decoded, 7), Some("1.123.1"));
    }
}
