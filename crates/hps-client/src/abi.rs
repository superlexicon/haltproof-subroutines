//! Human-readable Ethereum/Lexicon ABI calldata encoder and return-value formatter.
//!
//! Supports signatures such as:
//! - `increment(bytes32,uint64)`
//! - `getCount(bytes32)`
//! - `setNote(bytes32,string)`
//! - `postMessage(bytes32,bytes)`
//! - `transfer(address,uint256)`

use anyhow::{anyhow, bail, Context, Result};
use ethereum_types::{H160, U256};
use sha3::{Digest, Keccak256};

/// Compute the 4-byte Keccak-256 function selector for a canonical signature (e.g. `"set(bytes32,uint64)"`).
pub fn function_selector(canonical_sig: &str) -> [u8; 4] {
    let digest = Keccak256::digest(canonical_sig.as_bytes());
    [digest[0], digest[1], digest[2], digest[3]]
}

/// Compute the 32-byte Keccak-256 hash of `bytes`.
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let digest = Keccak256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiValue {
    Uint(U256),
    Bool(bool),
    Address(H160),
    Bytes4([u8; 4]),
    Bytes32([u8; 32]),
    Bytes(Vec<u8>),
}

impl AbiValue {
    pub fn is_dynamic(&self) -> bool {
        matches!(self, AbiValue::Bytes(_))
    }
}

/// Normalize a signature like `"fn increment(bytes32 key, uint64 delta)"` or `"increment(bytes32, uint64)"`
/// into canonical `"increment(bytes32,uint64)"` and return `(canonical_sig, param_types)`.
pub fn parse_signature(raw_sig: &str) -> Result<(String, Vec<String>)> {
    let s = raw_sig.trim().strip_prefix("function ").unwrap_or(raw_sig.trim());
    let open = s
        .find('(')
        .ok_or_else(|| anyhow!("invalid function signature '{raw_sig}': missing '('"))?;
    let close = s
        .rfind(')')
        .ok_or_else(|| anyhow!("invalid function signature '{raw_sig}': missing ')'"))?;
    if close < open {
        bail!("invalid function signature '{raw_sig}'");
    }
    let name = s[..open].trim();
    if name.is_empty() {
        bail!("empty function name in '{raw_sig}'");
    }
    let inner = s[open + 1..close].trim();
    let mut types = Vec::new();
    if !inner.is_empty() {
        for part in inner.split(',') {
            let ty = part
                .split_whitespace()
                .next()
                .ok_or_else(|| anyhow!("empty parameter in '{raw_sig}'"))?;
            types.push(ty.to_string());
        }
    }
    let canonical = format!("{}({})", name, types.join(","));
    Ok((canonical, types))
}

/// Parse a CLI string argument according to its canonical Solidity/Lexicon ABI type.
pub fn parse_typed_arg(ty: &str, raw: &str) -> Result<AbiValue> {
    match ty {
        "bool" => match raw.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(AbiValue::Bool(true)),
            "false" | "0" => Ok(AbiValue::Bool(false)),
            _ => bail!("invalid bool '{raw}' (expected true/false)"),
        },
        "address" => {
            let clean = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
            let bytes = hex::decode(clean).with_context(|| format!("invalid hex address '{raw}'"))?;
            if bytes.len() != 20 {
                bail!("address must be 20 bytes (got {})", bytes.len());
            }
            Ok(AbiValue::Address(H160::from_slice(&bytes)))
        }
        "bytes4" => {
            if let Some(sig) = raw.trim().strip_prefix("sig:") {
                let (canonical, _) = parse_signature(sig)?;
                Ok(AbiValue::Bytes4(function_selector(&canonical)))
            } else {
                let clean = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
                let bytes =
                    hex::decode(clean).with_context(|| format!("invalid bytes4 hex '{raw}'"))?;
                if bytes.len() != 4 {
                    bail!("bytes4 must be 4 bytes (got {})", bytes.len());
                }
                Ok(AbiValue::Bytes4([bytes[0], bytes[1], bytes[2], bytes[3]]))
            }
        }
        "bytes32" => {
            if let Some(hex_str) = raw.trim().strip_prefix("0x") {
                let bytes = hex::decode(hex_str).with_context(|| format!("invalid bytes32 hex '{raw}'"))?;
                if bytes.len() > 32 {
                    bail!("bytes32 hex exceeds 32 bytes ({} bytes)", bytes.len());
                }
                let mut out = [0u8; 32];
                // Full 32-byte hash stays exact; shorter hex right-pads or left-pads? For bytes32, right-pad.
                out[..bytes.len()].copy_from_slice(&bytes);
                Ok(AbiValue::Bytes32(out))
            } else if let Some(label) = raw.trim().strip_prefix("keccak:") {
                Ok(AbiValue::Bytes32(keccak256(label.as_bytes())))
            } else {
                // Convenient plain-ASCII label right-padded to 32 bytes (or hashed if > 32 bytes)
                let b = raw.as_bytes();
                if b.len() > 32 {
                    bail!(
                        "plain string '{raw}' is {} bytes (> 32); pass 0x<64-hex> or keccak:<label>",
                        b.len()
                    );
                }
                let mut out = [0u8; 32];
                out[..b.len()].copy_from_slice(b);
                Ok(AbiValue::Bytes32(out))
            }
        }
        "string" => Ok(AbiValue::Bytes(raw.as_bytes().to_vec())),
        "bytes" => {
            if let Some(hex_str) = raw.trim().strip_prefix("0x") {
                let bytes = hex::decode(hex_str).with_context(|| format!("invalid hex bytes '{raw}'"))?;
                Ok(AbiValue::Bytes(bytes))
            } else {
                Ok(AbiValue::Bytes(raw.as_bytes().to_vec()))
            }
        }
        t if t.starts_with("uint") => {
            let bits: usize = t
                .strip_prefix("uint")
                .unwrap_or("256")
                .parse()
                .unwrap_or(256);
            let val = if let Some(h) = raw.trim().strip_prefix("0x") {
                U256::from_str_radix(h, 16).with_context(|| format!("invalid hex uint '{raw}'"))?
            } else {
                U256::from_dec_str(raw.trim()).with_context(|| format!("invalid decimal uint '{raw}'"))?
            };
            if bits < 256 && val >= (U256::one() << bits) {
                bail!("value {val} overflows {t}");
            }
            Ok(AbiValue::Uint(val))
        }
        other => bail!(
            "unsupported ABI parameter type '{other}' (supported: uint8..uint256, bool, address, bytes32, bytes, string)"
        ),
    }
}

/// Encode `AbiValue` arguments with a 4-byte function selector using standard head/tail ABI layout.
pub fn encode_values(canonical_sig: &str, values: &[AbiValue]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + values.len() * 32);
    out.extend_from_slice(&function_selector(canonical_sig));

    let head_len = values.len() * 32;
    let mut head = Vec::with_capacity(head_len);
    let mut tail = Vec::new();

    for val in values {
        match val {
            AbiValue::Uint(v) => {
                let mut w = [0u8; 32];
                v.to_big_endian(&mut w);
                head.extend_from_slice(&w);
            }
            AbiValue::Bool(b) => {
                let mut w = [0u8; 32];
                w[31] = u8::from(*b);
                head.extend_from_slice(&w);
            }
            AbiValue::Address(a) => {
                let mut w = [0u8; 32];
                w[12..32].copy_from_slice(a.as_bytes());
                head.extend_from_slice(&w);
            }
            AbiValue::Bytes4(b) => {
                let mut w = [0u8; 32];
                w[0..4].copy_from_slice(b);
                head.extend_from_slice(&w);
            }
            AbiValue::Bytes32(b) => {
                head.extend_from_slice(b);
            }
            AbiValue::Bytes(data) => {
                let offset = head_len + tail.len();
                let mut off_word = [0u8; 32];
                U256::from(offset).to_big_endian(&mut off_word);
                head.extend_from_slice(&off_word);

                let mut len_word = [0u8; 32];
                U256::from(data.len()).to_big_endian(&mut len_word);
                tail.extend_from_slice(&len_word);
                tail.extend_from_slice(data);
                let pad = (32 - (data.len() % 32)) % 32;
                tail.resize(tail.len() + pad, 0u8);
            }
        }
    }

    out.extend_from_slice(&head);
    out.extend_from_slice(&tail);
    out
}

/// Parse a human-readable signature and string arguments into ABI-encoded calldata.
pub fn encode_call_from_strings(raw_sig: &str, raw_args: &[String]) -> Result<Vec<u8>> {
    let (canonical, types) = parse_signature(raw_sig)?;
    if types.len() != raw_args.len() {
        bail!(
            "signature '{}' expects {} argument(s), but {} were provided",
            canonical,
            types.len(),
            raw_args.len()
        );
    }
    let mut values = Vec::with_capacity(types.len());
    for (ty, arg) in types.iter().zip(raw_args.iter()) {
        values.push(parse_typed_arg(ty, arg)?);
    }
    Ok(encode_values(&canonical, &values))
}

/// Try decoding ABI-encoded dynamic `bytes` / `string` (`[offset=0x20][len][data...]`).
pub fn try_decode_abi_bytes(ret: &[u8]) -> Option<&[u8]> {
    if ret.len() < 64 {
        return None;
    }
    if ret[0..31] != [0u8; 31] || ret[31] != 0x20 {
        return None;
    }
    if ret[32..56] != [0u8; 24] {
        return None;
    }
    let mut lb = [0u8; 8];
    lb.copy_from_slice(&ret[56..64]);
    let len = u64::from_be_bytes(lb) as usize;
    if 64 + len > ret.len() {
        return None;
    }
    Some(&ret[64..64 + len])
}

/// Try decoding a 32-byte ABI `uint256` / `uint64` word.
pub fn try_decode_u256(ret: &[u8]) -> Option<U256> {
    if ret.len() == 32 {
        Some(U256::from_big_endian(ret))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_post_message_identically_to_lexicon_node() {
        let ch_hex = format!("0x{}", "c0".repeat(32));
        let calldata = encode_call_from_strings(
            "postMessage(bytes32,bytes)",
            &[ch_hex, "hello".to_string()],
        )
        .unwrap();
        assert_eq!(calldata.len(), 132);
        assert_eq!(&calldata[0..4], &[0x48, 0x2f, 0x63, 0xb0]);
        assert_eq!(calldata[67], 0x40);
        assert_eq!(&calldata[92..100], &5u64.to_be_bytes());
        assert_eq!(&calldata[100..105], b"hello");
    }
}
