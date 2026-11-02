//! Minimal NEAR transaction encoding (Borsh), just enough for a `Transfer`.
//!
//! Layout follows NEAR's `Transaction` (v0) schema:
//!   signer_id: string | public_key: enum(u8) + [u8;32] | nonce: u64
//!   receiver_id: string | block_hash: [u8;32] | actions: vec<Action>
//! Borsh: integers little-endian, strings and vecs prefixed with a u32 length.
//!
//! This module is pure (no IC calls) so it can be tested natively against
//! vectors produced by NEAR's own JS library (`tests/vectors/near-tx.json`).

use sha2::{Digest, Sha256};

/// Borsh enum index of `KeyType::ED25519` and `Signature::ED25519`.
const KEY_TYPE_ED25519: u8 = 0;
/// Borsh enum index of `Action::Transfer`
/// (CreateAccount=0, DeployContract=1, FunctionCall=2, Transfer=3, ...).
const ACTION_TRANSFER: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub signer_id: String,
    pub public_key: [u8; 32],
    pub nonce: u64,
    pub receiver_id: String,
    pub block_hash: [u8; 32],
    pub yocto: u128,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AccountIdError {
    Length,
    Character,
    Separator,
}

/// NEAR account id rules: 2..=64 chars, lowercase alphanumerics, parts separated
/// by `.`, and `-`/`_` only between alphanumerics.
pub fn validate_account_id(id: &str) -> Result<(), AccountIdError> {
    if id.len() < 2 || id.len() > 64 {
        return Err(AccountIdError::Length);
    }
    let mut prev_sep = true; // start counts as a separator: no leading separator
    for c in id.chars() {
        match c {
            'a'..='z' | '0'..='9' => prev_sep = false,
            '-' | '_' | '.' => {
                if prev_sep {
                    return Err(AccountIdError::Separator);
                }
                prev_sep = true;
            }
            _ => return Err(AccountIdError::Character),
        }
    }
    if prev_sep {
        return Err(AccountIdError::Separator);
    }
    Ok(())
}

/// Implicit account id of an ed25519 key: lowercase hex of the 32 key bytes.
pub fn implicit_account_id(public_key: &[u8; 32]) -> String {
    hex::encode(public_key)
}

/// NEAR RPC prints block hashes in base58; we need the 32 raw bytes.
pub fn decode_block_hash(b58: &str) -> Result<[u8; 32], String> {
    let raw = bs58::decode(b58)
        .into_vec()
        .map_err(|e| format!("block_hash is not base58: {e}"))?;
    raw.try_into()
        .map_err(|v: Vec<u8>| format!("block_hash must be 32 bytes, got {}", v.len()))
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_u32(out, u32::try_from(s.len()).expect("account ids are at most 64 bytes"));
    out.extend_from_slice(s.as_bytes());
}

impl Transfer {
    /// Borsh bytes of the unsigned transaction.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        put_str(&mut out, &self.signer_id);
        out.push(KEY_TYPE_ED25519);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        put_str(&mut out, &self.receiver_id);
        out.extend_from_slice(&self.block_hash);
        put_u32(&mut out, 1); // one action
        out.push(ACTION_TRANSFER);
        out.extend_from_slice(&self.yocto.to_le_bytes());
        out
    }

    /// What NEAR signs: SHA-256 of the Borsh-encoded transaction.
    pub fn signing_hash(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }

    /// Borsh bytes of the `SignedTransaction` ready for `send_tx`.
    pub fn encode_signed(&self, signature: &[u8; 64]) -> Vec<u8> {
        let mut out = self.encode();
        out.push(KEY_TYPE_ED25519);
        out.extend_from_slice(signature);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_id_rules() {
        for ok in ["bob.testnet", "a1", "guard_x-y.near", &"a".repeat(64)] {
            assert_eq!(validate_account_id(ok), Ok(()), "{ok}");
        }
        assert_eq!(validate_account_id("a"), Err(AccountIdError::Length));
        assert_eq!(validate_account_id(&"a".repeat(65)), Err(AccountIdError::Length));
        assert_eq!(validate_account_id("Bob.near"), Err(AccountIdError::Character));
        assert_eq!(validate_account_id(".bob"), Err(AccountIdError::Separator));
        assert_eq!(validate_account_id("bob..near"), Err(AccountIdError::Separator));
        assert_eq!(validate_account_id("bob-"), Err(AccountIdError::Separator));
    }

    #[test]
    fn block_hash_base58() {
        // 32 zero bytes are 32 '1's in base58 (each leading zero byte is one '1').
        assert_eq!(decode_block_hash(&"1".repeat(32)), Ok([0u8; 32]));
        let h = [0xaa; 32];
        assert_eq!(decode_block_hash(&bs58::encode(h).into_string()), Ok(h));
        assert!(decode_block_hash("111").is_err()); // too short
        assert!(decode_block_hash("0OIl").is_err()); // not in the alphabet
    }
}
