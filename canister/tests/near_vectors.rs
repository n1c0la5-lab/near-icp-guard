//! Our Borsh encoder against vectors produced by NEAR's own JS library.
//! Regenerate with `node scripts/reference-vector.mjs` — never by hand.

use guard::near_tx::{implicit_account_id, Transfer};
use serde::Deserialize;

#[derive(Deserialize)]
struct File {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    public_key: String,
    signer_id: String,
    receiver_id: String,
    nonce: String,
    block_hash: String,
    yocto: String,
    signature: String,
    tx: String,
    tx_sha256: String,
    signed_tx: String,
}

fn arr<const N: usize>(h: &str) -> [u8; N] {
    hex::decode(h).unwrap().try_into().unwrap()
}

fn cases() -> Vec<Case> {
    let raw = include_str!("vectors/near-tx.json");
    let file: File = serde_json::from_str(raw).unwrap();
    assert!(file.cases.len() >= 3, "vector file lost cases");
    file.cases
}

fn transfer(c: &Case) -> Transfer {
    Transfer {
        signer_id: c.signer_id.clone(),
        public_key: arr(&c.public_key),
        nonce: c.nonce.parse().unwrap(),
        receiver_id: c.receiver_id.clone(),
        block_hash: arr(&c.block_hash),
        yocto: c.yocto.parse().unwrap(),
    }
}

#[test]
fn unsigned_bytes_match_near_js() {
    for c in cases() {
        assert_eq!(hex::encode(transfer(&c).encode()), c.tx, "case {}", c.name);
    }
}

#[test]
fn signing_hash_matches_near_js() {
    for c in cases() {
        assert_eq!(hex::encode(transfer(&c).signing_hash()), c.tx_sha256, "case {}", c.name);
    }
}

#[test]
fn signed_bytes_match_near_js() {
    for c in cases() {
        let sig: [u8; 64] = arr(&c.signature);
        assert_eq!(hex::encode(transfer(&c).encode_signed(&sig)), c.signed_tx, "case {}", c.name);
    }
}

#[test]
fn implicit_account_matches_near_js() {
    // In these vectors, a 64-char signer id was computed by NEAR's
    // `keyToImplicitAddress` from the case's public key.
    let mut checked = 0;
    for c in cases().iter().filter(|c| c.signer_id.len() == 64) {
        assert_eq!(implicit_account_id(&arr(&c.public_key)), c.signer_id, "case {}", c.name);
        checked += 1;
    }
    assert!(checked > 0, "no implicit-account vector present");
}
