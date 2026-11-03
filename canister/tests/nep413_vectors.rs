//! Our NEP-413 encoder against signatures made by NEAR's own JS library
//! (near-api-js `KeyPairSigner.signNep413Message`). Each signature must verify
//! over the hash *our* code computes; any difference in tag, field order,
//! length prefixes or Option encoding makes it fail.
//! Regenerate with `node scripts/nep413-vector.mjs` — never by hand.

use ed25519_dalek::{Signature, VerifyingKey};
use guard::nep413::Payload;
use serde::Deserialize;

#[derive(Deserialize)]
struct File {
    generator: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    message: String,
    nonce: String,
    recipient: String,
    callback_url: Option<String>,
    public_key: String,
    signature: String,
}

fn arr<const N: usize>(h: &str) -> [u8; N] {
    hex::decode(h).unwrap().try_into().unwrap()
}

fn cases() -> Vec<Case> {
    let file: File = serde_json::from_str(include_str!("vectors/nep413.json")).unwrap();
    assert!(file.generator.starts_with("near-api-js "), "vectors not from near-api-js");
    assert!(file.cases.len() >= 4, "vector file lost cases");
    // The cases must keep covering both Option arms, Some("") and multi-byte text.
    assert!(file.cases.iter().any(|c| c.callback_url.is_none()));
    assert!(file.cases.iter().any(|c| c.callback_url.as_deref() == Some("")));
    assert!(file.cases.iter().any(|c| c.message.len() != c.message.chars().count()));
    file.cases
}

fn hash(c: &Case) -> [u8; 32] {
    Payload {
        message: &c.message,
        nonce: &arr(&c.nonce),
        recipient: &c.recipient,
        callback_url: c.callback_url.as_deref(),
    }
    .signing_hash()
}

fn verifies(c: &Case, hash: &[u8; 32]) -> bool {
    let vk = VerifyingKey::from_bytes(&arr(&c.public_key)).unwrap();
    vk.verify_strict(hash, &Signature::from_bytes(&arr(&c.signature))).is_ok()
}

#[test]
fn near_api_js_signatures_verify_over_our_hash() {
    for c in cases() {
        assert!(verifies(&c, &hash(&c)), "case {}: our NEP-413 hash differs from near-api-js", c.name);
    }
}

/// Guards the test above against passing vacuously: a hash one bit off must fail.
#[test]
fn a_different_hash_does_not_verify() {
    for c in cases() {
        let mut h = hash(&c);
        h[0] ^= 1;
        assert!(!verifies(&c, &h), "case {}: signature verified over a wrong hash", c.name);
    }
}
