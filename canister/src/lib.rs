//! Spike: an ICP canister that owns a NEAR account through a threshold
//! Ed25519 key and signs NEAR transfers. No single machine ever holds the key.
//!
//! The NEAR account is the *implicit* account of the canister's public key
//! (`hex(public_key)`): funding it creates it, with that key as its only
//! full-access key.
//!
//! Spike scope: only the owner (the identity that installed the canister) may
//! request signatures. The policy engine comes after this proves the path works.

pub mod near_tx;

use candid::{CandidType, Deserialize, Principal};
use ed25519_dalek::{Signature, VerifyingKey};
use ic_cdk::api::msg_caller;
use ic_cdk_management_canister::{
    schnorr_public_key, sign_with_schnorr, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgs,
    SignWithSchnorrArgs,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use near_tx::{decode_block_hash, implicit_account_id, validate_account_id, Transfer};
use std::cell::RefCell;

/// Every key this canister derives lives under this path. Changing it changes
/// the NEAR account.
const DERIVATION_PATH: &[u8] = b"near-icp-guard/agent/0";
/// `test_key_1` exists on mainnet (cheaper, for testing) and — per the icp-cli
/// examples — on the local network. Production is `key_1`.
const DEFAULT_KEY_NAME: &str = "test_key_1";

#[derive(CandidType, Deserialize)]
pub struct InitArgs {
    pub key_name: Option<String>,
}

#[derive(CandidType, Deserialize, Clone)]
pub struct Account {
    pub public_key_hex: String,
    /// NEAR's `ed25519:<base58>` notation, as `near-cli` and RPC print it.
    pub public_key_near: String,
    pub account_id: String,
}

#[derive(CandidType, Deserialize)]
pub struct TransferRequest {
    pub receiver_id: String,
    /// Amount in yoctoNEAR as a decimal string (u128 does not fit candid's nat64).
    pub yocto: String,
    /// Access-key nonce + 1. Untrusted: a wrong value only makes NEAR reject the tx.
    pub nonce: u64,
    /// Hash of a recent block, base58 as NEAR RPC prints it. Untrusted too.
    pub block_hash: String,
}

#[derive(CandidType, Deserialize)]
pub struct SignedTransfer {
    /// Borsh `SignedTransaction`, base64 — exactly what RPC `send_tx` takes.
    pub signed_tx_base64: String,
    /// Base58 of the signing hash — NEAR's transaction id.
    pub tx_hash: String,
}

struct State {
    owner: Principal,
    key_name: String,
    public_key: Option<[u8; 32]>,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|s| f(s.borrow_mut().as_mut().expect("canister not initialised")))
}

fn key_id() -> SchnorrKeyId {
    SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Ed25519,
        name: with_state(|s| s.key_name.clone()),
    }
}

fn account_of(pk: &[u8; 32]) -> Account {
    Account {
        public_key_hex: hex::encode(pk),
        public_key_near: format!("ed25519:{}", bs58::encode(pk).into_string()),
        account_id: implicit_account_id(pk),
    }
}

#[ic_cdk::init]
fn init(args: Option<InitArgs>) {
    let key_name = args
        .and_then(|a| a.key_name)
        .unwrap_or_else(|| DEFAULT_KEY_NAME.to_string());
    STATE.with(|s| {
        *s.borrow_mut() = Some(State {
            owner: msg_caller(),
            key_name,
            public_key: None,
        })
    });
}

// Owner and key name survive upgrades; the public key is cheap to fetch again
// and derives the same NEAR account.
#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    let (owner, key_name) = with_state(|s| (s.owner, s.key_name.clone()));
    ic_cdk::storage::stable_save((owner, key_name)).expect("saving state failed");
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    let (owner, key_name): (Principal, String) =
        ic_cdk::storage::stable_restore().expect("restoring state failed");
    STATE.with(|s| {
        *s.borrow_mut() = Some(State {
            owner,
            key_name,
            public_key: None,
        })
    });
}

/// Fetches (once) and returns the canister's NEAR account. Update call, because
/// it asks the management canister.
#[ic_cdk::update]
async fn account() -> Result<Account, String> {
    if let Some(pk) = with_state(|s| s.public_key) {
        return Ok(account_of(&pk));
    }
    let res = schnorr_public_key(&SchnorrPublicKeyArgs {
        canister_id: None,
        derivation_path: vec![DERIVATION_PATH.to_vec()],
        key_id: key_id(),
    })
    .await
    .map_err(|e| format!("schnorr_public_key failed: {e:?}"))?;
    let pk: [u8; 32] = res
        .public_key
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 32-byte ed25519 key, got {} bytes", v.len()))?;
    with_state(|s| s.public_key = Some(pk));
    Ok(account_of(&pk))
}

fn build(req: &TransferRequest) -> Result<Transfer, String> {
    let pk = with_state(|s| s.public_key).ok_or("call `account` once first")?;
    validate_account_id(&req.receiver_id).map_err(|e| format!("receiver_id invalid: {e:?}"))?;
    let yocto: u128 = req.yocto.parse().map_err(|_| "yocto must be a decimal u128")?;
    let block_hash = decode_block_hash(&req.block_hash)?;
    Ok(Transfer {
        signer_id: implicit_account_id(&pk),
        public_key: pk,
        nonce: req.nonce,
        receiver_id: req.receiver_id.clone(),
        block_hash,
        yocto,
    })
}

/// The exact unsigned bytes `sign_transfer` would sign, as hex. Lets the script
/// compare them with what `@near-js/transactions` builds for the same input.
#[ic_cdk::query]
fn preview_transfer(req: TransferRequest) -> Result<String, String> {
    Ok(hex::encode(build(&req)?.encode()))
}

#[ic_cdk::update]
async fn sign_transfer(req: TransferRequest) -> Result<SignedTransfer, String> {
    if msg_caller() != with_state(|s| s.owner) {
        return Err("only the owner may request signatures (spike)".into());
    }
    let tx = build(&req)?;
    let hash = tx.signing_hash();

    let res = sign_with_schnorr(&SignWithSchnorrArgs {
        message: hash.to_vec(),
        derivation_path: vec![DERIVATION_PATH.to_vec()],
        key_id: key_id(),
        aux: None,
    })
    .await
    .map_err(|e| format!("sign_with_schnorr failed: {e:?}"))?;
    let sig: [u8; 64] = res
        .signature
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 64-byte signature, got {} bytes", v.len()))?;

    // Verify before returning: if ICP signed something other than what NEAR
    // will check (e.g. a pre-hashed variant), fail here with a clear message
    // instead of getting an opaque "InvalidSignature" from the network.
    let vk = VerifyingKey::from_bytes(&tx.public_key).map_err(|e| format!("bad key: {e}"))?;
    vk.verify_strict(&hash, &Signature::from_bytes(&sig))
        .map_err(|e| format!("threshold signature does not verify over the NEAR hash: {e}"))?;

    Ok(SignedTransfer {
        signed_tx_base64: BASE64.encode(tx.encode_signed(&sig)),
        tx_hash: bs58::encode(hash).into_string(),
    })
}

ic_cdk::export_candid!();

#[cfg(test)]
mod candid_tests {
    /// The checked-in `guard.did` must describe exactly what the Rust code exports.
    #[test]
    fn did_file_matches_code() {
        use candid_parser::utils::{service_equal, CandidSource};
        let code = super::__export_service();
        service_equal(
            CandidSource::Text(&code),
            CandidSource::Text(include_str!("../guard.did")),
        )
        .unwrap_or_else(|e| panic!("guard.did is out of date:\n{e}\n\ngenerated:\n{code}"));
    }
}
