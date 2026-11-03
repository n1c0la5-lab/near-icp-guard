//! Policy engine: who may ask for a signature, and which transfers it gets.
//!
//! Everything in this module is pure: no IC calls, no system time. The canister
//! (`lib.rs`) passes in the caller and the current time, and performs the
//! threshold signature *between* [`Guard::begin_sign`] and [`Guard::finish_sign`].
//!
//! That split is the point. Signing is an `await`, and other messages run while
//! a request waits for its signature. So `begin_sign` checks every rule and
//! **reserves** the amount against the daily budget in one synchronous step,
//! before the canister awaits anything. A second request that arrives during
//! the await sees the first one's reservation. `finish_sign` keeps the
//! reservation if a signature came back and releases it if signing failed.
//!
//! Roles:
//! - `owner`: the identity that installed the canister; never anonymous. Sets
//!   the agent and the policy. Cannot request signatures.
//! - `agent`: exactly one principal, set by the owner; never the owner, never
//!   anonymous. The only caller that may request signatures. Cannot change
//!   the agent or the policy.
//!
//! Rules, checked before every signature (safe default: everything denied):
//! 1. per-transaction limit, 2. daily limit per UTC day, 3. receiver allowlist.
//!
//! NEP-413 messages (off-chain signatures, [`Guard::begin_message`]) have their
//! own rule: the `recipient` must be on a separate owner allowlist, and
//! [`FORBIDDEN_NEP413_RECIPIENTS`] are refused even if the owner lists them.
//! A NEP-413 signature by this account's full-access key is an authorization
//! wherever the recipient accepts one; signing arbitrary messages would let the
//! agent step around the three transfer rules.
//!
//! Every protected method refuses the anonymous principal first, explicitly,
//! even where the role check would refuse it anyway.
//!
//! Audit log: sign requests from the owner and the agent are logged with their
//! outcome. Requests from anyone else are only counted
//! (`rejected_unauthorized`): if they were logged, any stranger could push the
//! real entries out of the bounded log.

use crate::near_tx::validate_account_id;
use candid::{CandidType, Deserialize, Principal};
use sha2::{Digest, Sha256};
use std::fmt;

pub const NANOS_PER_DAY: u64 = 86_400 * 1_000_000_000;
/// The audit log keeps the most recent entries; `seq` keeps counting.
pub const AUDIT_LOG_CAPACITY: usize = 1000;
pub const MAX_ALLOWLIST_LEN: usize = 100;
/// Caller-supplied strings are clipped before they go into the log.
const MAX_LOGGED_INPUT: usize = 64;
const MAX_LOGGED_REASON: usize = 256;

/// NEP-413 recipients the guard never signs for, whatever the policy says.
/// `intents.near` (NEAR Intents) executes NEP-413-signed intents — including
/// withdrawals to any address — when the key belongs to the signer's account,
/// so a signature for it would move funds outside the transfer rules.
/// Compared case-insensitively.
pub const FORBIDDEN_NEP413_RECIPIENTS: &[&str] = &["intents.near"];
pub const MAX_NEP413_RECIPIENTS: usize = 20;
pub const MAX_MESSAGE_BYTES: usize = 4096;
pub const MAX_RECIPIENT_BYTES: usize = 128;
pub const MAX_CALLBACK_URL_BYTES: usize = 512;
pub const NEP413_NONCE_BYTES: usize = 32;

/// UTC day number (days since the Unix epoch) of a timestamp in nanoseconds.
pub fn utc_day(now_ns: u64) -> u64 {
    now_ns / NANOS_PER_DAY
}

/// Strict decimal u128: digits only. (`str::parse` also accepts a leading `+`.)
pub fn parse_yocto(s: &str) -> Result<u128, Refusal> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refusal::InvalidAmount);
    }
    s.parse().map_err(|_| Refusal::InvalidAmount)
}

/// Why a call was refused. `Display` is the text callers and the log see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    AnonymousCaller,
    AnonymousOwner,
    NotOwner,
    NotOwnerOrAgent,
    AgentIsOwner,
    AgentIsAnonymous,
    InvalidPolicy(String),
    OwnerCannotSign,
    NoAgent,
    NotAgent,
    InvalidReceiver,
    InvalidAmount,
    ZeroAmount,
    OverPerTxLimit { amount: u128, limit: u128 },
    ReceiverNotAllowed(String),
    OverDailyLimit { spent: u128, amount: u128, limit: u128 },
    DailyOverflow,
    InvalidNonce(usize),
    InvalidMessage(&'static str),
    InvalidRecipient,
    InvalidCallbackUrl,
    RecipientForbidden(String),
    RecipientNotAllowed(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Refusal::*;
        match self {
            AnonymousCaller => write!(f, "rejected: anonymous caller"),
            AnonymousOwner => write!(f, "the anonymous principal cannot be the owner; install with your own identity"),
            NotOwner => write!(f, "only the owner may do this"),
            NotOwnerOrAgent => write!(f, "only the owner or the agent may read this"),
            AgentIsOwner => write!(f, "the agent must be a different principal than the owner"),
            AgentIsAnonymous => write!(f, "the anonymous principal cannot be the agent"),
            InvalidPolicy(why) => write!(f, "invalid policy: {why}"),
            OwnerCannotSign => write!(f, "rejected: the owner cannot request signatures, only the agent can"),
            NoAgent => write!(f, "rejected: no agent is set"),
            NotAgent => write!(f, "rejected: caller is not the agent"),
            InvalidReceiver => write!(f, "rejected: receiver_id is not a valid NEAR account id"),
            InvalidAmount => write!(f, "rejected: yocto must be a decimal u128"),
            ZeroAmount => write!(f, "rejected: amount must be greater than zero"),
            OverPerTxLimit { amount, limit } => write!(
                f,
                "rejected: {amount} yocto exceeds the per-transaction limit of {limit} yocto"
            ),
            ReceiverNotAllowed(r) => write!(f, "rejected: receiver {r} is not on the allowlist"),
            OverDailyLimit { spent, amount, limit } => write!(
                f,
                "rejected: {spent} yocto already signed today + {amount} yocto exceeds the daily limit of {limit} yocto"
            ),
            DailyOverflow => write!(f, "rejected: daily total would overflow u128"),
            InvalidNonce(n) => write!(f, "rejected: nonce must be exactly {NEP413_NONCE_BYTES} bytes, got {n}"),
            InvalidMessage(why) => write!(f, "rejected: message {why}"),
            InvalidRecipient => write!(
                f,
                "rejected: recipient must be 1 to {MAX_RECIPIENT_BYTES} printable ASCII characters without spaces"
            ),
            InvalidCallbackUrl => write!(
                f,
                "rejected: callback_url must be at most {MAX_CALLBACK_URL_BYTES} printable ASCII characters without spaces"
            ),
            RecipientForbidden(r) => write!(
                f,
                "rejected: NEP-413 messages for {r} are never signed (there a signature authorizes moving funds, outside this policy)"
            ),
            RecipientNotAllowed(r) => write!(f, "rejected: recipient {r} is not on the NEP-413 allowlist"),
        }
    }
}

/// The rules in their public (candid) form. Amounts are yoctoNEAR as decimal
/// strings, because u128 does not fit candid's nat64.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub per_tx_limit_yocto: String,
    pub daily_limit_yocto: String,
    pub allowlist: Vec<String>,
    /// Recipients the agent may get NEP-413 messages signed for. Separate from
    /// the transfer `allowlist`. `null` (or left out) = empty: nothing signed.
    pub nep413_recipients: Option<Vec<String>>,
}

/// The rules as the guard enforces them.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Rules {
    pub per_tx_limit: u128,
    pub daily_limit: u128,
    /// Validated NEAR account ids, sorted and deduplicated.
    pub allowlist: Vec<String>,
    /// Validated NEP-413 recipients, sorted and deduplicated. `Option` only so
    /// that state saved before this field existed still decodes (as empty).
    pub nep413_recipients: Option<Vec<String>>,
}

/// NEP-413 recipients are free-form strings (an app name, a domain, an account
/// id), so the check is about shape: printable ASCII, no spaces, bounded.
fn printable_ascii(s: &str) -> bool {
    s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn valid_recipient(r: &str) -> bool {
    !r.is_empty() && r.len() <= MAX_RECIPIENT_BYTES && printable_ascii(r)
}

pub fn is_forbidden_recipient(r: &str) -> bool {
    FORBIDDEN_NEP413_RECIPIENTS.iter().any(|f| f.eq_ignore_ascii_case(r))
}

impl Rules {
    pub fn from_policy(p: &Policy) -> Result<Self, Refusal> {
        let per_tx_limit = parse_yocto(&p.per_tx_limit_yocto)
            .map_err(|_| Refusal::InvalidPolicy("per_tx_limit_yocto must be a decimal u128".into()))?;
        let daily_limit = parse_yocto(&p.daily_limit_yocto)
            .map_err(|_| Refusal::InvalidPolicy("daily_limit_yocto must be a decimal u128".into()))?;
        if p.allowlist.len() > MAX_ALLOWLIST_LEN {
            return Err(Refusal::InvalidPolicy(format!(
                "allowlist has more than {MAX_ALLOWLIST_LEN} entries"
            )));
        }
        let mut allowlist = Vec::with_capacity(p.allowlist.len());
        for id in &p.allowlist {
            validate_account_id(id).map_err(|e| {
                Refusal::InvalidPolicy(format!("allowlist entry {:?} is not a NEAR account id ({e:?})", clip(id, MAX_LOGGED_INPUT)))
            })?;
            allowlist.push(id.clone());
        }
        allowlist.sort();
        allowlist.dedup();
        let requested = p.nep413_recipients.as_deref().unwrap_or_default();
        if requested.len() > MAX_NEP413_RECIPIENTS {
            return Err(Refusal::InvalidPolicy(format!(
                "nep413_recipients has more than {MAX_NEP413_RECIPIENTS} entries"
            )));
        }
        let mut nep413 = Vec::with_capacity(requested.len());
        for r in requested {
            if !valid_recipient(r) {
                return Err(Refusal::InvalidPolicy(format!(
                    "nep413_recipients entry {:?} must be 1 to {MAX_RECIPIENT_BYTES} printable ASCII characters without spaces",
                    clip(r, MAX_LOGGED_INPUT)
                )));
            }
            // Refused here so the owner learns it at once, and again at signing
            // time, so the rule does not depend on how the list was built.
            if is_forbidden_recipient(r) {
                return Err(Refusal::InvalidPolicy(format!(
                    "{r} can never be a NEP-413 recipient: a signature there authorizes moving funds, outside this policy"
                )));
            }
            nep413.push(r.clone());
        }
        nep413.sort();
        nep413.dedup();
        Ok(Rules { per_tx_limit, daily_limit, allowlist, nep413_recipients: Some(nep413) })
    }

    pub fn to_policy(&self) -> Policy {
        Policy {
            per_tx_limit_yocto: self.per_tx_limit.to_string(),
            daily_limit_yocto: self.daily_limit.to_string(),
            allowlist: self.allowlist.clone(),
            nep413_recipients: Some(self.nep413().to_vec()),
        }
    }

    pub fn nep413(&self) -> &[String] {
        self.nep413_recipients.as_deref().unwrap_or_default()
    }

    fn allows_recipient(&self, recipient: &str) -> bool {
        self.nep413()
            .binary_search_by(|r| r.as_str().cmp(recipient))
            .is_ok()
    }

    fn allows(&self, receiver_id: &str) -> bool {
        self.allowlist
            .binary_search_by(|id| id.as_str().cmp(receiver_id))
            .is_ok()
    }
}

/// Amount signed (or reserved for a signature in flight) on one UTC day.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct DailySpend {
    pub day: u64,
    pub spent: u128,
}

impl DailySpend {
    pub fn spent_on(&self, day: u64) -> u128 {
        if self.day == day {
            self.spent
        } else {
            0
        }
    }

    fn reserve(&mut self, day: u64, amount: u128, limit: u128) -> Result<(), Refusal> {
        let spent = self.spent_on(day);
        let total = spent.checked_add(amount).ok_or(Refusal::DailyOverflow)?;
        if total > limit {
            return Err(Refusal::OverDailyLimit { spent, amount, limit });
        }
        self.day = day;
        self.spent = total;
        Ok(())
    }

    /// Gives a reservation back. A reservation from an earlier day is gone
    /// already (the counter reset), so it must not reduce today's total.
    fn release(&mut self, day: u64, amount: u128) {
        if self.day == day {
            self.spent = self.spent.saturating_sub(amount);
        }
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Checked and reserved, signature not back yet. Stays visible if the
    /// signing step never completes.
    Pending,
    Signed { tx_hash: String },
    /// A NEP-413 message was signed; base58 of the signed SHA-256 hash.
    MessageSigned { payload_hash: String },
    Rejected { reason: String },
}

/// What the log keeps of a NEP-413 request. The message itself is not stored,
/// only its length and hash (it can be long, and it is the agent's input).
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MessageInfo {
    pub message_bytes: u64,
    /// Hex SHA-256 of the message text (not of the NEP-413 payload).
    pub message_sha256: String,
    /// Hex, as requested (clipped), even when not 32 bytes.
    pub nonce_hex: String,
    /// As requested (clipped).
    pub callback_url: Option<String>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    /// Counts every request ever logged; gaps at the start show eviction.
    pub seq: u64,
    pub time_ns: u64,
    pub caller: Principal,
    /// Transfer receiver or NEP-413 recipient, as requested (clipped), even
    /// when invalid.
    pub receiver_id: String,
    /// As requested (clipped), even when invalid. Empty for NEP-413 requests.
    pub yocto: String,
    pub outcome: Outcome,
    /// Set for NEP-413 requests, `null` for transfers.
    pub message: Option<MessageInfo>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub owner: Principal,
    pub agent: Option<Principal>,
    pub policy: Policy,
    pub utc_day: u64,
    pub spent_today_yocto: String,
    /// Sign requests from callers that are neither owner nor agent. Counted,
    /// not logged.
    pub rejected_unauthorized: u64,
}

/// Proof that a request passed every rule and holds a reservation. Not
/// `Clone`: each ticket is finished exactly once.
#[derive(Debug)]
pub struct Ticket {
    seq: u64,
    day: u64,
    amount: u128,
    time_ns: u64,
    caller: Principal,
    receiver_id: String,
}

impl Ticket {
    pub fn amount(&self) -> u128 {
        self.amount
    }
}

/// Proof that a NEP-413 request passed every check. Carries the nonce as the
/// 32-byte array the encoder needs, so the canister cannot sign an unchecked one.
#[derive(Debug)]
pub struct MessageTicket {
    seq: u64,
    time_ns: u64,
    caller: Principal,
    recipient: String,
    info: MessageInfo,
    nonce: [u8; NEP413_NONCE_BYTES],
}

impl MessageTicket {
    pub fn nonce(&self) -> &[u8; NEP413_NONCE_BYTES] {
        &self.nonce
    }
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).chain(std::iter::once('…')).collect()
    }
}

/// The whole policy state. Survives upgrades as one value (see `lib.rs`).
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Guard {
    owner: Principal,
    agent: Option<Principal>,
    rules: Rules,
    spend: DailySpend,
    log: Vec<AuditEntry>,
    next_seq: u64,
    rejected_unauthorized: u64,
}

impl Guard {
    /// Safe default: no agent, limits 0, empty allowlist — nothing gets signed.
    pub fn new(owner: Principal) -> Result<Self, Refusal> {
        if owner == Principal::anonymous() {
            return Err(Refusal::AnonymousOwner);
        }
        Ok(Guard {
            owner,
            agent: None,
            rules: Rules::default(),
            spend: DailySpend::default(),
            log: Vec::new(),
            next_seq: 0,
            rejected_unauthorized: 0,
        })
    }

    fn reject_anonymous(caller: Principal) -> Result<(), Refusal> {
        if caller == Principal::anonymous() {
            return Err(Refusal::AnonymousCaller);
        }
        Ok(())
    }

    fn require_owner(&self, caller: Principal) -> Result<(), Refusal> {
        Self::reject_anonymous(caller)?;
        if caller != self.owner {
            return Err(Refusal::NotOwner);
        }
        Ok(())
    }

    fn is_owner_or_agent(&self, caller: Principal) -> bool {
        caller == self.owner || Some(caller) == self.agent
    }

    fn require_reader(&self, caller: Principal) -> Result<(), Refusal> {
        Self::reject_anonymous(caller)?;
        if caller == self.owner || Some(caller) == self.agent {
            Ok(())
        } else {
            Err(Refusal::NotOwnerOrAgent)
        }
    }

    /// `None` removes the agent: from then on nothing gets signed.
    pub fn set_agent(&mut self, caller: Principal, agent: Option<Principal>) -> Result<(), Refusal> {
        self.require_owner(caller)?;
        if let Some(a) = agent {
            if a == self.owner {
                return Err(Refusal::AgentIsOwner);
            }
            if a == Principal::anonymous() {
                return Err(Refusal::AgentIsAnonymous);
            }
        }
        self.agent = agent;
        Ok(())
    }

    /// Replaces all three rules and the NEP-413 list at once. Today's spent
    /// total is kept.
    pub fn set_policy(&mut self, caller: Principal, policy: &Policy) -> Result<(), Refusal> {
        self.require_owner(caller)?;
        self.rules = Rules::from_policy(policy)?;
        Ok(())
    }

    pub fn config(&self, caller: Principal, now_ns: u64) -> Result<Config, Refusal> {
        self.require_reader(caller)?;
        let day = utc_day(now_ns);
        Ok(Config {
            owner: self.owner,
            agent: self.agent,
            policy: self.rules.to_policy(),
            utc_day: day,
            spent_today_yocto: self.spend.spent_on(day).to_string(),
            rejected_unauthorized: self.rejected_unauthorized,
        })
    }

    pub fn audit_log(&self, caller: Principal) -> Result<Vec<AuditEntry>, Refusal> {
        self.require_reader(caller)?;
        Ok(self.log.clone())
    }

    fn authorize_sign(&self, caller: Principal) -> Result<(), Refusal> {
        Self::reject_anonymous(caller)?;
        if caller == self.owner {
            return Err(Refusal::OwnerCannotSign);
        }
        let agent = self.agent.ok_or(Refusal::NoAgent)?;
        if caller != agent {
            return Err(Refusal::NotAgent);
        }
        Ok(())
    }

    /// All checks, then the reservation. Mutates only on success.
    fn admit(&mut self, caller: Principal, receiver_id: &str, yocto: &str, now_ns: u64) -> Result<u128, Refusal> {
        self.authorize_sign(caller)?;
        validate_account_id(receiver_id).map_err(|_| Refusal::InvalidReceiver)?;
        let amount = parse_yocto(yocto)?;
        if amount == 0 {
            return Err(Refusal::ZeroAmount);
        }
        // Rule 1: per-transaction limit.
        if amount > self.rules.per_tx_limit {
            return Err(Refusal::OverPerTxLimit { amount, limit: self.rules.per_tx_limit });
        }
        // Rule 3: receiver allowlist.
        if !self.rules.allows(receiver_id) {
            return Err(Refusal::ReceiverNotAllowed(receiver_id.to_string()));
        }
        // Rule 2: daily limit — check and reserve in the same step.
        self.spend.reserve(utc_day(now_ns), amount, self.rules.daily_limit)?;
        Ok(amount)
    }

    fn push_log(&mut self, entry_without_seq: impl FnOnce(u64) -> AuditEntry) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        if self.log.len() >= AUDIT_LOG_CAPACITY {
            self.log.remove(0);
        }
        self.log.push(entry_without_seq(seq));
        seq
    }

    /// Step 1 of a signature, synchronous, before the canister awaits. Calls
    /// from owner or agent are logged (refused ones as `Rejected`, admitted
    /// ones as `Pending`); calls from anyone else are only counted.
    pub fn begin_sign(&mut self, caller: Principal, receiver_id: &str, yocto: &str, now_ns: u64) -> Result<Ticket, Refusal> {
        if !self.is_owner_or_agent(caller) {
            self.rejected_unauthorized = self.rejected_unauthorized.saturating_add(1);
            // Never `Ok` for such a caller; `NotAgent` only as a fallback.
            return Err(self.authorize_sign(caller).err().unwrap_or(Refusal::NotAgent));
        }
        let admitted = self.admit(caller, receiver_id, yocto, now_ns);
        let logged_receiver = clip(receiver_id, MAX_LOGGED_INPUT);
        let logged_yocto = clip(yocto, MAX_LOGGED_INPUT);
        let outcome = match &admitted {
            Ok(_) => Outcome::Pending,
            Err(r) => Outcome::Rejected { reason: r.to_string() },
        };
        let seq = self.push_log(|seq| AuditEntry {
            seq,
            time_ns: now_ns,
            caller,
            receiver_id: logged_receiver.clone(),
            yocto: logged_yocto,
            outcome,
            message: None,
        });
        admitted.map(|amount| Ticket {
            seq,
            day: utc_day(now_ns),
            amount,
            time_ns: now_ns,
            caller,
            receiver_id: logged_receiver,
        })
    }

    /// Step 2, after the signature call returned. `Ok(tx_hash)` keeps the
    /// reservation (the budget counts signatures, not NEAR arrivals);
    /// `Err` releases it.
    pub fn finish_sign(&mut self, ticket: Ticket, result: Result<String, String>) {
        let outcome = match result {
            Ok(tx_hash) => Outcome::Signed { tx_hash },
            Err(e) => {
                self.spend.release(ticket.day, ticket.amount);
                Outcome::Rejected { reason: clip(&format!("signing failed: {e}"), MAX_LOGGED_REASON) }
            }
        };
        if let Some(entry) = self.log.iter_mut().rev().find(|e| e.seq == ticket.seq) {
            entry.outcome = outcome;
        } else {
            // The pending entry was evicted while the signature was in flight.
            let yocto = ticket.amount.to_string();
            self.push_log(|seq| AuditEntry {
                seq,
                time_ns: ticket.time_ns,
                caller: ticket.caller,
                receiver_id: ticket.receiver_id,
                yocto,
                outcome,
                message: None,
            });
        }
    }

    /// Every NEP-413 check. The nonce comes back as an array on success.
    fn admit_message(
        &self,
        caller: Principal,
        message: &str,
        nonce: &[u8],
        recipient: &str,
        callback_url: Option<&str>,
    ) -> Result<[u8; NEP413_NONCE_BYTES], Refusal> {
        self.authorize_sign(caller)?;
        let nonce: [u8; NEP413_NONCE_BYTES] = nonce.try_into().map_err(|_| Refusal::InvalidNonce(nonce.len()))?;
        if message.is_empty() {
            return Err(Refusal::InvalidMessage("must not be empty"));
        }
        if message.len() > MAX_MESSAGE_BYTES {
            return Err(Refusal::InvalidMessage("exceeds 4096 bytes"));
        }
        if !valid_recipient(recipient) {
            return Err(Refusal::InvalidRecipient);
        }
        // Before the allowlist: refused even if the owner listed it.
        if is_forbidden_recipient(recipient) {
            return Err(Refusal::RecipientForbidden(recipient.to_string()));
        }
        if let Some(url) = callback_url {
            if url.len() > MAX_CALLBACK_URL_BYTES || !printable_ascii(url) {
                return Err(Refusal::InvalidCallbackUrl);
            }
        }
        if !self.rules.allows_recipient(recipient) {
            return Err(Refusal::RecipientNotAllowed(recipient.to_string()));
        }
        Ok(nonce)
    }

    /// Step 1 of a NEP-413 signature, synchronous. Same logging as
    /// [`Guard::begin_sign`]: owner and agent are logged, anyone else counted.
    /// A nonce may be signed more than once: replay protection is the
    /// recipient's job under NEP-413 (only it knows which nonces it accepted),
    /// and the guard's protection is the recipient allowlist.
    pub fn begin_message(
        &mut self,
        caller: Principal,
        message: &str,
        nonce: &[u8],
        recipient: &str,
        callback_url: Option<&str>,
        now_ns: u64,
    ) -> Result<MessageTicket, Refusal> {
        if !self.is_owner_or_agent(caller) {
            self.rejected_unauthorized = self.rejected_unauthorized.saturating_add(1);
            return Err(self.authorize_sign(caller).err().unwrap_or(Refusal::NotAgent));
        }
        let admitted = self.admit_message(caller, message, nonce, recipient, callback_url);
        let logged_recipient = clip(recipient, MAX_LOGGED_INPUT);
        let info = MessageInfo {
            message_bytes: message.len() as u64,
            message_sha256: hex::encode(Sha256::digest(message.as_bytes())),
            nonce_hex: hex::encode(&nonce[..nonce.len().min(NEP413_NONCE_BYTES)])
                + if nonce.len() > NEP413_NONCE_BYTES { "…" } else { "" },
            callback_url: callback_url.map(|u| clip(u, MAX_LOGGED_INPUT)),
        };
        let outcome = match &admitted {
            Ok(_) => Outcome::Pending,
            Err(r) => Outcome::Rejected { reason: clip(&r.to_string(), MAX_LOGGED_REASON) },
        };
        let seq = self.push_log(|seq| AuditEntry {
            seq,
            time_ns: now_ns,
            caller,
            receiver_id: logged_recipient.clone(),
            yocto: String::new(),
            outcome,
            message: Some(info.clone()),
        });
        admitted.map(|nonce| MessageTicket {
            seq,
            time_ns: now_ns,
            caller,
            recipient: logged_recipient,
            info,
            nonce,
        })
    }

    /// Step 2: `Ok(payload_hash)` or the signing error.
    pub fn finish_message(&mut self, ticket: MessageTicket, result: Result<String, String>) {
        let outcome = match result {
            Ok(payload_hash) => Outcome::MessageSigned { payload_hash },
            Err(e) => Outcome::Rejected { reason: clip(&format!("signing failed: {e}"), MAX_LOGGED_REASON) },
        };
        if let Some(entry) = self.log.iter_mut().rev().find(|e| e.seq == ticket.seq) {
            entry.outcome = outcome;
        } else {
            self.push_log(|seq| AuditEntry {
                seq,
                time_ns: ticket.time_ns,
                caller: ticket.caller,
                receiver_id: ticket.recipient,
                yocto: String::new(),
                outcome,
                message: Some(ticket.info),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
    const DAY: u64 = NANOS_PER_DAY;
    /// 2026-11-02 12:00 UTC.
    const NOW: u64 = 20_759 * DAY + DAY / 2;

    fn p(n: u8) -> Principal {
        Principal::from_slice(&[n; 29])
    }
    fn owner() -> Principal {
        p(1)
    }
    fn agent() -> Principal {
        p(2)
    }
    fn stranger() -> Principal {
        p(3)
    }

    fn policy(per_tx: u128, daily: u128, allow: &[&str]) -> Policy {
        Policy {
            per_tx_limit_yocto: per_tx.to_string(),
            daily_limit_yocto: daily.to_string(),
            allowlist: allow.iter().map(|s| s.to_string()).collect(),
            nep413_recipients: None,
        }
    }

    /// Owner + agent + per-tx 0.5 NEAR, daily 0.8 NEAR, one allowed receiver.
    fn configured() -> Guard {
        let mut g = Guard::new(owner()).unwrap();
        g.set_agent(owner(), Some(agent())).unwrap();
        g.set_policy(owner(), &policy(NEAR / 2, NEAR * 8 / 10, &["alice.testnet"])).unwrap();
        g
    }

    fn ask(g: &mut Guard, caller: Principal, to: &str, yocto: u128, now: u64) -> Result<Ticket, Refusal> {
        g.begin_sign(caller, to, &yocto.to_string(), now)
    }

    /// A full request whose signature succeeds.
    fn sign(g: &mut Guard, to: &str, yocto: u128, now: u64) -> Result<(), Refusal> {
        let t = ask(g, agent(), to, yocto, now)?;
        g.finish_sign(t, Ok("hash".into()));
        Ok(())
    }

    fn spent(g: &Guard, now: u64) -> u128 {
        g.config(owner(), now).unwrap().spent_today_yocto.parse().unwrap()
    }

    // ---- roles ---------------------------------------------------------------

    #[test]
    fn anonymous_owner_is_rejected() {
        assert_eq!(Guard::new(Principal::anonymous()), Err(Refusal::AnonymousOwner));
        assert!(Guard::new(owner()).is_ok());
    }

    #[test]
    fn only_the_owner_changes_policy_and_agent() {
        let mut g = configured();
        let before = g.clone();
        for caller in [agent(), stranger(), Principal::anonymous()] {
            assert!(g.set_policy(caller, &policy(u128::MAX, u128::MAX, &["attacker.testnet"])).is_err());
            assert!(g.set_agent(caller, Some(stranger())).is_err());
            assert!(g.set_agent(caller, None).is_err());
        }
        assert_eq!(g.set_policy(agent(), &policy(1, 1, &[])), Err(Refusal::NotOwner));
        assert_eq!(g.set_agent(agent(), None), Err(Refusal::NotOwner));
        assert_eq!(g, before, "a refused call changed state");
    }

    #[test]
    fn agent_is_neither_owner_nor_anonymous() {
        let mut g = Guard::new(owner()).unwrap();
        assert_eq!(g.set_agent(owner(), Some(owner())), Err(Refusal::AgentIsOwner));
        assert_eq!(g.set_agent(owner(), Some(Principal::anonymous())), Err(Refusal::AgentIsAnonymous));
        assert_eq!(g.agent, None);
        g.set_agent(owner(), Some(agent())).unwrap();
        g.set_agent(owner(), None).unwrap();
        assert_eq!(g.agent, None);
    }

    #[test]
    fn owner_cannot_sign() {
        let mut g = configured();
        assert_eq!(ask(&mut g, owner(), "alice.testnet", 1, NOW).unwrap_err(), Refusal::OwnerCannotSign);
        assert_eq!(spent(&g, NOW), 0);
    }

    #[test]
    fn only_the_agent_can_sign() {
        let mut g = configured();
        assert_eq!(ask(&mut g, stranger(), "alice.testnet", 1, NOW).unwrap_err(), Refusal::NotAgent);
        assert_eq!(ask(&mut g, Principal::anonymous(), "alice.testnet", 1, NOW).unwrap_err(), Refusal::AnonymousCaller);
        assert_eq!(spent(&g, NOW), 0);
        assert!(ask(&mut g, agent(), "alice.testnet", 1, NOW).is_ok());
    }

    /// Every protected method refuses anonymous explicitly — also where the
    /// role check alone would refuse it.
    #[test]
    fn anonymous_is_refused_everywhere() {
        let mut g = configured();
        let anon = Principal::anonymous();
        assert_eq!(ask(&mut g, anon, "alice.testnet", 1, NOW).unwrap_err(), Refusal::AnonymousCaller);
        assert_eq!(g.set_policy(anon, &policy(1, 1, &[])), Err(Refusal::AnonymousCaller));
        assert_eq!(g.set_agent(anon, None), Err(Refusal::AnonymousCaller));
        assert_eq!(g.config(anon, NOW).unwrap_err(), Refusal::AnonymousCaller);
        assert_eq!(g.audit_log(anon).unwrap_err(), Refusal::AnonymousCaller);
    }

    #[test]
    fn replaced_agent_cannot_sign() {
        let mut g = configured();
        let new_agent = p(4);
        g.set_agent(owner(), Some(new_agent)).unwrap();
        assert_eq!(ask(&mut g, agent(), "alice.testnet", 1, NOW).unwrap_err(), Refusal::NotAgent);
        assert!(ask(&mut g, new_agent, "alice.testnet", 1, NOW).is_ok());
    }

    #[test]
    fn removed_agent_cannot_sign() {
        let mut g = configured();
        g.set_agent(owner(), None).unwrap();
        assert_eq!(ask(&mut g, agent(), "alice.testnet", 1, NOW).unwrap_err(), Refusal::NoAgent);
    }

    #[test]
    fn reads_are_for_owner_and_agent_only() {
        let g = configured();
        assert!(g.config(owner(), NOW).is_ok());
        assert!(g.config(agent(), NOW).is_ok());
        assert!(g.audit_log(owner()).is_ok());
        assert!(g.audit_log(agent()).is_ok());
        assert_eq!(g.config(stranger(), NOW).unwrap_err(), Refusal::NotOwnerOrAgent);
        assert_eq!(g.audit_log(stranger()).unwrap_err(), Refusal::NotOwnerOrAgent);
        assert!(g.config(Principal::anonymous(), NOW).is_err());
        assert!(g.audit_log(Principal::anonymous()).is_err());
    }

    // ---- safe default --------------------------------------------------------

    #[test]
    fn fresh_guard_signs_nothing() {
        let mut g = Guard::new(owner()).unwrap();
        assert_eq!(ask(&mut g, agent(), "alice.testnet", 1, NOW).unwrap_err(), Refusal::NoAgent);
        g.set_agent(owner(), Some(agent())).unwrap();
        // Limits 0 and an empty allowlist: still nothing, not even 1 yocto.
        assert_eq!(
            ask(&mut g, agent(), "alice.testnet", 1, NOW).unwrap_err(),
            Refusal::OverPerTxLimit { amount: 1, limit: 0 }
        );
        assert_eq!(ask(&mut g, agent(), "alice.testnet", 0, NOW).unwrap_err(), Refusal::ZeroAmount);
    }

    // ---- rule 1: per-transaction limit ---------------------------------------

    #[test]
    fn per_tx_limit() {
        let mut g = configured();
        let limit = NEAR / 2;
        assert_eq!(
            ask(&mut g, agent(), "alice.testnet", limit + 1, NOW).unwrap_err(),
            Refusal::OverPerTxLimit { amount: limit + 1, limit }
        );
        assert_eq!(spent(&g, NOW), 0, "a refused request reserved budget");
        assert!(sign(&mut g, "alice.testnet", limit, NOW).is_ok(), "exactly the limit is allowed");
    }

    // ---- rule 2: daily limit -------------------------------------------------

    #[test]
    fn daily_limit_counts_signed_amounts() {
        let mut g = configured(); // daily 0.8
        sign(&mut g, "alice.testnet", NEAR / 2, NOW).unwrap();
        assert_eq!(
            ask(&mut g, agent(), "alice.testnet", NEAR * 4 / 10, NOW).unwrap_err(),
            Refusal::OverDailyLimit { spent: NEAR / 2, amount: NEAR * 4 / 10, limit: NEAR * 8 / 10 }
        );
        sign(&mut g, "alice.testnet", NEAR * 3 / 10, NOW).unwrap(); // exactly 0.8
        assert_eq!(spent(&g, NOW), NEAR * 8 / 10);
        assert!(ask(&mut g, agent(), "alice.testnet", 1, NOW).is_err());
    }

    /// Two requests both pass the check before either signature is back —
    /// what happens when a second message runs during the first one's await.
    #[test]
    fn reservation_is_made_before_the_signature_await() {
        let mut g = configured(); // per-tx 0.5, daily 0.8
        let first = ask(&mut g, agent(), "alice.testnet", NEAR / 2, NOW).unwrap();
        // `first` is in flight; its signature has not come back.
        assert_eq!(
            ask(&mut g, agent(), "alice.testnet", NEAR / 2, NOW).unwrap_err(),
            Refusal::OverDailyLimit { spent: NEAR / 2, amount: NEAR / 2, limit: NEAR * 8 / 10 }
        );
        g.finish_sign(first, Ok("hash".into()));
        assert_eq!(spent(&g, NOW), NEAR / 2);
    }

    #[test]
    fn failed_signature_releases_the_reservation() {
        let mut g = configured();
        let t = ask(&mut g, agent(), "alice.testnet", NEAR / 2, NOW).unwrap();
        assert_eq!(spent(&g, NOW), NEAR / 2);
        g.finish_sign(t, Err("subnet unavailable".into()));
        assert_eq!(spent(&g, NOW), 0);
        sign(&mut g, "alice.testnet", NEAR / 2, NOW).unwrap();
    }

    #[test]
    fn budget_resets_on_the_next_utc_day() {
        let mut g = configured();
        let last_ns_of_day = (utc_day(NOW) + 1) * DAY - 1;
        sign(&mut g, "alice.testnet", NEAR / 2, last_ns_of_day).unwrap();
        assert!(ask(&mut g, agent(), "alice.testnet", NEAR / 2, last_ns_of_day).is_err());
        let next_day = last_ns_of_day + 1;
        assert_eq!(spent(&g, next_day), 0);
        sign(&mut g, "alice.testnet", NEAR / 2, next_day).unwrap();
    }

    #[test]
    fn release_from_yesterday_does_not_touch_today() {
        let mut g = configured();
        let yesterday = ask(&mut g, agent(), "alice.testnet", NEAR / 2, NOW).unwrap();
        sign(&mut g, "alice.testnet", NEAR / 2, NOW + DAY).unwrap();
        g.finish_sign(yesterday, Err("late failure".into()));
        assert_eq!(spent(&g, NOW + DAY), NEAR / 2);
    }

    #[test]
    fn sums_do_not_overflow() {
        let mut g = configured();
        g.set_policy(owner(), &policy(u128::MAX, u128::MAX, &["alice.testnet"])).unwrap();
        sign(&mut g, "alice.testnet", u128::MAX, NOW).unwrap();
        assert_eq!(ask(&mut g, agent(), "alice.testnet", 1, NOW).unwrap_err(), Refusal::DailyOverflow);
        assert_eq!(spent(&g, NOW), u128::MAX);
    }

    // ---- rule 3: allowlist ---------------------------------------------------

    #[test]
    fn receiver_must_be_on_the_allowlist() {
        let mut g = configured();
        assert_eq!(
            ask(&mut g, agent(), "attacker.testnet", 1, NOW).unwrap_err(),
            Refusal::ReceiverNotAllowed("attacker.testnet".into())
        );
        assert_eq!(spent(&g, NOW), 0);
        assert!(sign(&mut g, "alice.testnet", 1, NOW).is_ok());
    }

    #[test]
    fn allowlist_entries_are_validated() {
        let mut g = configured();
        for bad in ["Alice.testnet", "a", "x..near", ""] {
            assert!(
                matches!(g.set_policy(owner(), &policy(1, 1, &[bad])), Err(Refusal::InvalidPolicy(_))),
                "{bad:?} accepted"
            );
        }
        let too_many: Vec<String> = (0..=MAX_ALLOWLIST_LEN).map(|i| format!("a{i}.testnet")).collect();
        let refs: Vec<&str> = too_many.iter().map(String::as_str).collect();
        assert!(g.set_policy(owner(), &policy(1, 1, &refs)).is_err());
        assert_eq!(g, configured(), "a refused policy changed state");
    }

    #[test]
    fn invalid_requests_are_refused() {
        let mut g = configured();
        assert_eq!(ask(&mut g, agent(), "Alice.testnet", 1, NOW).unwrap_err(), Refusal::InvalidReceiver);
        for bad in ["", "+5", " 5", "1e3", "-1", "340282366920938463463374607431768211456"] {
            assert_eq!(g.begin_sign(agent(), "alice.testnet", bad, NOW).unwrap_err(), Refusal::InvalidAmount, "{bad:?}");
        }
    }

    // ---- audit log -----------------------------------------------------------

    #[test]
    fn every_request_is_logged_with_its_outcome() {
        let mut g = configured();
        let _ = ask(&mut g, owner(), "alice.testnet", 1, NOW);
        let _ = ask(&mut g, agent(), "attacker.testnet", 7, NOW + 1);
        let t = ask(&mut g, agent(), "alice.testnet", 5, NOW + 2).unwrap();
        assert_eq!(g.log[2].outcome, Outcome::Pending);
        g.finish_sign(t, Ok("HASH".into()));
        let t = ask(&mut g, agent(), "alice.testnet", 6, NOW + 3).unwrap();
        g.finish_sign(t, Err("boom".into()));

        let log = g.audit_log(owner()).unwrap();
        assert_eq!(log.len(), 4);
        assert_eq!(log.iter().map(|e| e.seq).collect::<Vec<_>>(), [0, 1, 2, 3]);
        assert_eq!((log[0].caller, log[0].outcome.clone()), (owner(), Outcome::Rejected { reason: Refusal::OwnerCannotSign.to_string() }));
        assert_eq!((log[1].receiver_id.as_str(), log[1].yocto.as_str(), log[1].time_ns), ("attacker.testnet", "7", NOW + 1));
        assert!(matches!(&log[1].outcome, Outcome::Rejected { reason } if reason.contains("allowlist")));
        assert_eq!(log[2].outcome, Outcome::Signed { tx_hash: "HASH".into() });
        assert_eq!(log[3].outcome, Outcome::Rejected { reason: "signing failed: boom".into() });
    }

    #[test]
    fn log_is_bounded_and_clips_input() {
        let mut g = configured();
        let long = "x".repeat(10_000);
        for i in 0..AUDIT_LOG_CAPACITY + 5 {
            let _ = g.begin_sign(agent(), &long, &long, NOW + i as u64);
        }
        let log = g.audit_log(owner()).unwrap();
        assert_eq!(log.len(), AUDIT_LOG_CAPACITY);
        assert_eq!(log[0].seq, 5);
        assert_eq!(log.last().unwrap().seq, (AUDIT_LOG_CAPACITY + 4) as u64);
        assert_eq!(log[0].receiver_id.chars().count(), MAX_LOGGED_INPUT + 1);
        assert_eq!(log[0].yocto.chars().count(), MAX_LOGGED_INPUT + 1);
    }

    #[test]
    fn signature_finishing_after_eviction_is_still_logged() {
        let mut g = configured();
        let t = ask(&mut g, agent(), "alice.testnet", 9, NOW).unwrap();
        for _ in 0..AUDIT_LOG_CAPACITY {
            let _ = ask(&mut g, agent(), "attacker.testnet", 1, NOW);
        }
        g.finish_sign(t, Ok("LATE".into()));
        let last = g.log.last().unwrap();
        assert_eq!((last.yocto.as_str(), last.outcome.clone()), ("9", Outcome::Signed { tx_hash: "LATE".into() }));
    }

    /// Strangers must not be able to push the real entries out of the log.
    #[test]
    fn strangers_are_counted_not_logged() {
        let mut g = configured();
        sign(&mut g, "alice.testnet", 1, NOW).unwrap();
        let _ = ask(&mut g, agent(), "attacker.testnet", 1, NOW);
        let before = g.audit_log(owner()).unwrap();
        for i in 0..5 * AUDIT_LOG_CAPACITY {
            let caller = if i % 2 == 0 { stranger() } else { Principal::anonymous() };
            assert!(ask(&mut g, caller, "alice.testnet", 1, NOW).is_err());
        }
        assert_eq!(g.audit_log(owner()).unwrap(), before, "strangers changed the log");
        assert_eq!(g.config(owner(), NOW).unwrap().rejected_unauthorized, 5 * AUDIT_LOG_CAPACITY as u64);
        assert_eq!(spent(&g, NOW), 1);
    }

    // ---- upgrade -------------------------------------------------------------

    /// Worst case for `pre_upgrade`: a full log of entries with every
    /// caller-supplied field at its clipped maximum (2-byte characters),
    /// plus a full allowlist. Prints the encoded size; must stay well below
    /// what an upgrade can serialize.
    #[test]
    fn worst_case_state_size() {
        let mut g = configured();
        let ids: Vec<String> = (0..MAX_ALLOWLIST_LEN).map(|i| format!("{i:0>2}{}", "a".repeat(62))).collect();
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        g.set_policy(owner(), &policy(u128::MAX, u128::MAX, &refs)).unwrap();
        let wide = "é".repeat(10_000);
        for _ in 0..AUDIT_LOG_CAPACITY {
            let t = ask(&mut g, agent(), &ids[0], 1, NOW).unwrap();
            g.finish_sign(t, Err(wide.clone()));
        }
        for _ in 0..AUDIT_LOG_CAPACITY / 2 {
            let _ = g.begin_sign(agent(), &wide, &wide, NOW);
        }
        // NEP-413 entries carry more: a full list, then a full log of admitted
        // messages with every logged field at its maximum, failing with a long
        // (2-byte) error.
        let recipients: Vec<String> = (0..MAX_NEP413_RECIPIENTS)
            .map(|i| format!("{i:0>2}{}", "r".repeat(MAX_RECIPIENT_BYTES - 2)))
            .collect();
        let mut p = g.rules.to_policy();
        p.nep413_recipients = Some(recipients.clone());
        g.set_policy(owner(), &p).unwrap();
        let url = "u".repeat(MAX_CALLBACK_URL_BYTES);
        let message = "m".repeat(MAX_MESSAGE_BYTES);
        for _ in 0..AUDIT_LOG_CAPACITY {
            let t = g.begin_message(agent(), &message, &[0; 32], &recipients[0], Some(&url), NOW).unwrap();
            g.finish_message(t, Err(wide.clone()));
        }
        assert!(g.log.iter().all(|e| e.message.is_some()));
        assert_eq!(g.log.len(), AUDIT_LOG_CAPACITY);
        let bytes = candid::encode_one(&g).unwrap().len();
        println!("worst-case stable state: {bytes} bytes for {AUDIT_LOG_CAPACITY} log entries");
        assert!(bytes < 1 << 20, "state grew to {bytes} bytes");
    }

    /// What `pre_upgrade` writes, `post_upgrade` must read back unchanged.
    #[test]
    fn state_round_trips_through_candid() {
        let mut g = configured();
        sign(&mut g, "alice.testnet", NEAR / 4, NOW).unwrap();
        let _ = ask(&mut g, agent(), "attacker.testnet", 1, NOW);
        let _ = ask(&mut g, stranger(), "alice.testnet", 1, NOW);
        let bytes = candid::encode_one(&g).unwrap();
        let back: Guard = candid::decode_one(&bytes).unwrap();
        assert_eq!(back, g);
        assert_eq!(spent(&back, NOW), NEAR / 4);
        assert_eq!(back.log.len(), 2);
        assert_eq!(back.rejected_unauthorized, 1);
    }

    // ---- NEP-413 -------------------------------------------------------------

    const NONCE: [u8; 32] = [9; 32];

    /// `configured()` plus one NEP-413 recipient.
    fn with_nep413(recipients: &[&str]) -> Guard {
        let mut g = configured();
        let mut p = g.rules.to_policy();
        p.nep413_recipients = Some(recipients.iter().map(|s| s.to_string()).collect());
        g.set_policy(owner(), &p).unwrap();
        g
    }

    fn ask_msg(g: &mut Guard, caller: Principal, recipient: &str, nonce: &[u8]) -> Result<MessageTicket, Refusal> {
        g.begin_message(caller, "hello", nonce, recipient, None, NOW)
    }

    #[test]
    fn nep413_recipient_must_be_on_its_own_list() {
        let mut g = with_nep413(&["login.example"]);
        assert_eq!(
            ask_msg(&mut g, agent(), "other.example", &NONCE).unwrap_err(),
            Refusal::RecipientNotAllowed("other.example".into())
        );
        // The transfer allowlist does not count for messages ...
        assert_eq!(
            ask_msg(&mut g, agent(), "alice.testnet", &NONCE).unwrap_err(),
            Refusal::RecipientNotAllowed("alice.testnet".into())
        );
        // ... and the NEP-413 list does not count for transfers.
        assert_eq!(
            ask(&mut g, agent(), "login.example", 1, NOW).unwrap_err(),
            Refusal::ReceiverNotAllowed("login.example".into())
        );
        let t = ask_msg(&mut g, agent(), "login.example", &NONCE).unwrap();
        assert_eq!(t.nonce(), &NONCE);
    }

    #[test]
    fn nep413_default_signs_nothing() {
        let mut g = configured(); // policy without nep413_recipients
        assert_eq!(g.config(owner(), NOW).unwrap().policy.nep413_recipients, Some(vec![]));
        assert_eq!(
            ask_msg(&mut g, agent(), "login.example", &NONCE).unwrap_err(),
            Refusal::RecipientNotAllowed("login.example".into())
        );
    }

    #[test]
    fn intents_near_cannot_be_listed() {
        let mut g = configured();
        let before = g.clone();
        for r in ["intents.near", "INTENTS.near", "Intents.Near"] {
            let mut p = g.rules.to_policy();
            p.nep413_recipients = Some(vec!["login.example".into(), r.into()]);
            assert!(
                matches!(g.set_policy(owner(), &p), Err(Refusal::InvalidPolicy(why)) if why.contains("never be a NEP-413 recipient")),
                "{r} accepted"
            );
        }
        assert_eq!(g, before, "a refused policy changed state");
    }

    /// Even if `intents.near` got onto the list some other way (e.g. a future
    /// code path or restored state), signing for it is refused.
    #[test]
    fn intents_near_is_refused_even_when_listed() {
        let mut g = with_nep413(&["login.example"]);
        g.rules.nep413_recipients = Some(vec!["INTENTS.NEAR".into(), "intents.near".into(), "login.example".into()]);
        g.rules.nep413_recipients.as_mut().unwrap().sort();
        for r in ["intents.near", "INTENTS.NEAR"] {
            assert_eq!(
                ask_msg(&mut g, agent(), r, &NONCE).unwrap_err(),
                Refusal::RecipientForbidden(r.into())
            );
        }
        let log = g.audit_log(owner()).unwrap();
        assert!(matches!(&log.last().unwrap().outcome, Outcome::Rejected { reason } if reason.contains("never signed")));
    }

    #[test]
    fn nep413_only_the_agent_signs() {
        let mut g = with_nep413(&["login.example"]);
        assert_eq!(ask_msg(&mut g, owner(), "login.example", &NONCE).unwrap_err(), Refusal::OwnerCannotSign);
        assert_eq!(ask_msg(&mut g, stranger(), "login.example", &NONCE).unwrap_err(), Refusal::NotAgent);
        assert_eq!(
            ask_msg(&mut g, Principal::anonymous(), "login.example", &NONCE).unwrap_err(),
            Refusal::AnonymousCaller
        );
        g.set_agent(owner(), None).unwrap();
        assert_eq!(ask_msg(&mut g, agent(), "login.example", &NONCE).unwrap_err(), Refusal::NoAgent);
        g.set_agent(owner(), Some(agent())).unwrap();
        assert!(ask_msg(&mut g, agent(), "login.example", &NONCE).is_ok());
    }

    #[test]
    fn nep413_strangers_are_counted_not_logged() {
        let mut g = with_nep413(&["login.example"]);
        let before = g.audit_log(owner()).unwrap();
        for i in 0..2 * AUDIT_LOG_CAPACITY {
            let caller = if i % 2 == 0 { stranger() } else { Principal::anonymous() };
            assert!(ask_msg(&mut g, caller, "login.example", &NONCE).is_err());
        }
        assert_eq!(g.audit_log(owner()).unwrap(), before);
        assert_eq!(g.config(owner(), NOW).unwrap().rejected_unauthorized, 2 * AUDIT_LOG_CAPACITY as u64);
    }

    #[test]
    fn nep413_nonce_must_be_32_bytes() {
        let mut g = with_nep413(&["login.example"]);
        for n in [0usize, 1, 31, 33, 64] {
            assert_eq!(
                ask_msg(&mut g, agent(), "login.example", &vec![1u8; n]).unwrap_err(),
                Refusal::InvalidNonce(n),
                "{n} bytes"
            );
        }
        assert!(ask_msg(&mut g, agent(), "login.example", &[1u8; 32]).is_ok());
    }

    /// Decision: a nonce may be signed again (see `begin_message`).
    #[test]
    fn nep413_same_nonce_may_be_signed_twice() {
        let mut g = with_nep413(&["login.example"]);
        for _ in 0..2 {
            let t = ask_msg(&mut g, agent(), "login.example", &NONCE).unwrap();
            g.finish_message(t, Ok("H".into()));
        }
    }

    #[test]
    fn nep413_bounds() {
        let mut g = with_nep413(&["login.example"]);
        let ok = |g: &mut Guard, m: &str, r: &str, cb: Option<&str>| g.begin_message(agent(), m, &NONCE, r, cb, NOW);
        assert_eq!(ok(&mut g, "", "login.example", None).unwrap_err(), Refusal::InvalidMessage("must not be empty"));
        let big = "x".repeat(MAX_MESSAGE_BYTES + 1);
        assert_eq!(ok(&mut g, &big, "login.example", None).unwrap_err(), Refusal::InvalidMessage("exceeds 4096 bytes"));
        assert!(ok(&mut g, &"x".repeat(MAX_MESSAGE_BYTES), "login.example", None).is_ok());
        // Multi-byte characters count in bytes, as Borsh encodes them.
        let wide = "é".repeat(MAX_MESSAGE_BYTES / 2 + 1);
        assert!(ok(&mut g, &wide, "login.example", None).is_err());
        for bad in ["", "login example", "login.example\n", &"r".repeat(MAX_RECIPIENT_BYTES + 1), "lögin.example"] {
            assert_eq!(ok(&mut g, "m", bad, None).unwrap_err(), Refusal::InvalidRecipient, "{bad:?}");
        }
        for bad in [" https://x", &format!("https://{}", "a".repeat(MAX_CALLBACK_URL_BYTES))] {
            assert_eq!(ok(&mut g, "m", "login.example", Some(bad)).unwrap_err(), Refusal::InvalidCallbackUrl);
        }
        assert!(ok(&mut g, "m", "login.example", Some("https://login.example/cb")).is_ok());
    }

    #[test]
    fn nep413_list_is_validated() {
        let mut g = configured();
        let set = |g: &mut Guard, list: Vec<String>| {
            let mut p = g.rules.to_policy();
            p.nep413_recipients = Some(list);
            g.set_policy(owner(), &p)
        };
        for bad in ["", "a b", &"r".repeat(MAX_RECIPIENT_BYTES + 1)] {
            assert!(matches!(set(&mut g, vec![bad.to_string()]), Err(Refusal::InvalidPolicy(_))), "{bad:?}");
        }
        let too_many = (0..=MAX_NEP413_RECIPIENTS).map(|i| format!("app{i}.example")).collect();
        assert!(set(&mut g, too_many).is_err());
        assert_eq!(g, configured());
        set(&mut g, vec!["b.example".into(), "a.example".into(), "b.example".into()]).unwrap();
        assert_eq!(g.rules.nep413(), ["a.example", "b.example"]);
        // `null` means empty, and set_policy replaces the list.
        let mut p = g.rules.to_policy();
        p.nep413_recipients = None;
        g.set_policy(owner(), &p).unwrap();
        assert!(g.rules.nep413().is_empty());
    }

    #[test]
    fn nep413_policy_is_owner_only() {
        let mut g = configured();
        let mut p = g.rules.to_policy();
        p.nep413_recipients = Some(vec!["evil.example".into()]);
        for caller in [agent(), stranger(), Principal::anonymous()] {
            assert!(g.set_policy(caller, &p).is_err());
        }
        assert!(g.rules.nep413().is_empty());
    }

    #[test]
    fn nep413_requests_are_logged() {
        let mut g = with_nep413(&["login.example"]);
        let _ = g.begin_message(agent(), "pay me", &[1, 2, 3], "login.example", None, NOW);
        let _ = g.begin_message(agent(), "x", &NONCE, "intents.near", Some("https://cb"), NOW + 1);
        let t = g.begin_message(agent(), "sign in", &NONCE, "login.example", None, NOW + 2).unwrap();
        assert_eq!(g.log.last().unwrap().outcome, Outcome::Pending);
        g.finish_message(t, Ok("PAYLOADHASH".into()));
        let t = g.begin_message(agent(), "again", &NONCE, "login.example", None, NOW + 3).unwrap();
        g.finish_message(t, Err("subnet down".into()));

        let log = g.audit_log(owner()).unwrap();
        assert_eq!(log.len(), 4);
        let m0 = log[0].message.as_ref().unwrap();
        assert_eq!((m0.message_bytes, m0.nonce_hex.as_str()), (6, "010203"));
        assert_eq!(m0.message_sha256, hex::encode(Sha256::digest(b"pay me")));
        assert!(matches!(&log[0].outcome, Outcome::Rejected { reason } if reason.contains("nonce")));
        assert_eq!((log[1].receiver_id.as_str(), log[1].message.as_ref().unwrap().callback_url.as_deref()), ("intents.near", Some("https://cb")));
        assert!(matches!(&log[1].outcome, Outcome::Rejected { reason } if reason.contains("never signed")));
        assert_eq!(log[2].outcome, Outcome::MessageSigned { payload_hash: "PAYLOADHASH".into() });
        assert_eq!(log[2].message.as_ref().unwrap().nonce_hex, hex::encode(NONCE));
        assert_eq!(log[3].outcome, Outcome::Rejected { reason: "signing failed: subnet down".into() });
        assert!(log.iter().all(|e| e.yocto.is_empty()));
        // Transfers stay without message info.
        sign(&mut g, "alice.testnet", 1, NOW).unwrap();
        assert_eq!(g.log.last().unwrap().message, None);
    }

    #[test]
    fn nep413_log_clips_input() {
        let mut g = with_nep413(&["login.example"]);
        let long = "y".repeat(10_000);
        let _ = g.begin_message(agent(), &long, &vec![0u8; 10_000], &long, Some(&long), NOW);
        let e = g.log.last().unwrap();
        let m = e.message.as_ref().unwrap();
        assert_eq!(e.receiver_id.chars().count(), MAX_LOGGED_INPUT + 1);
        assert_eq!(m.nonce_hex.chars().count(), 2 * NEP413_NONCE_BYTES + 1);
        assert_eq!(m.callback_url.as_ref().unwrap().chars().count(), MAX_LOGGED_INPUT + 1);
        assert_eq!(m.message_bytes, 10_000);
    }

    #[test]
    fn nep413_list_survives_the_state_round_trip() {
        let mut g = with_nep413(&["login.example", "app.example"]);
        let t = ask_msg(&mut g, agent(), "login.example", &NONCE).unwrap();
        g.finish_message(t, Ok("H".into()));
        let back: Guard = candid::decode_one(&candid::encode_one(&g).unwrap()).unwrap();
        assert_eq!(back, g);
        assert_eq!(back.rules.nep413(), ["app.example", "login.example"]);
    }

    /// State saved by the version before NEP-413 (no `nep413_recipients`, no
    /// `message`) must still restore, with an empty NEP-413 list.
    #[test]
    fn state_from_before_nep413_still_decodes() {
        #[derive(CandidType)]
        struct OldRules { per_tx_limit: u128, daily_limit: u128, allowlist: Vec<String> }
        #[derive(CandidType)]
        enum OldOutcome { Pending, Signed { tx_hash: String }, Rejected { reason: String } }
        #[derive(CandidType)]
        struct OldEntry { seq: u64, time_ns: u64, caller: Principal, receiver_id: String, yocto: String, outcome: OldOutcome }
        #[derive(CandidType)]
        struct OldGuard {
            owner: Principal,
            agent: Option<Principal>,
            rules: OldRules,
            spend: DailySpend,
            log: Vec<OldEntry>,
            next_seq: u64,
            rejected_unauthorized: u64,
        }
        let old = OldGuard {
            owner: owner(),
            agent: Some(agent()),
            rules: OldRules { per_tx_limit: 5, daily_limit: 8, allowlist: vec!["alice.testnet".into()] },
            spend: DailySpend { day: 1, spent: 3 },
            log: vec![
                OldEntry { seq: 0, time_ns: 1, caller: agent(), receiver_id: "alice.testnet".into(), yocto: "3".into(), outcome: OldOutcome::Signed { tx_hash: "T".into() } },
                OldEntry { seq: 1, time_ns: 2, caller: agent(), receiver_id: "x".into(), yocto: "1".into(), outcome: OldOutcome::Rejected { reason: "r".into() } },
                OldEntry { seq: 2, time_ns: 3, caller: agent(), receiver_id: "x".into(), yocto: "1".into(), outcome: OldOutcome::Pending },
            ],
            next_seq: 3,
            rejected_unauthorized: 4,
        };
        let g: Guard = candid::decode_one(&candid::encode_one(&old).unwrap()).unwrap();
        assert_eq!(g.rules.allowlist, ["alice.testnet"]);
        assert!(g.rules.nep413().is_empty());
        assert_eq!((g.spend.spent, g.next_seq, g.rejected_unauthorized), (3, 3, 4));
        assert_eq!(g.log[0].outcome, Outcome::Signed { tx_hash: "T".into() });
        assert!(g.log.iter().all(|e| e.message.is_none()));
    }
}
