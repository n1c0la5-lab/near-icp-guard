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
//! Every protected method refuses the anonymous principal first, explicitly,
//! even where the role check would refuse it anyway.
//!
//! Audit log: sign requests from the owner and the agent are logged with their
//! outcome. Requests from anyone else are only counted
//! (`rejected_unauthorized`): if they were logged, any stranger could push the
//! real entries out of the bounded log.

use crate::near_tx::validate_account_id;
use candid::{CandidType, Deserialize, Principal};
use std::fmt;

pub const NANOS_PER_DAY: u64 = 86_400 * 1_000_000_000;
/// The audit log keeps the most recent entries; `seq` keeps counting.
pub const AUDIT_LOG_CAPACITY: usize = 1000;
pub const MAX_ALLOWLIST_LEN: usize = 100;
/// Caller-supplied strings are clipped before they go into the log.
const MAX_LOGGED_INPUT: usize = 64;
const MAX_LOGGED_REASON: usize = 256;

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
}

/// The rules as the guard enforces them.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Rules {
    pub per_tx_limit: u128,
    pub daily_limit: u128,
    /// Validated NEAR account ids, sorted and deduplicated.
    pub allowlist: Vec<String>,
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
        Ok(Rules { per_tx_limit, daily_limit, allowlist })
    }

    pub fn to_policy(&self) -> Policy {
        Policy {
            per_tx_limit_yocto: self.per_tx_limit.to_string(),
            daily_limit_yocto: self.daily_limit.to_string(),
            allowlist: self.allowlist.clone(),
        }
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
    Rejected { reason: String },
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    /// Counts every request ever logged; gaps at the start show eviction.
    pub seq: u64,
    pub time_ns: u64,
    pub caller: Principal,
    /// As requested (clipped), even when invalid.
    pub receiver_id: String,
    /// As requested (clipped), even when invalid.
    pub yocto: String,
    pub outcome: Outcome,
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

    /// Replaces all three rules at once. Today's spent total is kept.
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
}
