# near-icp-guard (working title)

An ICP canister that owns a NEAR account and signs NEAR transactions with a
**threshold Ed25519 key**: the key is split across the subnet's nodes and never
exists in one place. An AI agent can *ask* for a payment; it never holds a key.

Before it signs, the canister checks a **policy** the agent cannot change:
a per-transaction limit, a daily limit and a receiver allowlist. Every request,
signed or rejected, goes into an audit log.

Built at NEAR HACKATHON (Nov 2026).

## How it works

1. The canister derives an Ed25519 public key via `schnorr_public_key`.
2. Its NEAR account is the **implicit account** `hex(public_key)`. Sending
   testnet NEAR to it creates it, with the canister's key as its only
   full-access key.
3. To pay, the canister builds the NEAR transaction itself (Borsh), signs
   `sha256(tx)` with `sign_with_schnorr`, **verifies the signature locally**, and
   returns the signed transaction.
4. `scripts/spike.mjs` (running as the agent) fetches nonce and block hash
   from NEAR RPC and asks the canister to sign. Before it submits, it checks
   the **signed transaction from the update response**: the unsigned part must
   equal what NEAR's own library (`@near-js/transactions`) builds, byte for
   byte, and the ed25519 signature must verify against the canister's key over
   `sha256(unsigned)` (`scripts/verify-signed.mjs`). The earlier
   `preview_transfer` comparison is a query, answered by a single replica, so
   it is only a hint.

Nonce and block hash come from the caller and are **untrusted by design**: a
wrong value only makes NEAR reject the transaction. It never changes what gets
paid to whom.

## Policy

**Roles**

| Role | Who | May | May not |
|---|---|---|---|
| owner | the identity that installed the canister | set the agent (`set_agent`), set the policy (`set_policy`), read config and log | request signatures |
| agent | one principal, set by the owner | request signatures (`sign_transfer`), read config and log | change the policy, change the agent |
| anyone else | — | `account`, `preview_transfer` (signs nothing) | sign, set, read config or log |

`init` refuses the anonymous principal as owner: the install traps and nothing
is installed. Every protected method (`sign_transfer`, `set_agent`,
`set_policy`, `get_config`, `audit_log`) refuses an anonymous caller
explicitly. The agent can never be the owner or the anonymous principal.
The owner can replace the agent (`set_agent(opt <new>)`) or remove it
(`set_agent(null)`); the old agent cannot sign from that moment on.

**Rules**, checked before every signature, in this order:

1. **Per-transaction limit**: amount > limit ⇒ rejected.
2. **Receiver allowlist**: receiver not on the list ⇒ rejected. Entries must be
   valid NEAR account ids (at most 100).
3. **Daily limit**: amount signed so far in the current UTC day + this amount
   > limit ⇒ rejected. Sums use checked u128 arithmetic.

**Safe default.** After install there is no agent, both limits are 0 and the
allowlist is empty: nothing gets signed. A zero amount is always rejected.

**The daily limit counts signatures, not arrivals.** The canister does not see
NEAR, so it counts an amount when it signs it. A transaction that was signed
but never submitted (or rejected by NEAR) still uses up budget. This errs on
the safe side.

**Reserve before the await.** Signing is an `await` on the subnet, and other
requests run while one waits. So the canister checks all rules *and reserves*
the amount in one synchronous step before it awaits; a request that arrives in
the meantime sees the reservation. If signing fails, the reservation is
released. Tested natively and live (see below: two parallel requests, exactly
one signed).

**Audit log.** Every `sign_transfer` call from the owner or the agent, signed
or rejected, is logged with time, caller, receiver, amount (as requested,
clipped to 64 characters) and outcome: `Signed` with the transaction hash, or
`Rejected` with the reason. `Pending` marks a request whose signature has not
come back yet. The log is a ring buffer of the last 1000 entries; `seq` keeps
counting, so a gap at the start shows evicted entries. Calls from anyone else
are **counted, not logged** (`rejected_unauthorized` in `get_config`), so a
stranger cannot push the real entries out of the ring buffer. Owner and agent
read the log with `audit_log` (a query call, answered by one replica and not
certified).

**Upgrades** keep owner, agent, policy, today's spent amount, the counter and
the audit log: `pre_upgrade` writes them to stable memory as one candid value
(`stable_save`). That value is bounded: a test fills the log and the
allowlist with maximum-size entries and measures 498,289 bytes
(`policy::tests::worst_case_state_size`). Upgrading the spike version to this one is refused
(`post_upgrade` traps and the upgrade rolls back, measured locally): reinstall
instead. The NEAR account stays the same either way, because the key depends
on the canister id, not on its state.

**What the policy does not cover.** The policy binds callers of the canister,
not its **controllers**: a controller can install different code. Who controls
the canister is set at deploy time (`icp canister status guard` lists them).

**Not built:** time windows, multi-signature approval, rate limits per minute,
more than one agent, tokens other than NEAR.

## Run it

Prerequisites: Rust with `wasm32-unknown-unknown`, Node 22+, `icp` ≥ 1.2, and
`ic-wasm` (the `@dfinity/rust@v3.3.0` recipe aborts without it):

```bash
cargo install ic-wasm --locked
```

Measured with ic-wasm 0.11.1, icp 1.8.0, rustc 1.99.0, Node 22.

```bash
# tests (native, no network)
cargo test --locked

# local ICP network + deploy
icp network start -d
icp deploy

# scripts
scripts/e2e-policy.sh                  # local end-to-end test of the policy, sends nothing to NEAR

cd scripts && npm ci --ignore-scripts
node spike.mjs account                 # prints the canister's NEAR account
# fund that account with testnet NEAR; as the owner, set the agent and a policy:
icp canister call guard set_agent '(opt principal "<agent principal>")'
icp canister call guard set_policy '(record { per_tx_limit_yocto = "500000000000000000000000"; daily_limit_yocto = "800000000000000000000000"; allowlist = vec { "<receiver>.testnet" } })'
# then, as the agent:
node spike.mjs send --identity <agent identity> <receiver>.testnet 0.1
node spike.mjs config --identity <agent identity>   # policy and today's spent amount
```

`scripts/e2e-policy.sh` (needs `npm ci --ignore-scripts` in `scripts/` once)
reinstalls `guard` on the local network (state wiped, same NEAR account),
creates the identities `e2e-agent` and `e2e-stranger` if missing (plaintext
storage, local only), and checks roles, anonymous on every protected method,
the three rules, two parallel requests, the audit log and its counter, an
upgrade, the check of the signed transaction (`scripts/check-signed.mjs`:
the real response passes, six tampered or different ones are refused), and
replacing and removing the agent. Its signed transactions use a fake block
hash (32 zero bytes), so no NEAR network would accept them.

The local network listens on **port 8010** (set in `icp.yaml`); 8000 is a
common default and was taken on our dev machine. Change it there if 8010 is
busy for you.

**Deploy with your own icp identity, not `anonymous`.** Without one, `icp`
deploys as the anonymous principal. In the spike that principal became the
owner and anyone could sign (measured: an anonymous `sign_transfer` returned
`Ok`). **Fixed:** `init` now traps for an anonymous installer
(test `policy::tests::anonymous_owner_is_rejected`; measured locally:
`icp deploy --mode reinstall --identity anonymous` fails with "the anonymous
principal cannot be the owner" and the installed module stays unchanged).

```bash
icp identity new my-identity       # any name
icp identity default my-identity   # select it before `icp deploy`
```

`spike.mjs send` refuses to sign if the canister's transaction bytes differ
from what `@near-js/transactions` builds for the same input.

## Testing against NEAR, not against ourselves

Round-trip tests can stay green while both sides share a mistake. So the
encoder is tested against **vectors generated by NEAR's own JS library**
(`scripts/reference-vector.mjs` → `canister/tests/vectors/near-tx.json`),
including `u64::MAX` nonces and `u128::MAX` amounts.

Sabotage probes for the encoder, each caught by the tests:

| Deliberate bug | Caught |
|---|---|
| Transfer action index 3 → 2 | 3 tests red |
| amount encoded as u64 instead of u128 | 3 tests red |
| nonce big-endian | 3 tests red |
| receiver and signer swapped | 3 tests red |
| hash over the signed instead of the unsigned tx | 1 test red |
| implicit account id in uppercase hex | 1 test red |
| `guard.did` out of sync with the code | 1 test red |

Regenerate vectors only with `npm run vectors`, never by hand.
`npm run vectors:check` fails if the library and the checked-in file disagree.

The policy is pure code (`canister/src/policy.rs`: no IC calls, time passed in),
so every rule is tested natively. Sabotage probes for the policy, each run on a
copy with one rule broken (`cargo test --no-fail-fast`, 33 tests):

| Deliberate bug | Caught |
|---|---|
| per-transaction limit check removed | 2 tests red |
| daily limit check removed | 3 tests red |
| allowlist check removed | 4 tests red |
| reservation moved after the await (check before, reserve after) | 2 tests red |
| failed signature keeps its reservation | 1 test red |
| daily total never resets at the UTC day change | 2 tests red |
| release ignores the day of the reservation | 1 test red |
| `checked_add` replaced by `wrapping_add` | 1 test red |
| anonymous owner accepted | 1 test red |
| explicit anonymous check removed | 2 tests red |
| `set_policy` without owner check (agent changes policy) | 2 tests red |
| `set_agent` without owner check | 2 tests red |
| agent may be the owner | 1 test red |
| owner may sign | 2 tests red |
| anyone may sign (stranger branch and agent check removed) | 4 tests red |
| `set_agent` cannot replace an existing agent | 1 test red |
| `set_agent(null)` ignored | 2 tests red |
| rejected requests not logged | 3 tests red |
| strangers written into the log again | 2 tests red |
| anyone may read config and log | 1 test red |
| audit log unbounded | 3 tests red |
| `guard.did` out of sync (`audit_log` removed) | 1 test red |

And two probes against the deployed canister on the local network, with
`scripts/e2e-policy.sh`:

| Deliberate bug | Caught |
|---|---|
| reservation moved after the await | 3 checks red: both parallel requests signed |
| `pre_upgrade` saves a fresh state | 5 checks red: config, log and budget lost |

And two probes against the check of the signed transaction
(`scripts/check-signed.mjs`, run against the local canister):

| Deliberate bug | Caught |
|---|---|
| ed25519 verification skipped | 1 check red: flipped signature byte accepted |
| byte comparison with near-js skipped | 1 check red: validly signed 2-yocto tx accepted for a 1-yocto request |

## Proven so far (spike gate)

- **Signed on ICP, accepted by NEAR testnet.** The canister signed a 0.1 NEAR
  transfer with its threshold key; NEAR finalized it:
  [`HUvCWehTDRtJDVqsipXcgsb16kHXaUsbDYbxegNAL1qN`](https://testnet.nearblocks.io/txns/HUvCWehTDRtJDVqsipXcgsb16kHXaUsbDYbxegNAL1qN)
  (status `SuccessValue`, `FINAL`). Signer is the canister's implicit account
  `10283143de96cb3c61b3e410ba13589bd7cd7fbdcdd718860673e2833cb22c86`, key
  `ed25519:265531gAWxPEFvGhDbiNhudp2X7CPmTZgvHAMScGqPbj`, action
  `Transfer` of 0.1 NEAR. This ran against a local ICP network with the local
  `test_key_1`, not against mainnet ICP.
- `icp.yaml` builds and deploys locally (with the two fixes above).
- `test_key_1` exists on the local network; `account` returns the same NEAR
  account before and after a reinstall.
- `spike.mjs` parses the `icp` output (`account`, `send`).
- **Policy on the local network.** `scripts/e2e-policy.sh` passes all 45 checks:
  default deny, roles, anonymous refused on every protected method, the three
  rules, two parallel requests of which exactly one is signed, the audit log,
  an upgrade that keeps owner, agent, policy, spent amount, log and NEAR
  account, the signed-transaction check, and agent replacement and removal. (The testnet transfer above was
  signed by the spike, before the policy existed.)

## Known unknowns (check before trusting)

- **Key name.** Default `test_key_1`. Production is `key_1`, not yet tried.
  Override at install with `(opt record { key_name = opt "key_1" })`.
- **Upgrades.** Exercised on the local network only (`scripts/e2e-policy.sh`),
  not on ICP mainnet.
- **Policy with real NEAR.** The policy has run against the local network
  with fake block hashes; a policy-checked transfer has not yet been
  submitted to NEAR testnet.
- **Audit log flooding by the agent.** Strangers are only counted, but the
  agent itself (for example a compromised one) can still fill the ring buffer
  with rejected requests and push older entries out; `seq` shows that it
  happened, the evicted entries are gone.
- **`spike.mjs` wiring.** `check-signed.mjs` tests the check function against
  the real canister; that `spike.mjs send` calls it before `send_tx` was seen
  against a local stand-in RPC, not against NEAR testnet yet.
- **ICP mainnet.** Nothing here has run on ICP mainnet.

## License

Apache-2.0
