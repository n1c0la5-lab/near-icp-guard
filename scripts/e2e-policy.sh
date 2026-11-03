#!/usr/bin/env bash
# End-to-end test of the policy engine on a LOCAL icp network.
#
#   icp network start -d     # once
#   scripts/e2e-policy.sh
#
# Reinstalls the `guard` canister (its state is wiped; the NEAR account stays
# the same, because the key depends on the canister id, not on its state), then
# exercises roles, the three rules, NEP-413 messages, the audit log and an
# upgrade.
#
# Nothing is sent to NEAR. Requests use a fake block hash (32 zero bytes), so
# even the signed transactions could never be accepted by any NEAR network.
#
# Needs `npm ci --ignore-scripts` in scripts/ once (for check-signed.mjs).
#
# Identities: the owner is your current icp identity (or $OWNER_IDENTITY).
# `e2e-agent` and `e2e-stranger` are created if missing, with plaintext storage
# (local testing only); their seed phrases are discarded, never printed.
set -euo pipefail

cd "$(dirname "$0")/.."
export DO_NOT_TRACK=1

if [[ -n "${ICP_ENVIRONMENT:-}" && "${ICP_ENVIRONMENT}" != "local" ]]; then
  echo "refusing: this script reinstalls the canister and runs only against the local environment" >&2
  exit 2
fi

OWNER="${OWNER_IDENTITY:-$(icp identity default)}"
AGENT=e2e-agent
STRANGER=e2e-stranger

for id in "$AGENT" "$STRANGER"; do
  if ! icp identity list | grep -qw -- "$id"; then
    icp identity new "$id" --storage plaintext --quiet >/dev/null # stdout is the seed: discarded
  fi
done
principal() { icp identity principal --identity "$1"; }
OWNER_P=$(principal "$OWNER")
AGENT_P=$(principal "$AGENT")
STRANGER_P=$(principal "$STRANGER")
[[ "$OWNER_P" != "2vxsx-fae" ]] || { echo "refusing: the owner identity is anonymous" >&2; exit 2; }
[[ -d scripts/node_modules ]] || { echo "run: (cd scripts && npm ci --ignore-scripts)" >&2; exit 2; }

NEAR=1000000000000000000000000
yocto() { python3 -c "print(int(round($1 * 10**6)) * 10**18)"; } # NEAR (6 decimals) -> yocto
FAKE_BLOCK=11111111111111111111111111111111

pass=0
fail=0
ok()  { echo "  PASS  $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $1"; echo "$2" | sed 's/^/        /'; fail=$((fail + 1)); }

call() { # identity method arg
  icp canister call guard "$2" "$3" --identity "$1" 2>&1 || true
}
expect_ok() { # label identity method arg
  local out; out=$(call "$2" "$3" "$4")
  if grep -q 'Ok' <<<"$out" && ! grep -q 'Err' <<<"$out"; then ok "$1"; else bad "$1" "$out"; fi
  LAST="$out"
}
expect_err() { # label substring identity method arg
  local out; out=$(call "$3" "$4" "$5")
  if grep -q 'Err' <<<"$out" && grep -qF -- "$2" <<<"$out"; then ok "$1  →  Err: $2"; else bad "$1 (wanted Err containing: $2)" "$out"; fi
}
req() { # receiver nearAmount
  echo "(record { receiver_id = \"$1\"; yocto = \"$(yocto "$2")\"; nonce = 1 : nat64; block_hash = \"$FAKE_BLOCK\" })"
}
POLICY="(record { per_tx_limit_yocto = \"$(yocto 0.5)\"; daily_limit_yocto = \"$(yocto 0.8)\"; allowlist = vec { \"alice.testnet\"; \"bob.testnet\" }; nep413_recipients = opt vec { \"login.example\" } })"
nonce() { python3 -c "print('blob \"' + ''.join('\\\\%02x' % (i + $2) for i in range($1)) + '\"')"; } # length offset -> candid blob
msg() { # recipient nonce-blob
  echo "(record { message = \"near-icp-guard e2e\"; nonce = $2; recipient = \"$1\"; callback_url = null })"
}

echo "owner    $OWNER  $OWNER_P"
echo "agent    $AGENT  $AGENT_P"
echo "stranger $STRANGER  $STRANGER_P"
echo

echo "== reinstall as owner (fresh state)"
icp deploy guard --mode reinstall -y --identity "$OWNER" >/dev/null 2>&1 || { echo "deploy failed"; icp deploy guard --mode reinstall -y --identity "$OWNER"; exit 1; }
ACCOUNT_BEFORE=$(call "$OWNER" account '()' | grep -o 'account_id = "[0-9a-f]*"')
echo "  $ACCOUNT_BEFORE"

echo "== safe default"
expect_ok  "owner reads config" "$OWNER" get_config '()'
grep -q 'per_tx_limit_yocto = "0"' <<<"$LAST" && grep -q 'agent = null' <<<"$LAST" \
  && ok "fresh config: no agent, limit 0" || bad "fresh config not deny-all" "$LAST"
expect_err "agent signs before setup" "no agent is set" "$AGENT" sign_transfer "$(req alice.testnet 0.1)"

echo "== roles"
expect_err "owner sets itself as agent" "different principal than the owner" "$OWNER" set_agent "(opt principal \"$OWNER_P\")"
expect_err "owner sets anonymous as agent" "anonymous principal cannot be the agent" "$OWNER" set_agent '(opt principal "2vxsx-fae")'
expect_err "stranger sets agent" "only the owner" "$STRANGER" set_agent "(opt principal \"$STRANGER_P\")"
expect_ok  "owner sets agent" "$OWNER" set_agent "(opt principal \"$AGENT_P\")"
expect_err "agent signs with default policy" "per-transaction limit of 0 yocto" "$AGENT" sign_transfer "$(req alice.testnet 0.1)"
expect_ok  "owner sets policy (0.5/tx, 0.8/day, alice+bob, NEP-413: login.example)" "$OWNER" set_policy "$POLICY"
expect_err "agent changes policy" "only the owner" "$AGENT" set_policy "(record { per_tx_limit_yocto = \"$(yocto 100)\"; daily_limit_yocto = \"$(yocto 100)\"; allowlist = vec { \"attacker.testnet\" } })"
expect_err "agent replaces agent" "only the owner" "$AGENT" set_agent "(opt principal \"$STRANGER_P\")"
expect_err "anonymous changes policy" "anonymous caller" anonymous set_policy "$POLICY"
expect_err "anonymous sets agent" "anonymous caller" anonymous set_agent '(opt principal "2vxsx-fae")'
expect_err "anonymous removes agent" "anonymous caller" anonymous set_agent '(null)'

echo "== rules"
expect_err "agent: 0.6 NEAR to alice (over per-tx)" "exceeds the per-transaction limit" "$AGENT" sign_transfer "$(req alice.testnet 0.6)"
expect_err "agent: 0.1 NEAR to attacker.testnet" "not on the allowlist" "$AGENT" sign_transfer "$(req attacker.testnet 0.1)"

echo "== two 0.5 NEAR requests in parallel (daily 0.8): exactly one may be signed"
P1=$(mktemp); P2=$(mktemp)
call "$AGENT" sign_transfer "$(req alice.testnet 0.5)" >"$P1" &
call "$AGENT" sign_transfer "$(req bob.testnet 0.5)" >"$P2" &
wait
signed=$(cat "$P1" "$P2" | grep -c 'signed_tx_base64' || true)
daily=$(cat "$P1" "$P2" | grep -c 'exceeds the daily limit' || true)
[[ "$signed" == 1 && "$daily" == 1 ]] && ok "parallel: 1 signed, 1 over daily limit" || bad "parallel: $signed signed, $daily over daily limit" "$(cat "$P1" "$P2")"
rm -f "$P1" "$P2"
expect_err "agent: 0.4 NEAR after 0.5 (0.9 > 0.8)" "exceeds the daily limit" "$AGENT" sign_transfer "$(req alice.testnet 0.4)"

echo "== nobody but the agent signs"
expect_err "owner signs" "owner cannot request signatures" "$OWNER" sign_transfer "$(req alice.testnet 0.1)"
expect_err "stranger signs" "caller is not the agent" "$STRANGER" sign_transfer "$(req alice.testnet 0.1)"
expect_err "anonymous signs" "anonymous caller" anonymous sign_transfer "$(req alice.testnet 0.1)"

echo "== reads"
expect_ok  "agent reads config" "$AGENT" get_config '()'
expect_err "anonymous reads config" "anonymous caller" anonymous get_config '()'
expect_err "stranger reads config" "only the owner or the agent" "$STRANGER" get_config '()'
expect_err "stranger reads audit log" "only the owner or the agent" "$STRANGER" audit_log '()'
expect_err "anonymous reads audit log" "anonymous caller" anonymous audit_log '()'

CONFIG_BEFORE=$(call "$OWNER" get_config '()' | grep -v 'utc_day')
LOG_BEFORE=$(call "$OWNER" audit_log '()')
N_BEFORE=$( (grep -o 'seq = ' <<<"$LOG_BEFORE" || true) | wc -l)
grep -q "spent_today_yocto = \"$(yocto 0.5)\"" <<<"$CONFIG_BEFORE" && ok "spent today = 0.5 NEAR" || bad "spent today" "$CONFIG_BEFORE"
# Logged: default policy + 2 rules + 2 parallel + 1 daily + owner = 7.
# Counted only (neither owner nor agent at the time): agent before setup, stranger, anonymous = 3.
[[ "$N_BEFORE" == 7 ]] && ok "audit log has the 7 owner/agent sign requests" || bad "audit log has $N_BEFORE entries, want 7" "$LOG_BEFORE"
grep -q 'rejected_unauthorized = 3' <<<"$CONFIG_BEFORE" && ok "3 requests from non-owner/non-agent counted, not logged" || bad "rejected_unauthorized" "$CONFIG_BEFORE"

echo "== upgrade"
upgrades() { icp canister logs guard 2>/dev/null | grep -c 'post_upgrade: state restored' || true; }
UPGRADES_BEFORE=$(upgrades)
icp deploy guard --mode upgrade -y --identity "$OWNER" >/dev/null 2>&1 || { echo "upgrade failed"; icp deploy guard --mode upgrade -y --identity "$OWNER"; exit 1; }
UPGRADES_AFTER=$(upgrades)
[[ "$UPGRADES_AFTER" -gt "$UPGRADES_BEFORE" ]] && ok "post_upgrade ran (canister log: $UPGRADES_BEFORE -> $UPGRADES_AFTER)" || bad "no post_upgrade in the canister log" "$(icp canister logs guard 2>&1 | tail -5)"
CONFIG_AFTER=$(call "$OWNER" get_config '()' | grep -v 'utc_day')
LOG_AFTER=$(call "$OWNER" audit_log '()')
ACCOUNT_AFTER=$(call "$OWNER" account '()' | grep -o 'account_id = "[0-9a-f]*"')
[[ "$CONFIG_AFTER" == "$CONFIG_BEFORE" ]] && ok "owner, agent, policy, spent today unchanged" || bad "config changed" "$CONFIG_BEFORE"$'\n---\n'"$CONFIG_AFTER"
[[ "$LOG_AFTER" == "$LOG_BEFORE" ]] && ok "audit log unchanged ($N_BEFORE entries)" || bad "audit log changed" "$LOG_AFTER"
[[ -n "$ACCOUNT_BEFORE" && "$ACCOUNT_AFTER" == "$ACCOUNT_BEFORE" ]] && ok "same NEAR account" || bad "NEAR account changed" "$ACCOUNT_BEFORE / $ACCOUNT_AFTER"
expect_err "agent: 0.4 NEAR after upgrade (budget survived)" "exceeds the daily limit" "$AGENT" sign_transfer "$(req alice.testnet 0.4)"
expect_ok  "agent: 0.3 NEAR to alice (0.8 = limit)" "$AGENT" sign_transfer "$(req alice.testnet 0.3)"
expect_err "agent: 1 more yocto" "exceeds the daily limit" "$AGENT" sign_transfer "(record { receiver_id = \"alice.testnet\"; yocto = \"1\"; nonce = 1 : nat64; block_hash = \"$FAKE_BLOCK\" })"

echo "== NEP-413 messages (own recipient allowlist)"
N32=$(nonce 32 0)
# icp prints records on one line or several, depending on length: compare
# without whitespace, and count with `grep -o`, not per line.
only_login() { tr -d ' \n' | grep -Eq 'nep413_recipients=optvec\{"login.example";?\}'; }
only_login <<<"$CONFIG_AFTER" && ok "NEP-413 list survived the upgrade" || bad "NEP-413 list after upgrade" "$CONFIG_AFTER"
expect_err "owner lists intents.near" "can never be a NEP-413 recipient" "$OWNER" set_policy "(record { per_tx_limit_yocto = \"$(yocto 0.5)\"; daily_limit_yocto = \"$(yocto 0.8)\"; allowlist = vec { \"alice.testnet\" }; nep413_recipients = opt vec { \"login.example\"; \"intents.near\" } })"
only_login <<<"$(call "$OWNER" get_config '()')" && ok "refused policy left the NEP-413 list unchanged" || bad "NEP-413 list changed" "$(call "$OWNER" get_config '()')"
expect_err "agent: message for intents.near" "are never signed" "$AGENT" sign_message "$(msg intents.near "$N32")"
expect_err "agent: message for a recipient not on the list" "not on the NEP-413 allowlist" "$AGENT" sign_message "$(msg other.example "$N32")"
expect_err "agent: transfer receiver is no NEP-413 recipient" "not on the NEP-413 allowlist" "$AGENT" sign_message "$(msg alice.testnet "$N32")"
expect_err "agent: 31-byte nonce" "nonce must be exactly 32 bytes, got 31" "$AGENT" sign_message "$(msg login.example "$(nonce 31 0)")"
expect_err "agent: 33-byte nonce" "nonce must be exactly 32 bytes, got 33" "$AGENT" sign_message "$(msg login.example "$(nonce 33 0)")"
expect_err "owner signs a message" "owner cannot request signatures" "$OWNER" sign_message "$(msg login.example "$N32")"
expect_err "stranger signs a message" "caller is not the agent" "$STRANGER" sign_message "$(msg login.example "$N32")"
expect_err "anonymous signs a message" "anonymous caller" anonymous sign_message "$(msg login.example "$N32")"
expect_ok  "agent: message for login.example" "$AGENT" sign_message "$(msg login.example "$N32")"
grep -q 'signature = "' <<<"$LAST" && ok "answer carries a signature" || bad "no signature" "$LAST"
if CHECK=$(cd scripts && node check-nep413.mjs --identity "$AGENT" login.example 2>&1); then ok "check-nep413: 3 signatures verified by near-api-js verifyMessage, 6 altered ones refused"; else bad "check-nep413" "$CHECK"; fi
echo "$CHECK" | sed 's/^/      /'
NLOG=$(call "$OWNER" audit_log '()')
n_msg=$( (grep -o 'message_sha256' <<<"$NLOG" || true) | wc -l)
n_signed=$( (grep -o 'MessageSigned' <<<"$NLOG" || true) | wc -l)
# Logged: intents.near, not listed, transfer receiver, 31, 33, owner, 1 signed + 3 from check-nep413 = 10.
[[ "$n_msg" == 10 && "$n_signed" == 4 ]] && ok "audit log: 10 NEP-413 requests from owner/agent, 4 signed" || bad "audit log: $n_msg NEP-413 entries, $n_signed signed (want 10, 4)" "$NLOG"
grep -q 'rejected_unauthorized = 5' <<<"$(call "$OWNER" get_config '()')" && ok "stranger + anonymous messages counted, not logged (3 -> 5)" || bad "rejected_unauthorized" "$(call "$OWNER" get_config '()')"

echo "== signed transaction from the update response (scripts/check-signed.mjs)"
expect_ok  "owner raises daily limit to 1 NEAR" "$OWNER" set_policy "(record { per_tx_limit_yocto = \"$(yocto 0.5)\"; daily_limit_yocto = \"$(yocto 1)\"; allowlist = vec { \"alice.testnet\"; \"bob.testnet\" } })"
if CHECK=$(cd scripts && node check-signed.mjs --identity "$AGENT" 2>&1); then ok "check-signed: real response accepted, 6 wrong ones refused"; else bad "check-signed" "$CHECK"; fi
echo "$CHECK" | sed 's/^/      /'

echo "== agent replaced, then removed"
expect_ok  "owner replaces agent with $STRANGER" "$OWNER" set_agent "(opt principal \"$STRANGER_P\")"
expect_err "old agent signs" "caller is not the agent" "$AGENT" sign_transfer "$(req alice.testnet 0.01)"
expect_ok  "new agent signs 0.01 NEAR" "$STRANGER" sign_transfer "$(req alice.testnet 0.01)"
expect_err "old agent reads the log" "only the owner or the agent" "$AGENT" audit_log '()'
expect_ok  "owner removes the agent" "$OWNER" set_agent '(null)'
expect_err "removed agent signs" "no agent is set" "$STRANGER" sign_transfer "$(req alice.testnet 0.01)"
expect_ok  "owner sets $AGENT again" "$OWNER" set_agent "(opt principal \"$AGENT_P\")"

echo "== audit log (owner)"
call "$OWNER" audit_log '()' | python3 -c '
import re, sys
def get(pat, t):
    m = re.search(pat, t)
    return m.group(1) if m else "?"
for e in sys.stdin.read().split("record { seq = ")[1:]:
    seq = e.split(" ", 1)[0]
    caller = get(r"caller = principal \"([^\"]+)\"", e)[:11]
    to = get(r"receiver_id = \"([^\"]*)\"", e)
    yocto = get(r"yocto = \"([^\"]*)\"", e)
    out = get(r"outcome = variant \{ (\w+)", e)
    detail = get(r"(?:reason|tx_hash|payload_hash) = \"([^\"]*)\"", e)
    if "message_bytes" in e:
        yocto = "msg %s bytes" % get(r"message_bytes = ([0-9_]+)", e)
    print("  #%-2s %-11s %-16s %24s  %-13s %s" % (seq, caller, to, yocto, out, detail))
'

echo
echo "e2e: $pass passed, $fail failed"
[[ "$fail" == 0 ]]
