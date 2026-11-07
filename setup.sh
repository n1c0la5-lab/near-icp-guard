#!/usr/bin/env bash
# One command: a local ICP network, the guard canister installed on it, the
# policy set, and a probe that has the canister sign the allowed payments and
# refuse the forbidden ones. Ends with PASS or FAIL.
#
#   ./setup.sh
#   ./setup.sh --wasm <file>     install your own build instead (sabotage probes, see README)
#
# LOCAL ONLY. Nothing here talks to ICP mainnet or to NEAR, and nothing needs a
# key or an account: the probe replays fixed requests instead of asking a model.
# It refuses, with exit code 2, when the environment points anywhere but the
# local network. It installs nothing globally; it only creates files in this
# directory (`scripts/node_modules`, `target/`, `.icp/cache/`, `agent/logs/`) and
# one local icp identity, `guard-quickstart-owner` (plaintext, no funds).
#
# Exit codes: 0 PASS · 1 FAIL · 2 refused (not the local network) · 3 something
# you need is missing.
set -euo pipefail

WASM=""
case "${1:-}" in
  "") ;;
  --wasm) [[ -n "${2:-}" && -f "$2" && $# -eq 2 ]] || { echo "usage: ./setup.sh [--wasm <file>]  (--wasm installs your own build instead of this source: for sabotage probes)" >&2; exit 2; }
          WASM=$(cd "$(dirname "$2")" && pwd)/$(basename "$2") ;;
  *) echo "usage: ./setup.sh [--wasm <file>]" >&2; exit 2 ;;
esac

cd "$(dirname "$0")"
ROOT=$PWD
export DO_NOT_TRACK=1
OWNER="${OWNER_IDENTITY:-guard-quickstart-owner}"

say()  { printf '%s\n' "$*"; }
step() { printf '\n[%s] %s\n' "$1" "$2"; }
refuse() { printf '\nREFUSED: %s\n' "$*" >&2; exit 2; }
fail()   { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }

# ---- 1. the lock: local network only ------------------------------------------
# icp reads these from the environment. Anything but the two environments of
# this project's icp.yaml (both on the local network) is refused, not corrected.
step 1/6 "Checking that this run stays on the local network"
for v in ICP_ENVIRONMENT ICP_ENV ICP_NETWORK; do
  val="${!v:-}"
  case "$val" in
    "") ;;
    local|demo) unset "$v" ;; # harmless, but every call below names its environment itself
    *) refuse "$v=$val. This script runs only against the local network and reinstalls a canister on it. Unset $v and run it again." ;;
  esac
done
if [[ -n "${ICP_PROJECT_ROOT:-}" && "$(cd "$ICP_PROJECT_ROOT" 2>/dev/null && pwd)" != "$ROOT" ]]; then
  refuse "ICP_PROJECT_ROOT=$ICP_PROJECT_ROOT points at another project. Unset it and run it again."
fi
export ICP_PROJECT_ROOT="$ROOT"
say "  ok: no environment override"

# ---- 2. prerequisites ----------------------------------------------------------
step 2/6 "Checking what you need"
missing=()
need() { missing+=("$1"); }
ver_ge() { # have want: dotted versions, numeric compare of the first two parts
  local h1=${1%%.*} hrest=${1#*.} w1=${2%%.*} wrest=${2#*.}
  local h2=${hrest%%.*} w2=${wrest%%.*}
  (( h1 > w1 || (h1 == w1 && h2 >= w2) ))
}

if command -v node >/dev/null && command -v npm >/dev/null; then
  nv=$(node -p 'process.versions.node')
  if ver_ge "$nv" 22.0; then say "  ok: node $nv"; else need "Node 22 or newer (found $nv). Install it from https://nodejs.org/ or with your version manager."; fi
else
  need "Node 22 or newer, with npm. Install it from https://nodejs.org/ or with your version manager."
fi

if command -v cargo >/dev/null && command -v rustc >/dev/null; then
  say "  ok: $(rustc --version)"
  libdir=$(rustc --print target-libdir --target wasm32-unknown-unknown 2>/dev/null || true)
  if compgen -G "$libdir/libcore-*" >/dev/null 2>&1; then
    say "  ok: wasm32-unknown-unknown target"
  else
    need "The Rust target wasm32-unknown-unknown. Run: rustup target add wasm32-unknown-unknown"
  fi
else
  need "Rust (cargo and rustc). Install it from https://rustup.rs/ , then run: rustup target add wasm32-unknown-unknown"
fi

if command -v icp >/dev/null; then
  iv=$(icp --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || true)
  if [[ -n "$iv" ]] && ver_ge "$iv" 1.2; then say "  ok: icp $iv"; else need "icp-cli 1.2 or newer (found ${iv:-an unreadable version}). Run: npm install -g @icp-sdk/icp-cli"; fi
else
  need "icp-cli 1.2 or newer. Run: npm install -g @icp-sdk/icp-cli"
fi

if command -v ic-wasm >/dev/null; then
  say "  ok: ic-wasm $(ic-wasm --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
else
  need "ic-wasm (the build recipe stops without it). Run: cargo install ic-wasm --locked"
fi

if (( ${#missing[@]} )); then
  printf '\nMISSING (nothing was installed or changed):\n' >&2
  for m in "${missing[@]}"; do printf '  - %s\n' "$m" >&2; done
  printf '\nThen run ./setup.sh again.\n' >&2
  exit 3
fi

# ---- 3. dependencies of the scripts --------------------------------------------
step 3/6 "Installing the script dependencies (scripts/, npm ci, no install scripts)"
(cd scripts && npm ci --ignore-scripts --no-audit --no-fund --loglevel=error) || fail "npm ci failed in scripts/"

# ---- 4. the local network ------------------------------------------------------
step 4/6 "Starting the local ICP network (reused if it is already running)"
PORT=$(awk '/^[[:space:]]*port:[[:space:]]*[0-9]+/ { gsub(/[^0-9]/, "", $2); print $2; exit }' icp.yaml)
if icp network status -e demo --json >/dev/null 2>&1; then
  say "  already running for this project"
else
  if [[ -n "$PORT" ]] && (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
    printf '\nFAIL: port %s is taken by another program. Stop it, or change gateway.port in icp.yaml.\n' "$PORT" >&2
    exit 1
  fi
  icp network start -e demo -d || fail "the local network did not start. icp's message is above; the first start also downloads icp's network launcher, so it needs internet access once"
fi
# Before any canister is touched: the same check the demo makes, with the same code.
node agent/demo/check-local.mjs || refuse "icp's demo environment is not a managed network on this machine. Nothing was installed."

# ---- 5. owner identity ---------------------------------------------------------
step 5/6 "Preparing the local owner identity ($OWNER)"
if icp identity list 2>/dev/null | grep -Eq "(^|[[:space:]])${OWNER}([[:space:]]|\$)"; then
  say "  exists"
else
  icp identity new "$OWNER" --storage plaintext --quiet >/dev/null # stdout is the seed phrase: discarded, local test identity only
  say "  created (plaintext, local only)"
fi
export OWNER_IDENTITY="$OWNER"

# ---- 6. install, set the policy, probe -----------------------------------------
step 6/6 "Installing the canister, setting the policy, replaying requests (the first build takes a few minutes)"
EVIDENCE="$ROOT/agent/logs/quickstart/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVIDENCE"
rc=0
demo_args=(--scripted --runs 1 --out "$EVIDENCE")
if [[ -n "$WASM" ]]; then
  demo_args+=(--wasm "$WASM")
  say "  installing $WASM instead of this source (sabotage probe)"
fi
node agent/demo/demo.mjs "${demo_args[@]}" || rc=$?
case $rc in
  0|1) ;;
  2)   refuse "the demo stopped before it ran (see above). Nothing was signed." ;;
  *)   fail "the demo crashed (exit code $rc)" ;;
esac

printf '\n'
vrc=0
node agent/demo/verdict.mjs "$EVIDENCE/summary.json" || vrc=$?
printf '\nevidence: %s\n' "$EVIDENCE"
if (( rc == 0 && vrc == 0 )); then
  cat <<DONE

PASS  The guard runs on your machine. It signed the requests the policy allows
      and refused the forbidden ones. Nothing was sent to NEAR; no key or
      account was used; no model was asked.

Look at it:
  icp canister call guard audit_log '()' --query -e demo --identity $OWNER
  icp canister call guard get_config '()' --query -e demo --identity $OWNER
Stop the network when you are done:  icp network stop
DONE
  exit 0
fi
fail "the probe did not pass (demo exit code $rc, verdict exit code $vrc). Details above and in $EVIDENCE."
