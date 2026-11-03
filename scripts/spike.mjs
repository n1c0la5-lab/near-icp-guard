// The agent's side on the command line: ask the guard canister to sign a NEAR
// testnet transfer.
//
//   node spike.mjs account                                       # the canister's NEAR account
//   node spike.mjs config  --identity <owner|agent>              # policy, agent, spent today
//   node spike.mjs send    --identity <agent> <receiver> <NEAR>  # sign in the canister, send to NEAR
//
// The work is done by `guard.mjs` (shared with the agent in `agent/`). Canister
// calls go through the `icp` CLI, so they run as an icp identity and no key
// ever touches this script. Only the agent identity the owner set with
// `set_agent` gets signatures; the canister checks the policy first.
//
// Identity: --identity <name> or GUARD_IDENTITY (default: icp's default
// identity; `send` requires one to be named).
// Env: GUARD_CANISTER (default "guard"), ICP_ENV (default: icp's default env),
//      NEAR_RPC (default https://rpc.testnet.near.org)

import { createGuard, nearToYocto } from "./guard.mjs";

const EXPLORER = "https://testnet.nearblocks.io/txns/";

// `--identity <name>` may appear anywhere; everything else is positional.
const argv = process.argv.slice(2);
let identity = process.env.GUARD_IDENTITY;
const positional = [];
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--identity") identity = argv[++i];
  else positional.push(argv[i]);
}

function die(msg) {
  console.error(`\n✗ ${msg}`);
  process.exit(1);
}

const guard = createGuard({
  identity,
  canister: process.env.GUARD_CANISTER ?? "guard",
  environment: process.env.ICP_ENV,
  rpcUrl: process.env.NEAR_RPC ?? "https://rpc.testnet.near.org",
  onStep: (s) => console.log(s),
});

async function cmdAccount() {
  const { accountId, publicKey } = guard.account();
  console.log(`NEAR account (implicit): ${accountId}`);
  console.log(`public key:              ${publicKey}`);
  const b = await guard.balance(accountId);
  if (b.exists) {
    console.log(`balance:                 ${b.yocto} yoctoNEAR`);
  } else {
    console.log(`\nNot on testnet yet. Send it some testnet NEAR from any testnet wallet,`);
    console.log(`e.g. with near-cli:  near tokens <your-account> send-near ${accountId} '1 NEAR' network-config testnet`);
  }
}

function cmdConfig() {
  process.stdout.write(guard.config());
}

async function cmdSend(receiver, amount) {
  if (!receiver || !amount) die("usage: node spike.mjs send --identity <agent> <receiver> <amountNEAR>");
  if (!identity) die("send runs as the agent: name it with --identity <agent> or GUARD_IDENTITY");
  const { txHash } = await guard.transfer({ receiver, yocto: nearToYocto(amount) });
  console.log(`✓ on NEAR testnet: ${EXPLORER}${txHash}`);
}

const [cmd, ...rest] = positional;
try {
  if (cmd === "account") await cmdAccount();
  else if (cmd === "config") cmdConfig();
  else if (cmd === "send") await cmdSend(...rest);
  else die("usage: node spike.mjs account | config | send --identity <agent> <receiver> <amountNEAR>");
} catch (e) {
  die(e.message);
}
