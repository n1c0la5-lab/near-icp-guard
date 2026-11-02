// The agent's side: ask the guard canister to sign a NEAR testnet transfer.
//
//   node spike.mjs account                                       # the canister's NEAR account
//   node spike.mjs config  --identity <owner|agent>              # policy, agent, spent today
//   node spike.mjs send    --identity <agent> <receiver> <NEAR>  # sign in the canister, send to NEAR
//
// Canister calls go through the `icp` CLI, so they run as an icp identity and
// no key ever touches this script. Only the agent identity the owner set with
// `set_agent` gets signatures; the canister checks the policy first.
//
// Identity: --identity <name> or GUARD_IDENTITY (default: icp's default
// identity; `send` requires one to be named).
// Env: GUARD_CANISTER (default "guard"), ICP_ENV (default: icp's default env),
//      NEAR_RPC (default https://rpc.testnet.near.org)

import { execFileSync } from "node:child_process";
import { actionCreators, createTransaction, encodeTransaction } from "@near-js/transactions";
import { PublicKey } from "@near-js/crypto";
import { parseNearAmount } from "@near-js/utils";
import bs58 from "bs58";

const CANISTER = process.env.GUARD_CANISTER ?? "guard";
const RPC = process.env.NEAR_RPC ?? "https://rpc.testnet.near.org";
const EXPLORER = "https://testnet.nearblocks.io/txns/";

// `--identity <name>` may appear anywhere; everything else is positional.
const argv = process.argv.slice(2);
let IDENTITY = process.env.GUARD_IDENTITY;
const positional = [];
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--identity") IDENTITY = argv[++i];
  else positional.push(argv[i]);
}

function die(msg) {
  console.error(`\n✗ ${msg}`);
  process.exit(1);
}

// ---- ICP side --------------------------------------------------------------

function icpCall(method, arg = "()") {
  const args = ["canister", "call", CANISTER, method, arg];
  if (process.env.ICP_ENV) args.push("-e", process.env.ICP_ENV);
  if (IDENTITY) args.push("--identity", IDENTITY);
  let out;
  try {
    out = execFileSync("icp", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    die(`icp ${args.join(" ")}\n${e.stderr || e.message}`);
  }
  const err = out.match(/Err\s*=\s*"([^"]*)"/);
  if (err) die(`the guard refused ${method}: ${err[1]}`);
  if (/\bErr\b/.test(out)) die(`canister ${method} returned an error:\n${out}`);
  return out;
}

// Reads `name = "value"` from candid text output. All our fields are text.
function field(out, name) {
  const m = out.match(new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`));
  if (!m) die(`field "${name}" not found in icp output:\n${out}`);
  return m[1];
}

// `variant { Ok = "..." }` → the string
function okText(out) {
  const m = out.match(/Ok\s*=\s*"([^"]*)"/);
  if (!m) die(`unexpected icp output:\n${out}`);
  return m[1];
}

function account() {
  const out = icpCall("account");
  return {
    accountId: field(out, "account_id"),
    publicKey: field(out, "public_key_near"),
  };
}

// ---- NEAR side -------------------------------------------------------------

async function rpc(method, params) {
  const res = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "spike", method, params }),
  });
  const body = await res.json();
  if (body.error) die(`NEAR RPC ${method}: ${JSON.stringify(body.error, null, 2)}`);
  return body.result;
}

// One `query` call. Returns the parsed JSON-RPC body; anything that is not a
// JSON-RPC answer (network failure, HTTP error page, rate limit) is a hard error.
async function query(params) {
  let res;
  let text;
  try {
    res = await fetch(RPC, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: "spike", method: "query", params }),
    });
    text = await res.text();
  } catch (e) {
    die(`NEAR RPC ${RPC} unreachable: ${e.cause?.message ?? e.message}`);
  }
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    die(`NEAR RPC ${RPC} returned no JSON (HTTP ${res.status}):\n${text.slice(0, 500)}`);
  }
  return body;
}

// Only these mean "does not exist yet". Every other error is a real error.
const missing = (body, ...names) => names.includes(body.error?.cause?.name);

async function accessKey(accountId, publicKey) {
  const body = await query({
    request_type: "view_access_key",
    finality: "final",
    account_id: accountId,
    public_key: publicKey,
  });
  if (missing(body, "UNKNOWN_ACCOUNT", "UNKNOWN_ACCESS_KEY")) {
    die(
      `account ${accountId} has no access key yet (${body.error.cause.name}).\n` +
        `  Fund it first — a transfer to an implicit account creates it.\n` +
        `  Run: node spike.mjs account`,
    );
  }
  if (body.error || body.result?.error) {
    die(`view_access_key: ${JSON.stringify(body.error ?? body.result.error)}`);
  }
  return body.result; // { nonce, block_hash, permission, ... }
}

// ---- commands --------------------------------------------------------------

async function cmdAccount() {
  const { accountId, publicKey } = account();
  console.log(`NEAR account (implicit): ${accountId}`);
  console.log(`public key:              ${publicKey}`);
  const body = await query({ request_type: "view_account", finality: "final", account_id: accountId });
  if (body.result?.amount) {
    console.log(`balance:                 ${body.result.amount} yoctoNEAR`);
  } else if (missing(body, "UNKNOWN_ACCOUNT")) {
    console.log(`\nNot on testnet yet. Send it some testnet NEAR from any testnet wallet,`);
    console.log(`e.g. with near-cli:  near tokens <your-account> send-near ${accountId} '1 NEAR' network-config testnet`);
  } else {
    die(`view_account failed (not a funding problem): ${JSON.stringify(body.error ?? body.result)}`);
  }
}

function cmdConfig() {
  process.stdout.write(icpCall("get_config"));
}

async function cmdSend(receiver, amount) {
  if (!receiver || !amount) die("usage: node spike.mjs send --identity <agent> <receiver> <amountNEAR>");
  if (!IDENTITY) die("send runs as the agent: name it with --identity <agent> or GUARD_IDENTITY");
  // Same rule the canister enforces; checked here too because the receiver is
  // pasted into candid text, and a stray quote must not reshape the request.
  if (!/^(?=.{2,64}$)[a-z0-9]+([-_.][a-z0-9]+)*$/.test(receiver)) die(`not a NEAR account id: ${receiver}`);
  const yocto = parseNearAmount(amount);
  if (!yocto) die(`not a NEAR amount: ${amount}`);

  const { accountId, publicKey } = account();
  const key = await accessKey(accountId, publicKey);
  const nonce = BigInt(key.nonce) + 1n;
  const blockHash = key.block_hash; // base58

  const req =
    `(record { receiver_id = "${receiver}"; yocto = "${yocto}"; ` +
    `nonce = ${nonce} : nat64; block_hash = "${blockHash}" })`;

  // 1. Byte check: canister vs. NEAR's own library, before anything is signed.
  const reference = Buffer.from(
    encodeTransaction(
      createTransaction(
        accountId,
        PublicKey.fromString(publicKey),
        receiver,
        nonce,
        [actionCreators.transfer(BigInt(yocto))],
        bs58.decode(blockHash),
      ),
    ),
  ).toString("hex");
  const fromCanister = okText(icpCall("preview_transfer", req));
  if (fromCanister !== reference) {
    die(`canister bytes differ from @near-js/transactions — not signing.\n canister:  ${fromCanister}\n near-js:   ${reference}`);
  }
  console.log("✓ canister builds the same bytes as @near-js/transactions");

  // 2. Policy check, then threshold signature on ICP (the canister also
  //    verifies it before returning). A refusal stops here: nothing is sent.
  const signed = icpCall("sign_transfer", req);
  const txB64 = field(signed, "signed_tx_base64");
  const txHash = field(signed, "tx_hash");
  console.log(`✓ signed by the subnet, tx ${txHash}`);

  // 3. Submit to NEAR.
  const result = await rpc("send_tx", { signed_tx_base64: txB64, wait_until: "FINAL" });
  const status = result.status ?? result.final_execution_status;
  if (status?.Failure) die(`NEAR rejected it: ${JSON.stringify(status.Failure, null, 2)}`);
  console.log(`✓ on NEAR testnet: ${EXPLORER}${txHash}`);
}

const [cmd, ...rest] = positional;
if (cmd === "account") await cmdAccount();
else if (cmd === "config") cmdConfig();
else if (cmd === "send") await cmdSend(...rest);
else die("usage: node spike.mjs account | config | send --identity <agent> <receiver> <amountNEAR>");
