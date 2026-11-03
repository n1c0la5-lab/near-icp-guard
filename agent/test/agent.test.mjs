// Agent tests without any network: NEAR AI Cloud, the `icp` CLI and NEAR RPC
// are replaced by stand-ins. The guard client (`scripts/guard.mjs`) and the
// signed-transaction check (`scripts/verify-signed.mjs`) are the real code.
//
//   cd agent && npm test        (needs `npm ci --ignore-scripts` in scripts/)

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createGuard } from "../../scripts/guard.mjs";
import { referenceBytes } from "../../scripts/verify-signed.mjs";
import { parsePaymentArgs, runAgent } from "../agent.mjs";
import { createLog } from "../log.mjs";

// ---- helpers ------------------------------------------------------------------

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58(bytes) {
  let n = BigInt("0x" + (Buffer.from(bytes).toString("hex") || "0"));
  let s = "";
  while (n > 0n) {
    s = B58[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    s = "1" + s;
  }
  return s;
}
const sha256 = (b) => createHash("sha256").update(b).digest();

const { publicKey: pub, privateKey: priv } = generateKeyPairSync("ed25519");
const PK = pub.export({ format: "der", type: "spki" }).subarray(-32);
const ACCOUNT = PK.toString("hex");
const PK_NEAR = "ed25519:" + b58(PK);
const BLOCK = b58(Buffer.alloc(32, 7));
const KEY_NONCE = 5;

/**
 * Stand-in for the `icp` CLI running the guard canister. `mode`:
 *   "sign"     sign what was asked (valid signature)
 *   "refuse"   policy refusal
 *   "tamper"   a valid signature over a different transaction (1 yocto more)
 */
function fakeCanister(mode = "sign") {
  const calls = [];
  const exec = (cmd, args) => {
    assert.equal(cmd, "icp");
    const [, , , method, arg] = args;
    calls.push({ method, arg, args });
    if (method === "account") {
      return `(variant { Ok = record { public_key_hex = "${ACCOUNT}"; public_key_near = "${PK_NEAR}"; account_id = "${ACCOUNT}" } })`;
    }
    const m = arg.match(/receiver_id = "([^"]*)"; yocto = "([^"]*)"; nonce = (\d+) : nat64; block_hash = "([^"]*)"/);
    const input = { accountId: ACCOUNT, publicKey: PK_NEAR, receiver: m[1], yocto: m[2], nonce: m[3], blockHash: m[4] };
    if (method === "preview_transfer") return `(variant { Ok = "${referenceBytes(input).toString("hex")}" })`;
    if (method === "sign_transfer") {
      if (mode === "refuse") return `(variant { Err = "rejected: receiver ${m[1]} is not on the allowlist" })`;
      const tx = referenceBytes(mode === "tamper" ? { ...input, yocto: (BigInt(m[2]) + 1n).toString() } : input);
      const hash = sha256(tx);
      const signed = Buffer.concat([tx, Buffer.from([0]), edSign(null, hash, priv)]);
      return `(variant { Ok = record { signed_tx_base64 = "${signed.toString("base64")}"; tx_hash = "${b58(hash)}" } })`;
    }
    throw new Error(`unexpected canister method ${method}`);
  };
  return { exec, calls, signCalls: () => calls.filter((c) => c.method === "sign_transfer") };
}

/** Stand-in for NEAR RPC. Records every `send_tx`. */
function fakeRpc() {
  const sent = [];
  const fetch = async (_url, init) => {
    const { method, params } = JSON.parse(init.body);
    let body;
    if (method === "query" && params.request_type === "view_access_key") {
      body = { result: { nonce: KEY_NONCE, block_hash: BLOCK, permission: "FullAccess" } };
    } else if (method === "query" && params.request_type === "view_account") {
      body = { result: { amount: "892885010000000000000000" } };
    } else if (method === "send_tx") {
      sent.push(params.signed_tx_base64);
      body = { result: { status: { SuccessValue: "" } } };
    } else throw new Error(`unexpected RPC ${method}`);
    return { status: 200, text: async () => JSON.stringify(body) };
  };
  return { fetch, sent };
}

/** Stand-in for NEAR AI Cloud: answers with `script`, one completion per call. */
function fakeCloud(script, { attestationFails = false, signatureFails = false, chatThrows } = {}) {
  const requests = [];
  let n = 0;
  return {
    requests,
    async verify() {
      if (attestationFails) throw new Error("gateway quote did not verify");
      return {
        gateway: { tcbStatus: "UpToDate", signer: { signingAddress: "0xgateway", signingAlgo: "ecdsa" }, deploymentProvenance: "not_checked" },
        models: [{ tcbStatus: "UpToDate", signer: { signingAddress: "abcd", signingAlgo: "ed25519" }, deploymentProvenance: "not_checked", gpuEvidence: "verified" }],
      };
    },
    async chat(body) {
      requests.push(structuredClone(body));
      if (chatThrows) throw new Error(chatThrows);
      const message = script[n++] ?? { role: "assistant", content: "done" };
      return { id: `chatcmpl-${n}`, model: body.model, choices: [{ message, finish_reason: message.tool_calls ? "tool_calls" : "stop" }], usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 } };
    },
    async verifyResponse(id) {
      if (signatureFails) throw new Error("signature does not match the attested signer");
      return { id, signatureKind: "provider_tee", signature: { signer: { signingAddress: "abcd" } } };
    },
  };
}

const pay = (args, id = "call-1") => ({
  role: "assistant",
  content: null,
  tool_calls: [{ id, type: "function", function: { name: "request_payment", arguments: typeof args === "string" ? args : JSON.stringify(args) } }],
});

function setup({ canisterMode = "sign", script, cloudOpts, secrets = [], dryRun = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "agent-test-"));
  const logPath = join(dir, "agent.jsonl");
  const out = [];
  const log = createLog({ path: logPath, secrets, stdout: (s) => out.push(s) });
  const canister = fakeCanister(canisterMode);
  const rpc = fakeRpc();
  const guard = createGuard({ identity: "agent-id", exec: canister.exec, fetch: rpc.fetch });
  const cloud = fakeCloud(script, cloudOpts);
  const run = (task = "pay the invoice") => runAgent({ task, cloud, guard, log, dryRun });
  const lines = () => (existsSync(logPath) ? readFileSync(logPath, "utf8").trim().split("\n").map((l) => JSON.parse(l)) : []);
  return { run, canister, rpc, cloud, logPath, out, lines };
}

// ---- tool call → canister call ---------------------------------------------------

test("request_payment becomes exactly one sign_transfer, then one send_tx", async () => {
  const t = setup({ script: [pay({ receiver: "bob.testnet", amount_near: "0.1" })] });
  const { payments } = await t.run();
  const signs = t.canister.signCalls();
  assert.equal(signs.length, 1);
  assert.match(signs[0].arg, /receiver_id = "bob\.testnet"; yocto = "100000000000000000000000"; nonce = 6 : nat64;/);
  assert.deepEqual(signs[0].args.slice(-2), ["--identity", "agent-id"]);
  assert.equal(t.rpc.sent.length, 1, "signed tx not sent exactly once");
  const call = t.lines().find((l) => l.event === "tool_call");
  assert.equal(call.canister.result, "signed");
  assert.equal(call.sent, true);
  assert.equal(call.tx_hash, payments[0].tx_hash);
  // The canister's answer goes back to the model.
  const toolMsg = t.cloud.requests[1].messages.find((m) => m.role === "tool");
  assert.deepEqual(JSON.parse(toolMsg.content), { ok: true, tx_hash: payments[0].tx_hash, sent: true });
});

test("the model is offered exactly the two tools", async () => {
  const t = setup({ script: [{ role: "assistant", content: "nothing to pay" }] });
  await t.run();
  assert.deepEqual(t.cloud.requests[0].tools.map((x) => x.function.name), ["get_balance", "request_payment"]);
  assert.equal(t.cloud.requests[0].model, "deepseek-ai/DeepSeek-V4.1-Flash-1017");
});

test("dry run signs and checks, but sends nothing", async () => {
  const t = setup({ script: [pay({ receiver: "bob.testnet", amount_near: "0.1" })], dryRun: true });
  await t.run();
  assert.equal(t.canister.signCalls().length, 1);
  assert.equal(t.rpc.sent.length, 0);
  const call = t.lines().find((l) => l.event === "tool_call");
  assert.deepEqual([call.canister.result, call.sent, call.dry_run], ["signed", false, true]);
});

test("get_balance reads the canister account's balance", async () => {
  const t = setup({ script: [{ role: "assistant", content: null, tool_calls: [{ id: "b", type: "function", function: { name: "get_balance", arguments: "{}" } }] }] });
  await t.run();
  const toolMsg = t.cloud.requests[1].messages.find((m) => m.role === "tool");
  assert.deepEqual(JSON.parse(toolMsg.content), { account_id: ACCOUNT, balance_near: "0.89288501" });
  assert.equal(t.canister.signCalls().length, 0);
});

// ---- the canister refuses ---------------------------------------------------------

test("a refusal by the canister: nothing sent, refusal logged and reported", async () => {
  const t = setup({ canisterMode: "refuse", script: [pay({ receiver: "attacker.testnet", amount_near: "0.1" })] });
  const { payments } = await t.run();
  assert.equal(t.canister.signCalls().length, 1);
  assert.equal(t.rpc.sent.length, 0);
  assert.equal(payments.length, 0);
  const call = t.lines().find((l) => l.event === "tool_call");
  assert.deepEqual(call.canister, { result: "refused", reason: "rejected: receiver attacker.testnet is not on the allowlist" });
  assert.equal(call.sent, false);
  const toolMsg = t.cloud.requests[1].messages.find((m) => m.role === "tool");
  assert.deepEqual(JSON.parse(toolMsg.content), { ok: false, refused: "rejected: receiver attacker.testnet is not on the allowlist" });
});

// ---- the signed transaction does not match (A9) -----------------------------------

test("a validly signed but different transaction is not sent", async () => {
  const t = setup({ canisterMode: "tamper", script: [pay({ receiver: "bob.testnet", amount_near: "0.1" })] });
  await t.run();
  assert.equal(t.canister.signCalls().length, 1);
  assert.equal(t.rpc.sent.length, 0, "tampered tx was sent");
  const call = t.lines().find((l) => l.event === "tool_call");
  assert.equal(call.canister.result, "check failed");
});

// ---- broken or unexpected tool arguments ------------------------------------------

const BAD_ARGS = [
  ["exponent", { receiver: "bob.testnet", amount_near: "1e3" }],
  ["small exponent", { receiver: "bob.testnet", amount_near: "1e-3" }],
  ["negative", { receiver: "bob.testnet", amount_near: "-0.1" }],
  ["plus sign", { receiver: "bob.testnet", amount_near: "+0.1" }],
  ["JSON number", { receiver: "bob.testnet", amount_near: 0.1 }],
  ["two points", { receiver: "bob.testnet", amount_near: "0.1.2" }],
  ["comma", { receiver: "bob.testnet", amount_near: "0,1" }],
  ["space", { receiver: "bob.testnet", amount_near: " 0.1" }],
  ["hex", { receiver: "bob.testnet", amount_near: "0x10" }],
  ["Infinity", { receiver: "bob.testnet", amount_near: "Infinity" }],
  ["empty", { receiver: "bob.testnet", amount_near: "" }],
  ["25 decimals", { receiver: "bob.testnet", amount_near: "0." + "1".repeat(25) }],
  ["leading zeros", { receiver: "bob.testnet", amount_near: "007" }],
  ["missing amount", { receiver: "bob.testnet" }],
  ["uppercase receiver", { receiver: "Bob.testnet", amount_near: "0.1" }],
  ["quote in receiver", { receiver: 'bob.testnet"; yocto = "9', amount_near: "0.1" }],
  ["receiver as number", { receiver: 42, amount_near: "0.1" }],
  ["extra field", { receiver: "bob.testnet", amount_near: "0.1", memo: "x" }],
  ["array", [["bob.testnet", "0.1"]]],
  ["not JSON", "{receiver: bob.testnet"],
];

for (const [label, args] of BAD_ARGS) {
  test(`bad tool arguments (${label}): the guard is not asked, nothing sent`, async () => {
    const t = setup({ script: [pay(args)] });
    await t.run();
    assert.equal(t.canister.calls.length, 0, "the canister was called");
    assert.equal(t.rpc.sent.length, 0);
    const call = t.lines().find((l) => l.event === "tool_call");
    assert.equal(call.canister, "not asked");
    assert.equal(call.sent, false);
  });
}

test("plain decimal amounts are accepted and converted exactly", () => {
  assert.equal(parsePaymentArgs('{"receiver":"bob.testnet","amount_near":"0.1"}').yocto, "100000000000000000000000");
  assert.equal(parsePaymentArgs({ receiver: "a1", amount_near: "2" }).yocto, "2000000000000000000000000");
  assert.equal(parsePaymentArgs({ receiver: "a1", amount_near: "0." + "0".repeat(23) + "1" }).yocto, "1");
});

// ---- verification gates -----------------------------------------------------------

test("attestation not verified: no chat, nothing asked", async () => {
  const t = setup({ script: [pay({ receiver: "bob.testnet", amount_near: "0.1" })], cloudOpts: { attestationFails: true } });
  await t.run();
  assert.equal(t.cloud.requests.length, 0);
  assert.equal(t.canister.calls.length, 0);
  const att = t.lines().find((l) => l.event === "attestation");
  assert.equal(att.attestation.status, "not verified");
});

test("response signature not verified: its tool call is not executed", async () => {
  const t = setup({ script: [pay({ receiver: "bob.testnet", amount_near: "0.1" })], cloudOpts: { signatureFails: true } });
  await t.run();
  assert.equal(t.canister.calls.length, 0);
  assert.equal(t.rpc.sent.length, 0);
  const c = t.lines().find((l) => l.event === "completion");
  assert.equal(c.response_signature.status, "not verified");
});

test("the log records model, attestation, signature status and token usage", async () => {
  const t = setup({ script: [pay({ receiver: "bob.testnet", amount_near: "0.1" })] });
  await t.run();
  const [att, c] = [t.lines().find((l) => l.event === "attestation"), t.lines().find((l) => l.event === "completion")];
  assert.equal(att.attestation.status, "verified");
  assert.equal(att.attestation.models[0].deployment_provenance, "not verified");
  assert.equal(c.model, "deepseek-ai/DeepSeek-V4.1-Flash-1017");
  assert.deepEqual(c.response_signature, { status: "verified", kind: "provider_tee", signer: "abcd" });
  assert.equal(c.usage.total_tokens, 15);
  assert.ok(t.lines().every((l) => typeof l.ts === "string"));
});

// ---- the API key never appears ----------------------------------------------------

test("the API key appears in no log line and no printed line", async () => {
  const KEY = "sk-" + "f00dfeed".repeat(4);
  const OTHER = "sk-0123456789abcdefXYZ"; // shaped like a key, not ours
  // Upstream errors that echo the key back, and a task that contains it.
  const t = setup({ secrets: [KEY], script: [], cloudOpts: { chatThrows: `401 invalid key ${KEY} (also ${OTHER})` } });
  await t.run(`pay with ${KEY}`);
  const t2 = setup({ secrets: [KEY], script: [], cloudOpts: { attestationFails: true } });
  await t2.run();
  const all = readFileSync(t.logPath, "utf8") + t.out.join("") + readFileSync(t2.logPath, "utf8") + t2.out.join("");
  assert.ok(all.includes("[redacted]"), "nothing was redacted: the test did not see the key");
  assert.ok(!all.includes(KEY), "API key leaked");
  assert.ok(!all.includes(KEY.slice(3)), "API key body leaked");
  assert.ok(!all.includes(OTHER), "key-shaped string leaked");
});
