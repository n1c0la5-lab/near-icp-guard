// Checks NEP-413 signatures from the guard on the LOCAL network with NEAR's own
// verifier, near-api-js `verifyMessage` (near-api-js/nep413). The canister
// signs as the agent; verification rebuilds the payload hash in near-api-js,
// not in our code. Then altered payloads and signatures must be refused.
//
//   node check-nep413.mjs --identity <agent> <recipient>
//
// `verifyMessage` also asks a NEAR RPC whether the key is a full-access key of
// the account. By default that lookup is answered by a stand-in that says
// "FullAccess", so only the signature is checked. With NEAR_RPC set (e.g.
// https://rpc.testnet.near.org) the lookup goes to that network instead, which
// only works once the canister's account exists there. Read-only either way.

import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { JsonRpcProvider } from "near-api-js";
import { verifyMessage } from "near-api-js/nep413";

const args = process.argv.slice(2);
const i = args.indexOf("--identity");
const identity = i >= 0 ? args.splice(i, 2)[1] : process.env.GUARD_IDENTITY;
const recipient = args[0];
if (!identity || !recipient) throw new Error("usage: node check-nep413.mjs --identity <agent> <recipient>");

function call(method, arg = "()") {
  const out = execFileSync("icp", ["canister", "call", "guard", method, arg, "--identity", identity], { encoding: "utf8" });
  if (/\bErr\b/.test(out)) throw new Error(`${method}: ${out}`);
  return out;
}
const field = (out, name) => out.match(new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`))[1];
// Candid text literal: escape everything outside printable ASCII.
const text = (s) =>
  '"' +
  [...s].map((c) => (c === '"' || c === "\\" || c < " " || c > "~" ? `\\u{${c.codePointAt(0).toString(16)}}` : c)).join("") +
  '"';
const blob = (b) => 'blob "' + [...b].map((x) => "\\" + x.toString(16).padStart(2, "0")).join("") + '"';

const acc = call("account");
const accountId = field(acc, "account_id");
const publicKey = field(acc, "public_key_near");

function sign(payload) {
  const out = call(
    "sign_message",
    `(record { message = ${text(payload.message)}; nonce = ${blob(payload.nonce)}; recipient = ${text(payload.recipient)}; ` +
      `callback_url = ${payload.callbackUrl === undefined ? "null" : `opt ${text(payload.callbackUrl)}`} })`,
  );
  return {
    accountId: field(out, "account_id"),
    publicKey: field(out, "public_key"),
    signature: Buffer.from(field(out, "signature"), "base64"),
  };
}

const provider = process.env.NEAR_RPC
  ? new JsonRpcProvider({ url: process.env.NEAR_RPC })
  : { viewAccessKey: async () => ({ permission: "FullAccess" }) };

let failed = 0;
async function expect(label, shouldPass, { payload, signature, signerPublicKey = publicKey }) {
  let error = null;
  try {
    await verifyMessage({ signerAccountId: accountId, signerPublicKey, payload, signature, provider });
  } catch (e) {
    error = e.message.split("\n")[0];
  }
  const ok = shouldPass ? error === null : error !== null;
  if (!ok) failed++;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}${error ? `  →  ${error}` : "  →  verified"}`);
}

const plain = { message: "near-icp-guard e2e: sign in", nonce: randomBytes(32), recipient, callbackUrl: undefined };
const withUrl = { message: '{"login":"e2e","n":2}', nonce: randomBytes(32), recipient, callbackUrl: "https://example.org/cb" };
const emptyUrl = { message: "empty callback", nonce: randomBytes(32), recipient, callbackUrl: "" };

const s1 = sign(plain);
const s2 = sign(withUrl);
const s3 = sign(emptyUrl);
let mismatch = 0;
for (const s of [s1, s2, s3]) if (s.accountId !== accountId || s.publicKey !== publicKey) mismatch++;
console.log(`  ${mismatch ? "FAIL" : "PASS"}  account_id and public_key in the answer are the canister's (${accountId.slice(0, 8)}…, ${publicKey.slice(0, 16)}…)`);
failed += mismatch ? 1 : 0;

await expect("signature without callbackUrl, NEAR verifier", true, { payload: plain, signature: s1.signature });
await expect("signature with callbackUrl, NEAR verifier", true, { payload: withUrl, signature: s2.signature });
await expect('signature with callbackUrl "", NEAR verifier', true, { payload: emptyUrl, signature: s3.signature });
await expect("message changed", false, { payload: { ...plain, message: plain.message + "!" }, signature: s1.signature });
await expect("recipient changed", false, { payload: { ...plain, recipient: recipient + "x" }, signature: s1.signature });
await expect("nonce changed", false, { payload: { ...plain, nonce: randomBytes(32) }, signature: s1.signature });
await expect("callbackUrl added", false, { payload: { ...plain, callbackUrl: "https://example.org/cb" }, signature: s1.signature });
await expect('callbackUrl "" read as none', false, { payload: { ...emptyUrl, callbackUrl: undefined }, signature: s3.signature });
const flipped = Buffer.from(s1.signature);
flipped[10] ^= 1;
await expect("one signature byte flipped", false, { payload: plain, signature: flipped });
console.log(`check-nep413 (${process.env.NEAR_RPC ? `access key looked up on ${process.env.NEAR_RPC}` : "access-key lookup stubbed"}): ${failed === 0 ? "all checks passed" : `${failed} failed`}`);
process.exit(failed === 0 ? 0 : 1);
