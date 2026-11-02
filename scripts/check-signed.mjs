// Self-test of verify-signed.mjs against the guard on the LOCAL network.
// Asks the canister (as the agent) to sign a 1-yocto transfer with a fake block
// hash, checks the real update response, then checks that tampered copies are
// refused — and a validly signed transaction for a different amount (same
// length), which only the byte comparison catches. Sends nothing to NEAR.
//
//   node check-signed.mjs --identity <agent> [receiver]

import { execFileSync } from "node:child_process";
import { referenceBytes, verifySigned } from "./verify-signed.mjs";

const args = process.argv.slice(2);
const i = args.indexOf("--identity");
const identity = i >= 0 ? args.splice(i, 2)[1] : process.env.GUARD_IDENTITY;
const receiver = args[0] ?? "alice.testnet";
if (!identity) throw new Error("usage: node check-signed.mjs --identity <agent> [receiver]");

function call(method, arg = "()") {
  const out = execFileSync("icp", ["canister", "call", "guard", method, arg, "--identity", identity], { encoding: "utf8" });
  if (/\bErr\b/.test(out)) throw new Error(`${method}: ${out}`);
  return out;
}
const field = (out, name) => out.match(new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`))[1];

const acc = call("account");
const input = {
  accountId: field(acc, "account_id"),
  publicKey: field(acc, "public_key_near"),
  receiver,
  nonce: 1n,
  yocto: 1n,
  blockHash: "11111111111111111111111111111111", // 32 zero bytes: no NEAR network accepts this tx
};
const signTo = (to, yocto) => {
  const out = call(
    "sign_transfer",
    `(record { receiver_id = "${to}"; yocto = "${yocto}"; nonce = 1 : nat64; block_hash = "${input.blockHash}" })`,
  );
  return { signedTxBase64: field(out, "signed_tx_base64"), txHash: field(out, "tx_hash") };
};
const real = signTo(receiver, 1);
const otherTx = signTo(receiver, 2); // valid signature, different transaction
const reference = referenceBytes(input);

let failed = 0;
function expect(label, shouldPass, tx) {
  let error = null;
  try {
    verifySigned({ ...tx, reference, publicKey: input.publicKey });
  } catch (e) {
    error = e.message.split("\n")[0];
  }
  const ok = shouldPass ? error === null : error !== null;
  if (!ok) failed++;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}${error ? `  →  ${error}` : "  →  accepted"}`);
}
function flip(b64, index) {
  const b = Buffer.from(b64, "base64");
  b[index] ^= 0x01;
  return b.toString("base64");
}

const len = Buffer.from(real.signedTxBase64, "base64").length;
expect("real update response", true, real);
expect("one byte flipped in the amount", false, { ...real, signedTxBase64: flip(real.signedTxBase64, len - 66) });
expect("one byte flipped in the receiver", false, { ...real, signedTxBase64: flip(real.signedTxBase64, 4 + 64 + 1 + 32 + 8 + 4) });
expect("one byte flipped in the signature", false, { ...real, signedTxBase64: flip(real.signedTxBase64, len - 1) });
expect("signature cut off", false, { ...real, signedTxBase64: Buffer.from(real.signedTxBase64, "base64").subarray(0, len - 1).toString("base64") });
expect("wrong tx_hash", false, { ...real, txHash: "1" + real.txHash.slice(1) });
expect("validly signed, but 2 yocto instead of 1", false, otherTx);
console.log(`check-signed: ${failed === 0 ? "all checks passed" : `${failed} failed`}`);
process.exit(failed === 0 ? 0 : 1);
