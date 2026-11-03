// The agent's side of the guard, as a library: ask the canister to sign a NEAR
// testnet transfer, check what comes back, and only then send it.
//
// Used by `spike.mjs` (command line) and by the agent (`agent/`). Canister
// calls go through the `icp` CLI, so they run as an icp identity and no key
// ever touches this code. Nothing is sent unless the canister signed and the
// signed transaction from its update response passed `verifySigned`.
//
// `exec` (for `icp`) and `fetch` (for NEAR RPC) can be replaced, so tests can
// run the real code path without a network.

import { execFileSync } from "node:child_process";
import { parseNearAmount } from "@near-js/utils";
import { referenceBytes, verifySigned } from "./verify-signed.mjs";

/** The canister answered `Err`: a policy refusal or another canister-side error. */
export class GuardRefusal extends Error {
  constructor(method, reason) {
    super(`the guard refused ${method}: ${reason}`);
    this.name = "GuardRefusal";
    this.method = method;
    this.reason = reason;
  }
}

/** A check on our side failed; nothing was sent. */
export class CheckFailed extends Error {
  constructor(message) {
    super(message);
    this.name = "CheckFailed";
  }
}

/** NEAR account ids, the same rule the canister enforces. */
export const ACCOUNT_ID = /^(?=.{2,64}$)[a-z0-9]+([-_.][a-z0-9]+)*$/;
/** Plain decimal NEAR amounts: digits, optionally a point and up to 24 decimals. */
export const NEAR_AMOUNT = /^(0|[1-9][0-9]{0,15})(\.[0-9]{1,24})?$/;

/** "0.1" → "100000000000000000000000". Throws on anything but a plain decimal. */
export function nearToYocto(amount) {
  if (typeof amount !== "string" || !NEAR_AMOUNT.test(amount)) {
    throw new CheckFailed(`not a plain decimal NEAR amount: ${JSON.stringify(amount)}`);
  }
  const yocto = parseNearAmount(amount);
  if (!yocto || !/^[0-9]+$/.test(yocto)) throw new CheckFailed(`cannot convert ${amount} NEAR`);
  return yocto;
}

export function createGuard({
  identity,
  canister = "guard",
  environment,
  rpcUrl = "https://rpc.testnet.near.org",
  exec = execFileSync,
  fetch = globalThis.fetch,
  onStep = () => {},
} = {}) {
  function icpCall(method, arg = "()") {
    const args = ["canister", "call", canister, method, arg];
    if (environment) args.push("-e", environment);
    if (identity) args.push("--identity", identity);
    let out;
    try {
      out = exec("icp", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    } catch (e) {
      throw new Error(`icp ${args.join(" ")}\n${e.stderr || e.message}`);
    }
    const err = out.match(/Err\s*=\s*"([^"]*)"/);
    if (err) throw new GuardRefusal(method, err[1]);
    if (/\bErr\b/.test(out)) throw new GuardRefusal(method, out.trim());
    return out;
  }

  // Reads `name = "value"` from candid text output. All our fields are text.
  function field(out, name) {
    const m = out.match(new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`));
    if (!m) throw new Error(`field "${name}" not found in icp output:\n${out}`);
    return m[1];
  }

  function okText(out) {
    const m = out.match(/Ok\s*=\s*"([^"]*)"/);
    if (!m) throw new Error(`unexpected icp output:\n${out}`);
    return m[1];
  }

  function account() {
    const out = icpCall("account");
    return { accountId: field(out, "account_id"), publicKey: field(out, "public_key_near") };
  }

  // One JSON-RPC call. Anything that is not a JSON-RPC answer (network
  // failure, HTTP error page, rate limit) is a hard error.
  async function rpcBody(method, params) {
    let res;
    let text;
    try {
      res = await fetch(rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: "guard", method, params }),
      });
      text = await res.text();
    } catch (e) {
      throw new Error(`NEAR RPC ${rpcUrl} unreachable: ${e.cause?.message ?? e.message}`);
    }
    try {
      return JSON.parse(text);
    } catch {
      throw new Error(`NEAR RPC ${rpcUrl} returned no JSON (HTTP ${res.status}):\n${text.slice(0, 500)}`);
    }
  }

  // Only these mean "does not exist yet". Every other error is a real error.
  const missing = (body, ...names) => names.includes(body.error?.cause?.name);

  /** `{ exists: false }` or `{ exists: true, yocto }`. */
  async function balance(accountId) {
    const body = await rpcBody("query", { request_type: "view_account", finality: "final", account_id: accountId });
    if (body.result?.amount) return { exists: true, yocto: body.result.amount };
    if (missing(body, "UNKNOWN_ACCOUNT")) return { exists: false };
    throw new Error(`view_account failed (not a funding problem): ${JSON.stringify(body.error ?? body.result)}`);
  }

  async function accessKey(accountId, publicKey) {
    const body = await rpcBody("query", {
      request_type: "view_access_key",
      finality: "final",
      account_id: accountId,
      public_key: publicKey,
    });
    if (missing(body, "UNKNOWN_ACCOUNT", "UNKNOWN_ACCESS_KEY")) {
      throw new Error(
        `account ${accountId} has no access key yet (${body.error.cause.name}). ` +
          `Fund it first: a transfer to an implicit account creates it.`,
      );
    }
    if (body.error || body.result?.error) throw new Error(`view_access_key: ${JSON.stringify(body.error ?? body.result.error)}`);
    return body.result; // { nonce, block_hash, permission, ... }
  }

  /**
   * Asks the canister to sign `yocto` to `receiver`, checks the signed bytes,
   * and sends them unless `send` is false. Returns
   * `{ txHash, signedTxBase64, sent }`. Throws `GuardRefusal` if the canister
   * refuses and `CheckFailed` if a check on our side fails; nothing is sent then.
   */
  async function transfer({ receiver, yocto, send = true }) {
    // Same rule the canister enforces; checked here too because the receiver is
    // pasted into candid text, and a stray quote must not reshape the request.
    if (typeof receiver !== "string" || !ACCOUNT_ID.test(receiver)) throw new CheckFailed(`not a NEAR account id: ${JSON.stringify(receiver)}`);
    if (typeof yocto !== "string" || !/^[0-9]+$/.test(yocto)) throw new CheckFailed(`not a yocto amount: ${JSON.stringify(yocto)}`);

    const { accountId, publicKey } = account();
    const key = await accessKey(accountId, publicKey);
    const nonce = BigInt(key.nonce) + 1n;
    const blockHash = key.block_hash; // base58
    const req =
      `(record { receiver_id = "${receiver}"; yocto = "${yocto}"; ` +
      `nonce = ${nonce} : nat64; block_hash = "${blockHash}" })`;

    // 1. Early byte check, before anything is signed. `preview_transfer` is a
    //    query (one replica), so this is only a hint; step 3 is the real check.
    const reference = referenceBytes({ accountId, publicKey, receiver, nonce, yocto, blockHash });
    const fromCanister = okText(icpCall("preview_transfer", req));
    if (fromCanister !== reference.toString("hex")) {
      throw new CheckFailed(
        `canister bytes differ from @near-js/transactions — not signing.\n canister:  ${fromCanister}\n near-js:   ${reference.toString("hex")}`,
      );
    }
    onStep("✓ preview (query) matches @near-js/transactions");

    // 2. Policy check, then threshold signature on ICP (the canister also
    //    verifies it before returning). A refusal throws here: nothing is sent.
    const signed = icpCall("sign_transfer", req);
    const signedTxBase64 = field(signed, "signed_tx_base64");
    const txHash = field(signed, "tx_hash");
    onStep(`✓ signed by the subnet, tx ${txHash}`);

    // 3. Check the signed bytes from the update response before they leave:
    //    unsigned part = near-js reference, signature valid for the canister key.
    try {
      verifySigned({ signedTxBase64, reference, publicKey, txHash });
    } catch (e) {
      throw new CheckFailed(`signed transaction failed the check — not sending.\n${e.message}`);
    }
    onStep("✓ signed tx (update response) matches @near-js/transactions, signature verifies");

    if (!send) return { txHash, signedTxBase64, sent: false };

    // 4. Submit to NEAR.
    const body = await rpcBody("send_tx", { signed_tx_base64: signedTxBase64, wait_until: "FINAL" });
    if (body.error) throw new Error(`NEAR RPC send_tx: ${JSON.stringify(body.error)}`);
    const status = body.result?.status ?? body.result?.final_execution_status;
    if (status?.Failure) throw new Error(`NEAR rejected it: ${JSON.stringify(status.Failure)}`);
    return { txHash, signedTxBase64, sent: true };
  }

  return { icpCall, account, balance, accessKey, transfer, config: () => icpCall("get_config") };
}
