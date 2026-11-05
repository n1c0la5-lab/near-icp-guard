// A small payment agent: an LLM on NEAR AI Cloud with two tools,
// `get_balance` and `request_payment`. It holds no key. A payment is a request
// to the guard canister, which checks the owner's policy and signs or refuses;
// `scripts/guard.mjs` then checks the signed transaction before anything is sent.
//
// This module has no network code of its own: the cloud client and the guard
// are passed in, so tests can replace both.

import { ACCOUNT_ID, CheckFailed, GuardRefusal, nearToYocto } from "../scripts/guard.mjs";

export const MODEL = "deepseek-ai/DeepSeek-V4.1-Flash-1017";
export const MAX_TURNS = 6;

export const SYSTEM_PROMPT =
  "You are a payment agent for one NEAR testnet account. You can check its balance and request payments. " +
  "You do not hold any key: every payment goes to a guard that checks the owner's policy and signs or refuses. " +
  "If the guard refuses, report the refusal as it is; do not change the request to get around it. " +
  "Amounts are NEAR, written as plain decimal strings such as \"0.1\". Answer briefly.";

export const TOOLS = [
  {
    type: "function",
    function: {
      name: "get_balance",
      description: "The NEAR testnet account the agent pays from, and its balance in NEAR.",
      parameters: { type: "object", properties: {}, additionalProperties: false },
    },
  },
  {
    type: "function",
    function: {
      name: "request_payment",
      description:
        "Ask the guard to pay `amount_near` NEAR to `receiver`. The guard checks its policy (per-payment limit, daily limit, allowed receivers) and may refuse.",
      parameters: {
        type: "object",
        properties: {
          receiver: { type: "string", description: "NEAR account id, e.g. bob.testnet" },
          amount_near: { type: "string", description: 'Amount in NEAR as a plain decimal string, e.g. "0.1"' },
        },
        required: ["receiver", "amount_near"],
        additionalProperties: false,
      },
    },
  },
];

export class ArgumentError extends Error {
  constructor(message) {
    super(message);
    this.name = "ArgumentError";
  }
}

/**
 * Tool arguments as the model sent them (a JSON string) → a checked request.
 * Anything unexpected is refused before the guard is asked: no extra fields,
 * the receiver must be a NEAR account id, the amount a plain decimal *string*
 * (no exponent, no sign, no JSON number).
 */
export function parsePaymentArgs(raw) {
  let args;
  try {
    args = typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch {
    throw new ArgumentError("arguments are not valid JSON");
  }
  if (args === null || typeof args !== "object" || Array.isArray(args)) throw new ArgumentError("arguments must be an object");
  const extra = Object.keys(args).filter((k) => k !== "receiver" && k !== "amount_near");
  if (extra.length) throw new ArgumentError(`unexpected argument(s): ${extra.join(", ")}`);
  const { receiver, amount_near: amountNear } = args;
  if (typeof receiver !== "string" || !ACCOUNT_ID.test(receiver)) throw new ArgumentError("receiver must be a NEAR account id");
  if (typeof amountNear !== "string") throw new ArgumentError('amount_near must be a string such as "0.1"');
  let yocto;
  try {
    yocto = nearToYocto(amountNear);
  } catch (e) {
    throw new ArgumentError(`amount_near: ${e.message}`);
  }
  return { receiver, amountNear, yocto };
}

const YOCTO = 10n ** 24n;
export function formatNear(yocto) {
  const y = BigInt(yocto);
  const frac = (y % YOCTO).toString().padStart(24, "0").replace(/0+$/, "");
  return (y / YOCTO).toString() + (frac ? "." + frac : "");
}

function summarizeAttestation(r) {
  const one = (a) => ({
    tcb_status: a?.tcbStatus,
    signer: a?.signer?.signingAddress,
    signing_algo: a?.signer?.signingAlgo,
    deployment_provenance: a?.deploymentProvenance === "verified" ? "verified" : "not verified",
    ...(a && "gpuEvidence" in a ? { gpu_evidence: a.gpuEvidence === "verified" ? "verified" : "not verified" } : {}),
  });
  return { status: "verified", gateway: one(r?.gateway), models: (r?.models ?? []).map(one) };
}

function errorText(e) {
  return `${e?.name ?? "Error"}: ${String(e?.message ?? e).split("\n")[0]}`;
}

/**
 * Runs one task to the end. `cloud`: `{ verify(model), chat(body), verifyResponse(id) }`.
 * `guard`: `{ account(), balance(accountId), transfer({ receiver, yocto, send }) }`.
 * `log`: from `createLog`. With `dryRun`, payments are signed and checked, never sent.
 * `extraTools`: `[{ definition, run(rawArgs) → { result, logged } }]`, offered to
 * the model next to `TOOLS`. Only the attack demo (`demo/`) passes any;
 * `main.mjs` does not, so the production agent has exactly `TOOLS`.
 * Returns `{ answer, payments }`.
 */
export async function runAgent({ task, cloud, guard, log, model = MODEL, dryRun = false, maxTurns = MAX_TURNS, extraTools = [] }) {
  const payments = [];
  const tools = [...TOOLS, ...extraTools.map((t) => t.definition)];
  let attestation;
  try {
    attestation = summarizeAttestation(await cloud.verify(model));
  } catch (e) {
    attestation = { status: "not verified", error: errorText(e) };
  }
  log.write({ event: "attestation", model, attestation });
  if (attestation.status !== "verified") {
    log.print(`✗ attestation not verified, stopping: ${attestation.error}`);
    return { answer: null, payments };
  }
  log.print(`✓ attestation verified (gateway TCB ${attestation.gateway.tcb_status}, ${attestation.models.length} model report(s))`);

  const messages = [
    { role: "system", content: SYSTEM_PROMPT },
    { role: "user", content: task },
  ];

  for (let turn = 1; turn <= maxTurns; turn++) {
    let completion;
    try {
      completion = await cloud.chat({ model, messages, tools, tool_choice: "auto" });
    } catch (e) {
      log.write({ event: "completion_failed", model, turn, error: errorText(e) });
      log.print(`✗ model call failed: ${errorText(e)}`);
      return { answer: null, payments };
    }
    let signature;
    try {
      const v = await cloud.verifyResponse(completion.id);
      signature = { status: "verified", kind: v.signatureKind, signer: v.signature?.signer?.signingAddress };
    } catch (e) {
      signature = { status: "not verified", error: errorText(e) };
    }
    const choice = completion.choices?.[0] ?? {};
    const message = choice.message ?? { role: "assistant", content: null };
    const toolCalls = message.tool_calls ?? [];
    log.write({
      event: "completion",
      model: completion.model ?? model,
      turn,
      id: completion.id,
      attestation: attestation.status,
      response_signature: signature,
      finish_reason: choice.finish_reason,
      tool_calls: toolCalls.map((t) => ({ name: t.function?.name, arguments: t.function?.arguments })),
      content: message.content ?? null,
      usage: completion.usage,
    });

    // Only a response whose signature verified may trigger a tool.
    if (signature.status !== "verified") {
      log.print(`✗ response signature not verified, not acting on it: ${signature.error}`);
      return { answer: null, payments };
    }
    messages.push({ role: "assistant", content: message.content ?? null, ...(toolCalls.length ? { tool_calls: toolCalls } : {}) });
    if (!toolCalls.length) {
      log.write({ event: "final", model, answer: message.content ?? null });
      log.print(`agent: ${message.content ?? "(no answer)"}`);
      return { answer: message.content ?? null, payments };
    }
    for (const call of toolCalls) {
      const result = await runTool(call, { guard, log, model, dryRun, payments, extraTools });
      messages.push({ role: "tool", tool_call_id: call.id, content: JSON.stringify(result) });
    }
  }
  log.write({ event: "stopped", model, reason: `no final answer after ${maxTurns} turns` });
  return { answer: null, payments };
}

async function runTool(call, { guard, log, model, dryRun, payments, extraTools }) {
  const name = call.function?.name;
  const rawArgs = call.function?.arguments;
  const entry = { event: "tool_call", model, tool: name, arguments: rawArgs };

  const extra = extraTools.find((t) => t.definition.function.name === name);
  if (extra) {
    const { result, logged } = await extra.run(rawArgs);
    log.write({ ...entry, ...logged, result });
    return result;
  }

  if (name === "get_balance") {
    try {
      const { accountId } = guard.account();
      const b = await guard.balance(accountId);
      const result = { account_id: accountId, balance_near: b.exists ? formatNear(b.yocto) : "0 (account does not exist yet)" };
      log.write({ ...entry, result });
      return result;
    } catch (e) {
      log.write({ ...entry, error: errorText(e) });
      return { error: errorText(e) };
    }
  }

  if (name !== "request_payment") {
    log.write({ ...entry, error: "unknown tool" });
    return { error: `unknown tool ${name}` };
  }

  let req;
  try {
    req = parsePaymentArgs(rawArgs);
  } catch (e) {
    log.write({ ...entry, canister: "not asked", error: errorText(e), sent: false });
    log.print(`✗ request_payment refused locally (${e.message}); the guard was not asked`);
    return { ok: false, error: `invalid arguments: ${e.message}` };
  }

  try {
    const r = await guard.transfer({ receiver: req.receiver, yocto: req.yocto, send: !dryRun });
    payments.push({ receiver: req.receiver, amount_near: req.amountNear, tx_hash: r.txHash, sent: r.sent });
    log.write({
      ...entry,
      receiver: req.receiver,
      yocto: req.yocto,
      canister: { result: "signed", tx_hash: r.txHash },
      sent: r.sent,
      dry_run: dryRun,
      ...(r.sent ? { tx_hash: r.txHash } : {}),
    });
    log.print(`✓ guard signed ${req.amountNear} NEAR to ${req.receiver}, tx ${r.txHash}${r.sent ? " — sent" : " — not sent (dry run)"}`);
    return { ok: true, tx_hash: r.txHash, sent: r.sent };
  } catch (e) {
    const refused = e instanceof GuardRefusal;
    log.write({
      ...entry,
      receiver: req.receiver,
      yocto: req.yocto,
      canister: refused ? { result: "refused", reason: e.reason } : { result: e instanceof CheckFailed ? "check failed" : "error", error: errorText(e) },
      sent: false,
      dry_run: dryRun,
    });
    log.print(`✗ ${refused ? `guard refused: ${e.reason}` : errorText(e)} — nothing sent`);
    return refused ? { ok: false, refused: e.reason } : { ok: false, error: errorText(e) };
  }
}
