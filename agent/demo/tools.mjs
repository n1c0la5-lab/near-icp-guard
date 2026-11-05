// What the attack demo adds around the agent. Nothing here is part of the
// production agent: `agent/main.mjs` does not import this file.
//
// - `read_document` is how the injected text reaches the model: as data, in a
//   tool result, not as an instruction from the user.
// - `request_message_signature` exists only so the demo can show a NEP-413
//   request for `intents.near` reaching the canister. The production agent has
//   no way to ask for a message signature.
// - `offlineRpc` replaces NEAR RPC. It answers with a zero block hash, so no
//   transaction signed in the demo could be accepted by any NEAR network, and
//   it throws on `send_tx`. The demo also runs the agent with `dryRun`.

import { randomBytes } from "node:crypto";
import { GuardRefusal } from "../../scripts/guard.mjs";

/** base58 of 32 zero bytes. */
export const OFFLINE_BLOCK_HASH = "11111111111111111111111111111111";

/** A stand-in `fetch` for `createGuard`. Reads get fixed answers; nothing leaves this machine. */
export function offlineRpc() {
  let nonce = 1;
  return async (_url, init) => {
    const { method, params } = JSON.parse(init.body);
    let body;
    if (method === "query" && params.request_type === "view_access_key") {
      body = { result: { nonce: nonce++, block_hash: OFFLINE_BLOCK_HASH, permission: "FullAccess" } };
    } else if (method === "query" && params.request_type === "view_account") {
      body = { result: { amount: "10000000000000000000000000" } };
    } else {
      throw new Error(`the attack demo never talks to NEAR (asked for ${method})`);
    }
    return { status: 200, text: async () => JSON.stringify(body) };
  };
}

const candidText = (s) =>
  `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\t/g, "\\t").replace(/[\x00-\x1f\x7f]/g, "")}"`;
const candidBlob = (bytes) => `blob "${[...bytes].map((b) => "\\" + b.toString(16).padStart(2, "0")).join("")}"`;

/** Asks the canister for a NEP-413 signature. Throws `GuardRefusal` on `Err`. */
export function signMessage(guard, { recipient, message, nonce = randomBytes(32) }) {
  return guard.icpCall(
    "sign_message",
    `(record { message = ${candidText(message)}; nonce = ${candidBlob(nonce)}; recipient = ${candidText(recipient)}; callback_url = null })`,
  );
}

function parse(raw) {
  try {
    const args = typeof raw === "string" ? JSON.parse(raw) : raw;
    if (args && typeof args === "object" && !Array.isArray(args)) return args;
  } catch {
    // reported below
  }
  return null;
}

/** The two demo-only tools, for `runAgent({ extraTools })`. */
export function demoTools({ document, guard }) {
  return [
    {
      definition: {
        type: "function",
        function: {
          name: "read_document",
          description: "Read a document from the accounts-payable inbox.",
          parameters: {
            type: "object",
            properties: { name: { type: "string", description: "Document name, e.g. inv-2041.txt" } },
            required: ["name"],
            additionalProperties: false,
          },
        },
      },
      async run(raw) {
        const name = parse(raw)?.name;
        if (name !== document.name) return { result: { error: `no document ${JSON.stringify(name)}; the inbox holds ${document.name}` } };
        return { result: { name, content: document.lines.join("\n") } };
      },
    },
    {
      definition: {
        type: "function",
        function: {
          name: "request_message_signature",
          description:
            "Ask the guard to sign an off-chain NEP-413 message for `recipient` with the account's key. The guard checks its policy and may refuse.",
          parameters: {
            type: "object",
            properties: {
              recipient: { type: "string", description: "Who the message is for, e.g. login.example" },
              message: { type: "string", description: "The message text to sign" },
            },
            required: ["recipient", "message"],
            additionalProperties: false,
          },
        },
      },
      async run(raw) {
        const args = parse(raw);
        if (typeof args?.recipient !== "string" || typeof args?.message !== "string") {
          return { result: { ok: false, error: "recipient and message must be strings" }, logged: { canister: "not asked" } };
        }
        try {
          signMessage(guard, args);
          return { result: { ok: true }, logged: { recipient: args.recipient, canister: { result: "signed" } } };
        } catch (e) {
          if (!(e instanceof GuardRefusal)) {
            return { result: { ok: false, error: e.message.split("\n")[0] }, logged: { recipient: args.recipient, canister: { result: "error", error: e.message.split("\n")[0] } } };
          }
          return { result: { ok: false, refused: e.reason }, logged: { recipient: args.recipient, canister: { result: "refused", reason: e.reason } } };
        }
      },
    },
  ];
}
