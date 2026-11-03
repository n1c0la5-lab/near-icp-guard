// JSONL agent log. Every line goes through `redact` first, and so does
// everything the agent prints: the API key must never reach a log or stdout,
// even if an upstream error message echoes it back.

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

// NEAR AI Cloud keys start with `sk-`; anything shaped like one is masked too.
const KEY_SHAPE = /sk-[A-Za-z0-9_-]{8,}/g;

export function makeRedactor(secrets = []) {
  const exact = secrets.filter((s) => typeof s === "string" && s.length >= 8);
  return (text) => {
    let out = String(text);
    for (const s of exact) out = out.split(s).join("[redacted]");
    return out.replace(KEY_SHAPE, "[redacted]");
  };
}

/** `write(event)` appends one JSON line with a timestamp; `print(text)` writes to stdout. */
export function createLog({ path, secrets = [], stdout = (s) => process.stdout.write(s) } = {}) {
  const redact = makeRedactor(secrets);
  if (path) mkdirSync(dirname(path), { recursive: true });
  return {
    redact,
    write(event) {
      const line = redact(JSON.stringify({ ts: new Date().toISOString(), ...event }, (_, v) => (typeof v === "bigint" ? v.toString() : v)));
      if (path) appendFileSync(path, line + "\n");
      return line;
    },
    print(text) {
      stdout(redact(text) + "\n");
    },
  };
}
