// Runs the payment agent on one task.
//
//   node main.mjs --identity <agent> --task "Pay 0.1 NEAR to bob.testnet"
//   node main.mjs --identity <agent> --task-file invoice.txt [--dry-run] [--log <file>]
//
// --identity  the icp identity the owner set as agent (or GUARD_IDENTITY)
// --dry-run   sign and check payments, never send them to NEAR
// --log       JSONL log file (default: logs/agent.jsonl next to this script)
// --model     NEAR AI Cloud model (default: deepseek-ai/DeepSeek-V4.1-Flash-1017)
//
// API key: NEARAI_API_KEY, else ~/.config/near-icp-guard/nearai.key. It is never
// printed or logged. Env: GUARD_CANISTER, ICP_ENV, NEAR_RPC as for spike.mjs.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createGuard } from "../scripts/guard.mjs";
import { MODEL, runAgent } from "./agent.mjs";
import { createCloud } from "./cloud.mjs";
import { createLog } from "./log.mjs";

const KEY_FILE = join(homedir(), ".config", "near-icp-guard", "nearai.key");

function usage(msg) {
  console.error(`✗ ${msg}\nusage: node main.mjs --identity <agent> (--task "<text>" | --task-file <path>) [--dry-run] [--log <file>] [--model <id>]`);
  process.exit(2);
}

const opts = { identity: process.env.GUARD_IDENTITY, dryRun: false, model: MODEL, log: fileURLToPath(new URL("./logs/agent.jsonl", import.meta.url)) };
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  const next = () => (i + 1 < argv.length ? argv[++i] : usage(`${a} needs a value`));
  if (a === "--identity") opts.identity = next();
  else if (a === "--task") opts.task = next();
  else if (a === "--task-file") opts.task = readFileSync(next(), "utf8");
  else if (a === "--dry-run") opts.dryRun = true;
  else if (a === "--log") opts.log = next();
  else if (a === "--model") opts.model = next();
  else usage(`unknown argument ${a}`);
}
if (!opts.identity) usage("name the agent identity with --identity or GUARD_IDENTITY");
if (!opts.task?.trim()) usage("give a task with --task or --task-file");

let apiKey = process.env.NEARAI_API_KEY?.trim();
if (!apiKey) {
  try {
    apiKey = readFileSync(KEY_FILE, "utf8").trim();
  } catch {
    usage(`no API key: set NEARAI_API_KEY or put it in ${KEY_FILE}`);
  }
}

const log = createLog({ path: opts.log, secrets: [apiKey] });
const guard = createGuard({
  identity: opts.identity,
  canister: process.env.GUARD_CANISTER ?? "guard",
  environment: process.env.ICP_ENV,
  rpcUrl: process.env.NEAR_RPC ?? "https://rpc.testnet.near.org",
});

log.write({ event: "start", model: opts.model, identity: opts.identity, dry_run: opts.dryRun, task: opts.task });
log.print(`task: ${opts.task.trim()}${opts.dryRun ? "  [dry run: nothing is sent]" : ""}`);
try {
  const cloud = await createCloud({ apiKey });
  await runAgent({ task: opts.task, cloud, guard, log, model: opts.model, dryRun: opts.dryRun });
} catch (e) {
  log.write({ event: "crashed", error: String(e?.message ?? e).split("\n")[0] });
  log.print(`✗ ${e?.message ?? e}`);
  process.exitCode = 1;
}
log.print(`log: ${opts.log}`);
