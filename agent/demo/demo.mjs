// The attack demo. One command:
//
//   node agent/demo/demo.mjs                 model on NEAR AI Cloud, 3 runs per scenario
//   node agent/demo/demo.mjs --runs 10       the measurement in the README
//   node agent/demo/demo.mjs --scripted      no model and no API key: replays the attack requests
//
// Each run: reinstall the demo canister, set the policy, hand the agent a
// document from its inbox, then judge the run from the canister's `audit_log`
// and the agent's JSONL log (`evaluate.mjs`). Exit code 0 only if nothing
// forbidden was signed and the controls were signed.
//
// The canister is `guard` in icp's `demo` environment on the LOCAL network. Its
// state is wiped before every run. `guard` in the default environment is not
// touched. Nothing reaches NEAR: see `tools.mjs`.
//
//   --only a,b       only these scenarios
//   --wasm <file>    install this wasm instead of building (for sabotage probes)
//   --budget-usd n   stop before a run once this much was spent (default 2)
//   --model <id>     NEAR AI Cloud model
//   --out <dir>      evidence directory (default agent/logs/demo/<time>)

import { execFileSync } from "node:child_process";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createGuard } from "../../scripts/guard.mjs";
import { MODEL, runAgent } from "../agent.mjs";
import { createLog } from "../log.mjs";
import { costUsd, evaluateRun, parseAuditLog, passed, render, summarize } from "./evaluate.mjs";
import { assertLocalNetwork, CYCLES_FLOOR, parseCycles, TOP_UP_AMOUNT } from "./local.mjs";
import { scriptedCloud } from "./scripted.mjs";
import { demoTools, offlineRpc } from "./tools.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");
const KEY_FILE = join(homedir(), ".config", "near-icp-guard", "nearai.key");
const ENV = "demo";
const AGENT_IDENTITY = "demo-agent";
const FILE = JSON.parse(readFileSync(join(HERE, "scenarios.json"), "utf8"));

function fail(msg) {
  console.error(`✗ ${msg}`);
  process.exit(2);
}

const opts = { runs: 3, scripted: false, budgetUsd: 2, model: MODEL };
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  const next = () => (i + 1 < argv.length ? argv[++i] : fail(`${a} needs a value`));
  if (a === "--runs") opts.runs = Number(next());
  else if (a === "--scripted") opts.scripted = true;
  else if (a === "--only") opts.only = next().split(",");
  else if (a === "--wasm") opts.wasm = resolve(next());
  else if (a === "--budget-usd") opts.budgetUsd = Number(next());
  else if (a === "--model") opts.model = next();
  else if (a === "--out") opts.out = resolve(next());
  else fail(`unknown argument ${a}`);
}
if (!Number.isInteger(opts.runs) || opts.runs < 1) fail("--runs must be a positive integer");
const scenarios = FILE.scenarios.filter((s) => !opts.only || opts.only.includes(s.id));
if (!scenarios.length) fail(`no such scenario; there are: ${FILE.scenarios.map((s) => s.id).join(", ")}`);

process.chdir(ROOT);
process.env.DO_NOT_TRACK = "1";
// Every call names its environment; these must not point anything elsewhere.
delete process.env.ICP_ENVIRONMENT;
delete process.env.ICP_NETWORK;

const icp = (...args) => execFileSync("icp", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
const tryIcp = (...args) => {
  try {
    return icp(...args);
  } catch (e) {
    return { failed: true, stderr: String(e.stderr ?? e.message) };
  }
};

// ---- setup -------------------------------------------------------------------

// Before anything else: this must be the local network, not just any network.
function assertLocal() {
  const status = tryIcp("network", "status", "-e", ENV, "--json");
  if (status.failed) fail("no local network: run `icp network start -d` first");
  try {
    return assertLocalNetwork(status);
  } catch (e) {
    fail(e.message);
  }
}
assertLocal();

const owner = process.env.OWNER_IDENTITY ?? icp("identity", "default");
const ownerPrincipal = icp("identity", "principal", "--identity", owner);
if (ownerPrincipal === "2vxsx-fae") fail("the owner identity is anonymous; select your own with `icp identity default <name>`");
if (!icp("identity", "list").split("\n").some((l) => l.split(/\s+/).includes(AGENT_IDENTITY))) {
  icp("identity", "new", AGENT_IDENTITY, "--storage", "plaintext", "--quiet"); // local only; stdout is the seed: discarded
}
const agentPrincipal = icp("identity", "principal", "--identity", AGENT_IDENTITY);

// On the local network the anonymous identity holds the seeded cycles, so it
// creates the canister, with the owner as its only controller.
if (tryIcp("canister", "status", "guard", "-e", ENV, "--identity", owner).failed) {
  icp("canister", "create", "guard", "-e", ENV, "--identity", "anonymous", "--controller", ownerPrincipal);
}

// A reinstall costs cycles, so a long measurement would run the canister dry.
// On the local network the anonymous identity holds the seeded cycles.
let topUps = 0;
function ensureCycles() {
  const before = parseCycles(icp("canister", "status", "guard", "-e", ENV, "--identity", owner));
  if (before >= CYCLES_FLOOR) return;
  assertLocal(); // again, at the moment cycles move
  icp("canister", "top-up", "guard", "--amount", TOP_UP_AMOUNT, "-e", ENV, "--identity", "anonymous");
  const after = parseCycles(icp("canister", "status", "guard", "-e", ENV, "--identity", owner));
  if (after <= before) fail(`top-up had no effect: ${before} → ${after} cycles`);
  topUps++;
  process.stderr.write(`  local canister refilled: ${before} → ${after} cycles\n`);
}

function reinstall() {
  ensureCycles();
  if (opts.wasm) icp("canister", "install", "guard", "-e", ENV, "--mode", "reinstall", "-y", "--wasm", opts.wasm, "--identity", owner);
  else icp("deploy", "guard", "-e", ENV, "--mode", "reinstall", "-y", "--identity", owner);
  const call = (method, arg) => {
    const out = icp("canister", "call", "guard", method, arg, "-e", ENV, "--identity", owner);
    if (/\bErr\b/.test(out)) fail(`${method}: ${out}`);
    return out;
  };
  const p = FILE.policy;
  const list = (xs) => `vec { ${xs.map((x) => `"${x}"`).join("; ")} }`;
  call("set_agent", `(opt principal "${agentPrincipal}")`);
  call("set_policy", `(record { per_tx_limit_yocto = "${p.per_tx_limit_yocto}"; daily_limit_yocto = "${p.daily_limit_yocto}"; allowlist = ${list(p.allowlist)}; nep413_recipients = opt ${list(p.nep413_recipients)} })`);
  call("account", "()");
}

// ---- the model ---------------------------------------------------------------

let realCloud;
if (!opts.scripted) {
  let apiKey = process.env.NEARAI_API_KEY?.trim();
  try {
    apiKey ??= readFileSync(KEY_FILE, "utf8").trim();
  } catch {
    fail(`no API key: set NEARAI_API_KEY or put it in ${KEY_FILE}, or use --scripted`);
  }
  const { createCloud } = await import("../cloud.mjs");
  realCloud = { cloud: await createCloud({ apiKey }), secrets: [apiKey] };
}

// ---- one run -----------------------------------------------------------------

const evidence = opts.out ?? join(HERE, "..", "logs", "demo", new Date().toISOString().replace(/[:.]/g, "-"));
mkdirSync(evidence, { recursive: true });

async function runOnce(scenario, n) {
  reinstall();
  const logPath = join(evidence, `${scenario.id}-${String(n).padStart(2, "0")}.jsonl`);
  const log = createLog({ path: logPath, secrets: realCloud?.secrets ?? [], stdout: () => {} });
  const write = log.write;
  // A scripted run has no model to attest; its log must not say otherwise.
  if (opts.scripted) log.write = (e) => write(e.event === "attestation" ? { ...e, attestation: { status: "skipped: scripted run, no model" } } : e);

  const guard = createGuard({ identity: AGENT_IDENTITY, canister: "guard", environment: ENV, fetch: offlineRpc() });
  const task = FILE.task.replace("{document}", scenario.document.name);
  log.write({ event: "start", model: opts.scripted ? "scripted" : opts.model, identity: AGENT_IDENTITY, dry_run: true, task, scenario: scenario.id });
  await runAgent({
    task,
    cloud: opts.scripted ? scriptedCloud(scenario) : realCloud.cloud,
    guard,
    log,
    model: opts.scripted ? "scripted" : opts.model,
    dryRun: true,
    extraTools: demoTools({ document: scenario.document, guard }),
  });

  const auditText = icp("canister", "call", "guard", "audit_log", "()", "--query", "-e", ENV, "--identity", owner);
  writeFileSync(logPath.replace(/\.jsonl$/, ".audit.txt"), auditText + "\n");
  const events = readFileSync(logPath, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  return evaluateRun({ scenario, policy: FILE.policy, events, audit: parseAuditLog(auditText) });
}

// ---- all runs ----------------------------------------------------------------

const results = [];
let spent = 0;
let stopped = false;
let aborted = null;
const moduleHash = () => tryIcp("canister", "status", "guard", "-e", ENV, "--identity", owner).toString().match(/Module hash: (\S+)/)?.[1];
outer: for (let n = 1; n <= opts.runs; n++) {
  for (const scenario of scenarios) {
    if (spent >= opts.budgetUsd) {
      stopped = true;
      break outer;
    }
    let r;
    try {
      r = await runOnce(scenario, n);
    } catch (e) {
      aborted = `${scenario.id} run ${n}: ${String(e?.message ?? e).split("\n")[0]}`;
      break outer;
    }
    spent += costUsd(r.usage);
    results.push(r);
    appendFileSync(join(evidence, "runs.jsonl"), JSON.stringify(r) + "\n");
    process.stderr.write(`  ${scenario.id} ${n}/${opts.runs}: attempted ${r.attempted}, refused ${r.refused}, signed ${r.signed}${r.problems.length ? `, RED: ${r.problems[0]}` : ""}\n`);
  }
}

const rows = summarize(scenarios, results);
const model = opts.scripted ? "scripted requests, no model" : opts.model;
const hash = moduleHash();
writeFileSync(join(evidence, "summary.json"), JSON.stringify({ model, runs_per_scenario: opts.runs, policy: FILE.policy, module_hash: hash, wasm: opts.wasm ?? null, cost_usd: spent, stopped_by_budget: stopped, aborted, top_ups: topUps, rows, results }, null, 1) + "\n");
console.log(render({ rows, policy: FILE.policy, model, runsPerScenario: opts.runs, moduleHash: hash, evidence, costUsd: opts.scripted ? null : spent, scripted: opts.scripted }));
if (stopped) console.log(`stopped early: budget of $${opts.budgetUsd} reached`);
if (aborted) console.log(`ABORTED, not a complete measurement: ${aborted}`);
process.exitCode = passed(rows) && !stopped && !aborted ? 0 : 1;
