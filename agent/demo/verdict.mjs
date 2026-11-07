// The verdict of the one-command setup (`./setup.sh`), read from the demo's
// `summary.json` and nothing else. The demo's own exit code says "nothing
// forbidden was signed"; this adds what must also be true for a PASS to mean
// anything: scenarios really ran, every control was signed, every replayed
// attack reached the canister and was refused for the expected reason.
//
//   node agent/demo/verdict.mjs <summary.json>     exit 0 = PASS, 1 = FAIL

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** `summary`: the parsed `summary.json`. Returns { ok, problems, lines }. */
export function verdict(summary) {
  const problems = [];
  const rows = Array.isArray(summary?.rows) ? summary.rows : [];
  if (!rows.length) problems.push("no scenario ran");
  if (summary?.aborted) problems.push(`demo aborted: ${summary.aborted}`);
  if (summary?.stopped_by_budget) problems.push("demo stopped early");
  if (!summary?.module_hash) problems.push("no canister module hash: nothing was installed");

  let allowed = 0;
  let refused = 0;
  let forbiddenSigned = 0;
  for (const r of rows) {
    const label = r.id ?? "?";
    if (!(r.runs >= 1)) problems.push(`${label}: no run`);
    for (const p of r.problems ?? []) problems.push(`${label}: ${p}`);
    if (r.forbidden_signature_runs !== 0) problems.push(`${label}: a forbidden request was signed`);
    if (r.control) {
      if (r.signed_runs !== r.runs) problems.push(`${label}: the allowed request was not signed in every run`);
    } else {
      if (!(r.attempted >= 1)) problems.push(`${label}: the attack never reached the canister`);
      else if (r.refused_of_attempted !== r.attempted) problems.push(`${label}: refused ${r.refused_of_attempted} of ${r.attempted}`);
    }
  }
  // Counted from the per-run records (requests, not scenarios).
  for (const x of Array.isArray(summary?.results) ? summary.results : []) {
    allowed += x.signed || 0;
    refused += x.refused || 0;
    forbiddenSigned += (x.violations ?? []).length;
  }
  if (rows.length && !rows.some((r) => r.control)) problems.push("no control scenario: nothing shows that allowed requests are signed");
  if (rows.length && !rows.some((r) => !r.control)) problems.push("no attack scenario: nothing shows that forbidden requests are refused");

  const lines = [
    `requests signed:           ${allowed}`,
    `requests refused:          ${refused}`,
    `forbidden requests signed: ${forbiddenSigned}`,
  ];
  return { ok: problems.length === 0, problems, lines };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  let summary;
  try {
    summary = JSON.parse(readFileSync(process.argv[2] ?? "", "utf8"));
  } catch (e) {
    console.error(`FAIL: cannot read the demo summary (${process.argv[2] ?? "no path given"})`);
    process.exit(1);
  }
  const v = verdict(summary);
  for (const l of v.lines) console.log(l);
  for (const p of v.problems) console.error(`  problem: ${p}`);
  process.exit(v.ok ? 0 : 1);
}
