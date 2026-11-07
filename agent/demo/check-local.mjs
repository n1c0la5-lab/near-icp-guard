// Exit 0 only if icp's `demo` environment is a managed network on this machine
// (same check as the demo itself: `local.mjs`). Used by `./setup.sh` before it
// touches a canister.
//
//   node agent/demo/check-local.mjs        exit 0 = local, exit 2 = refused

import { execFileSync } from "node:child_process";
import { assertLocalNetwork } from "./local.mjs";

try {
  const out = execFileSync("icp", ["network", "status", "-e", "demo", "--json"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  console.log(`local network: ${assertLocalNetwork(out)}`);
} catch (e) {
  console.error(String(e.message ?? e).split("\n")[0].replace(/^Command failed: .*$/, "cannot read `icp network status -e demo --json`"));
  process.exit(2);
}
