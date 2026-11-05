// What keeps the demo on the local network. The demo reinstalls its canister
// before every run and refills it with cycles, so it must never reach a real
// network, whatever `icp.yaml` or the environment say.

/** A reinstall costs cycles. Below this the next run could fail; 323 billion was too few. */
export const CYCLES_FLOOR = 1_000_000_000_000n;
export const TOP_UP_AMOUNT = "2t";

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * `statusJson`: output of `icp network status -e demo --json`. Throws unless it
 * describes a network this machine manages and listens on. Both must hold:
 * `managed` alone would accept a managed network bound elsewhere, and the host
 * alone would accept a tunnel to a connected network.
 */
export function assertLocalNetwork(statusJson) {
  let status;
  try {
    status = JSON.parse(statusJson);
  } catch {
    throw new Error("cannot read `icp network status`");
  }
  let host;
  try {
    host = new URL(status.api_url).hostname;
  } catch {
    throw new Error(`no usable api_url in \`icp network status\`: ${JSON.stringify(status.api_url)}`);
  }
  if (status.managed !== true) throw new Error(`refusing: ${status.api_url} is not a local managed network`);
  if (!LOCAL_HOSTS.has(host)) throw new Error(`refusing: ${status.api_url} is not on this machine`);
  return status.api_url;
}

/** The canister's balance from `icp canister status` text. */
export function parseCycles(statusText) {
  const m = statusText.match(/^\s*Cycles: ([\d_]+)\s*$/m);
  if (!m) throw new Error("no cycles balance in `icp canister status`");
  return BigInt(m[1].replace(/_/g, ""));
}
