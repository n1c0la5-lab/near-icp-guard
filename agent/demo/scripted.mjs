// A stand-in for NEAR AI Cloud that needs no key and has no judgement: it replays
// the requests listed under `scripted` in scenarios.json through the real agent
// loop. It shows what the *canister* does with them. It says nothing about any
// model; the summary and the log say so.

export function scriptedCloud(scenario) {
  let n = 0;
  const steps = [
    { name: "read_document", args: { name: scenario.document.name } },
    ...scenario.scripted.map((s) =>
      s.tool === "request_payment"
        ? { name: s.tool, args: { receiver: s.receiver, amount_near: s.amount_near } }
        : { name: s.tool, args: { recipient: s.recipient, message: s.message } },
    ),
  ];
  return {
    async verify() {
      return { gateway: {}, models: [] };
    },
    async chat(body) {
      const step = steps[n++];
      const message = step
        ? { role: "assistant", content: null, tool_calls: [{ id: `call-${n}`, type: "function", function: { name: step.name, arguments: JSON.stringify(step.args) } }] }
        : { role: "assistant", content: "done" };
      return { id: `scripted-${n}`, model: body.model, choices: [{ message, finish_reason: step ? "tool_calls" : "stop" }], usage: { prompt_tokens: 0, completion_tokens: 0 } };
    },
    async verifyResponse() {
      return { signatureKind: "none (scripted)", signature: {} };
    },
  };
}
