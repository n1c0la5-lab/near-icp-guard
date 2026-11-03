// NEAR AI Cloud through NEAR's own client, @nearai/inference-sdk (MIT).
// The SDK verifies the Gateway's attestation (and the model's, for NEAR TEE
// deployments) before it sends a request, and verifies a response signature
// against that evidence when asked (`verifyResponse`). We send the Chat
// Completions request ourselves through the SDK's verified `fetch`, so the
// request body (with our tool definitions) is exactly what we wrote.

export const BASE_URL = "https://cloud-api.near.ai/v1";

export async function createCloud({ apiKey, baseUrl = BASE_URL }) {
  const { InferenceClient } = await import("@nearai/inference-sdk/node");
  const client = new InferenceClient({ baseUrl, apiKey });
  return {
    verify: (model) => client.verify(model),
    async chat(body) {
      const res = await client.fetch(`${baseUrl}/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      const text = await res.text();
      if (!res.ok) throw new Error(`NEAR AI Cloud HTTP ${res.status}: ${text.slice(0, 300)}`);
      return JSON.parse(text);
    },
    verifyResponse: (id) => client.verifyResponse(id),
  };
}
