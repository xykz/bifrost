// Unit tests for provider attribution. Run directly: `node provider-attribution.test.mjs`.
// No test framework needed (the tests/e2e/api dir has no test runner configured), same shape as
// chained-vars.test.mjs next door.
import assert from "node:assert";
import { makeMatchProvider, providerOfItem, providerOfLogLine } from "./provider-attribution.mjs";

let passed = 0;
function test(name, fn) {
  fn();
  passed++;
  console.log(`  ok - ${name}`);
}

// The providers a sequential run tracks.
const match = makeMatchProvider((p) => ["openai", "anthropic", "bedrock", "gemini", "vertex", "azure", "huggingface"].includes(p));

// A direct Vertex row, exactly as provider-harness.json carries it: the model
// is a collection variable, and 46 rows look like this.
const vertexRow = {
  name: "vertex/gemini-2.5-pro",
  request: { url: { raw: "{{baseUrl}}/genai/v1beta/models/{{vertexModel}}:generateContent" } },
};
const VERTEX_FOLDER = "7. Vertex (via /genai)";

// What newman prints for that same row once the variables are substituted. The
// literal "vertex" the raw URL matched on is simply gone from this string.
const vertexLogLine = "post http://localhost:8080/genai/v1beta/models/gemini-2.5-pro:generatecontent [200 ok, 1.2kb, 340ms]";

// The bug this file exists for: totals counted under one provider, results
// recorded under another, so vertex can never reach its own total and gemini
// reports passes for requests it never made.
test("a vertex row is attributed the same before and after variable substitution", () => {
  const denominator = providerOfItem(vertexRow, [VERTEX_FOLDER], match);
  const numerator = providerOfLogLine(vertexLogLine, VERTEX_FOLDER, match);
  assert.strictEqual(denominator, "vertex", "denominator should own the row");
  assert.strictEqual(numerator, denominator, "numerator and denominator disagree, so the row is double-booked");
});

// Gemini's own rows travel the same /genai path, so the fix must not simply
// hand every /genai row to vertex.
test("a genuine gemini row is still gemini", () => {
  const geminiRow = {
    name: "gemini/gemini-2.5-flash",
    request: { url: { raw: "{{baseUrl}}/genai/v1beta/models/gemini-2.5-flash:generateContent" } },
  };
  const folder = "10. Feature Variations (per-provider) / Gemini";
  const denominator = providerOfItem(geminiRow, ["Gemini", "GenAI Features"], match);
  const numerator = providerOfLogLine(
    "post http://localhost:8080/genai/v1beta/models/gemini-2.5-flash:generatecontent [200 ok, 1.2kb, 12ms]",
    "GenAI Features",
    match
  );
  assert.strictEqual(denominator, "gemini");
  assert.strictEqual(numerator, "gemini");
  assert.ok(folder);
});

// A row under a heading that names no provider has to keep working off its own
// text, or every cross-cut folder loses attribution entirely.
test("an unattributable folder falls back to the row's own signals", () => {
  const row = {
    name: "openai/gpt-4o-mini",
    request: { url: { raw: "{{baseUrl}}/openai/v1/chat/completions" } },
  };
  const folder = "8.1 Text Chat (non-streaming)";
  assert.strictEqual(providerOfItem(row, [folder], match), "openai");
  assert.strictEqual(
    providerOfLogLine("post http://localhost:8080/openai/v1/chat/completions [200 ok, 1kb, 9ms]", folder, match),
    "openai"
  );
});

test("a Hugging Face folder is attributed to its harness partition", () => {
  const folder = "61. Hugging Face Baseten model discovery (#6631)";
  const row = {
    name: "Hugging Face Baseten models appear in /v1/models - #6631",
    request: { url: { raw: "{{baseUrl}}/v1/models?provider=huggingface" } },
  };
  assert.strictEqual(providerOfItem(row, [folder], match), "huggingface");
  assert.strictEqual(providerOfLogLine("get http://localhost:8080/v1/models?provider=huggingface [200 ok]", folder, match), "huggingface");
});

// Ordering still has to keep the more specific provider ahead of the broader
// one when both keywords are present in a single heading.
test("a Vertex heading that also mentions Gemini stays with vertex", () => {
  assert.strictEqual(
    providerOfLogLine("post http://x/y [200 ok, 1kb, 9ms]", "Vertex Backlog Round 2 (Gemini-on-Vertex variants)", match),
    "vertex"
  );
});

// codebuddy-cn is the smoke row's fork, and it is hyphenated, so the partition
// name itself is the only signal: the row routes through the shared
// /v1/chat/completions and nothing else on the line names the provider. Without
// an entry here the row attributed to null, its port stayed at 0 total, and
// finalizeStatuses reported the fork as "skipped" - a green table that tested
// nothing.
test("a codebuddy-cn row attributes and counts on both sides", () => {
  const cnMatch = makeMatchProvider((p) => ["openai", "deepseek", "codebuddy-cn"].includes(p));
  const folder = "8.2.A Native /v1/chat/completions streaming × all providers";
  const row = {
    name: "codebuddy-cn/hunyuan-chat",
    request: {
      url: { raw: "{{baseUrl}}/v1/chat/completions" },
      body: { raw: '{"model":"codebuddy-cn/hunyuan-chat","stream":true}' },
    },
  };
  assert.strictEqual(providerOfItem(row, [folder], cnMatch), "codebuddy-cn");
  // The URL line alone names no provider — it is the shared /v1/chat/completions — so the monitor's
  // fallback to the "↳ codebuddy-cn/hunyuan-chat" name is what attributes it. Both halves are
  // asserted, because attributing the URL by accident would be a different (fragile) signal.
  assert.strictEqual(
    providerOfLogLine("POST http://localhost:8080/v1/chat/completions [200 OK, 1.1kB, 910ms]", folder, cnMatch),
    null
  );
  assert.strictEqual(providerOfLogLine("codebuddy-cn/hunyuan-chat", folder, cnMatch), "codebuddy-cn");
});

// The hyphen is load-bearing: "codebuddy-cn" must not be claimed by a bare
// "codebuddy" keyword somebody might add later, and the underscore spelling is a
// config identifier, not a row name, so both spellings are listed explicitly.
test("a codebuddy-cn directory-style label is still codebuddy-cn", () => {
  const cnMatch = makeMatchProvider((p) => ["codebuddy-cn"].includes(p));
  assert.strictEqual(providerOfLogLine("POST http://x/y [200 ok, 1kb, 9ms]", "CodeBuddy CN (codebuddy-cn)", cnMatch), "codebuddy-cn");
  assert.strictEqual(providerOfLogLine("POST http://x/y [200 ok, 1kb, 9ms]", "CodeBuddy CN (codebuddy_cn)", cnMatch), "codebuddy-cn");
  assert.strictEqual(providerOfLogLine("POST http://x/y [200 ok, 1kb, 9ms]", "CodeBuddy", cnMatch), null);
});

console.log(`\n${passed} passed`);
