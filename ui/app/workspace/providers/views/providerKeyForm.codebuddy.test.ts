import { describe, expect, it } from "vitest";

import { DefaultNetworkConfig } from "@/lib/constants/config";
import { ProviderFormSchema } from "@/lib/schemas/providerForm";
import { applyAuthMethod, providerKeyFormSchema } from "./providerKeyForm.utils";

// ProviderKeyForm resolves the key editor with this schema (through providerKeyFormSchema), so
// these cases are the ones that decide whether a bad codebuddy-cn key can reach the server at
// all. ProviderFormSchema is not imported by any production module: it belongs to the
// provider-creation form, and a rule that lives only there never runs on the save path.
const secret = (value: string) => ({ value, ref: "" });
const base = { id: "k1", name: "cb", models: ["*"], blacklisted_models: [], weight: 1 };
const refreshURL = "https://copilot.tencent.com/v2/plugin/auth/token/refresh";
const bundle = (overrides: Record<string, unknown> = {}) => ({
	grant_type: "browser_login" as const,
	token_url: secret(refreshURL),
	access_token: secret("access-abc"),
	refresh_token: secret("refresh-xyz"),
	expires_at: "2026-10-22T12:00:00Z",
	...overrides,
});

const parse = (provider: string, key: Record<string, unknown>) => providerKeyFormSchema(provider).safeParse({ key: { ...base, ...key } });
const issues = (result: ReturnType<typeof parse>) =>
	result.success ? [] : (result.error.issues.map((issue) => issue.path.join(".")) ?? []);

describe("providerKeyFormSchema codebuddy-cn credentials", () => {
	it("accepts an oauth-only key with an empty value", () => {
		const result = parse("codebuddy-cn", { value: secret(""), oauth_key_config: bundle() });
		expect(result.success, result.success ? "" : JSON.stringify(result.error.issues)).toBe(true);
	});

	it("accepts a pasted api key with no oauth config", () => {
		const result = parse("codebuddy-cn", { value: secret("sk-pasted"), oauth_key_config: { _auth_type: "api_key" } });
		expect(result.success, result.success ? "" : JSON.stringify(result.error.issues)).toBe(true);
	});

	// The server refuses both modes (provider_keys.go, "not both"): the OAuth login would be
	// persisted and silently unused because resolveKey prefers the pasted value.
	it("rejects a key with both auth modes, on the oauth path", () => {
		const result = parse("codebuddy-cn", { value: secret("sk-pasted"), oauth_key_config: bundle() });
		expect(result.success).toBe(false);
		expect(issues(result)).toContain("key.oauth_key_config");
	});

	// The server refuses a key with no credential at all; the form must say so on the field the
	// user can act on, not fail on submit with a 400.
	it("rejects a key with neither auth mode, on the value path", () => {
		const result = parse("codebuddy-cn", { value: secret(""), oauth_key_config: { _auth_type: "api_key" } });
		expect(result.success).toBe(false);
		expect(issues(result)).toContain("key.value");
	});

	// Only browser_login is accepted for this provider, so a bundle from another grant would be
	// persisted and then refused by the server.
	it("rejects a bundle using another grant", () => {
		const result = parse("codebuddy-cn", {
			value: secret(""),
			oauth_key_config: {
				grant_type: "client_credentials",
				token_url: secret("https://idp.example.com/token"),
				client_id: secret("id"),
				client_secret: secret("secret"),
			},
		});
		expect(result.success).toBe(false);
		expect(issues(result)).toContain("key.oauth_key_config.grant_type");
	});

	// The shared oauth schema's "has anyone started typing" heuristic lets a grant with no
	// credential through: requiring token_url and refresh_token explicitly is what catches it.
	it("rejects a grant-only bundle, on both missing fields", () => {
		const result = parse("codebuddy-cn", { value: secret(""), oauth_key_config: { grant_type: "browser_login" } });
		expect(result.success).toBe(false);
		expect(issues(result)).toEqual(expect.arrayContaining(["key.oauth_key_config.token_url", "key.oauth_key_config.refresh_token"]));
	});

	it("rejects a bundle with no refresh token", () => {
		const result = parse("codebuddy-cn", { value: secret(""), oauth_key_config: bundle({ refresh_token: secret("") }) });
		expect(result.success).toBe(false);
		expect(issues(result)).toContain("key.oauth_key_config.refresh_token");
	});

	it("rejects a padded expiry the server would refuse", () => {
		const result = parse("codebuddy-cn", { value: secret(""), oauth_key_config: bundle({ expires_at: " 2026-10-22T12:00:00Z " }) });
		expect(result.success).toBe(false);
		expect(issues(result)).toContain("key.oauth_key_config.expires_at");
	});

	// The key form seeds this placeholder for the API-key tab. It is inert: the save path drops
	// the block, so it must not count as a second auth mode.
	it("ignores the inert api_key placeholder when a value is pasted", () => {
		const result = parse("codebuddy-cn", { value: secret("sk-pasted"), oauth_key_config: { ...bundle(), _auth_type: "api_key" } });
		expect(result.success, result.success ? "" : JSON.stringify(result.error.issues)).toBe(true);
	});

	// A bundle the save path would drop must not pass as a credential: with the API-key
	// discriminator a complete block is stripped by applyAuthMethod, leaving no credential.
	it("rejects a discriminator that the save path would drop", () => {
		const result = parse("codebuddy-cn", { value: secret(""), oauth_key_config: { ...bundle(), _auth_type: "api_key" } });
		expect(result.success).toBe(false);
		expect(issues(result)).toContain("key.value");
	});

	// The key form registers oauth_key_config for every key, so an untouched block is normal on a
	// codebuddy key too and must not be mistaken for a half-filled credential.
	it("ignores an untouched block", () => {
		const withValue = parse("codebuddy-cn", { value: secret("sk-pasted"), oauth_key_config: {} });
		expect(withValue.success, withValue.success ? "" : JSON.stringify(withValue.error.issues)).toBe(true);
		const withoutValue = parse("codebuddy-cn", { value: secret(""), oauth_key_config: {} });
		expect(withoutValue.success).toBe(false);
		expect(issues(withoutValue)).toContain("key.value");
	});

	// The rule is conditional on the provider; a shared schema that rejected every OAuth bundle
	// carrying client credentials would break every openai key.
	it("leaves another provider's client credentials key alone", () => {
		const result = parse("openai", {
			value: secret(""),
			oauth_key_config: {
				_auth_type: "oauth",
				grant_type: "client_credentials",
				token_url: secret("https://idp.example.com/token"),
				client_id: secret("id"),
				client_secret: secret("secret"),
			},
		});
		expect(result.success, result.success ? "" : JSON.stringify(result.error.issues)).toBe(true);
	});
});

// Finding 1 was that the rule lived in a schema no production module imported, so the fix has to
// be pinned at the wiring, not only at the schema. The key editor resolves its form through
// providerKeyFormSchema(providerType); this asserts the component still does that. A DOM test
// would be better, but this UI has no jsdom/testing-library setup and adding one is out of scope,
// so the component's resolver line is the seam.
describe("ProviderKeyForm wiring", () => {
	it("resolves the live key form with the provider-aware schema, not the provider-agnostic one", async () => {
		const { readFile } = await import("node:fs/promises");
		const source = await readFile(new URL("./providerKeyForm.tsx", import.meta.url), "utf8");
		expect(source).toContain("providerKeyFormSchema");
		// The provider has to reach the schema: a bare modelProviderKeySchema resolver would
		// silently drop the codebuddy-cn rule again.
		expect(source).toMatch(/providerKeyFormSchema\(\s*providerType\s*\)/);
		expect(source).not.toMatch(/key:\s*modelProviderKeySchema\b/);
		// And the provider comes from the base provider when the key is a custom one.
		expect(source).toContain("provider.custom_provider_config?.base_provider_type || provider.name");
	});
});

// Finding 1's real risk is the two schemas drifting apart again. Both now call one helper, and
// this pins that they reach the same verdict on the same credential shapes.
describe("provider creation and the live key editor agree", () => {
	const value = (v: string) => secret(v);
	const cases: [string, string, Record<string, unknown>][] = [
		["neither", "", { _auth_type: "api_key" }],
		["both", "sk-pasted", bundle()],
		["pasted only", "sk-pasted", { _auth_type: "api_key" }],
		["oauth only", "", bundle()],
		["grant only", "", { grant_type: "browser_login" }],
		[
			"wrong grant",
			"",
			{ grant_type: "client_credentials", token_url: secret("https://idp.example/t"), client_id: secret("i"), client_secret: secret("s") },
		],
	];

	it.each(cases)("%s", (_name, pasted, oauthConfig) => {
		const live = parse("codebuddy-cn", { value: value(pasted), oauth_key_config: oauthConfig });
		const creation = ProviderFormSchema.safeParse({
			selectedProvider: "codebuddy-cn",
			isDirty: true,
			networkConfig: DefaultNetworkConfig,
			keys: [{ id: "k1", name: "cb", models: ["*"], weight: 1, value: pasted, oauth_key_config: oauthConfig }],
		});
		expect(live.success).toBe(creation.success);
	});
});

// The validator and the save path must agree: a key the schema accepts has to keep a credential
// after applyAuthMethod, and a block applyAuthMethod would drop must not read as connected.
describe("codebuddy-cn schema and applyAuthMethod agree", () => {
	it("keeps a validated browser-login bundle on save", () => {
		const key = { ...base, value: secret(""), oauth_key_config: { ...bundle(), _auth_type: "oauth" } };
		const result = providerKeyFormSchema("codebuddy-cn").safeParse({ key });
		expect(result.success, result.success ? "" : JSON.stringify(result.error.issues)).toBe(true);
		if (!result.success) return;
		const payload = applyAuthMethod(result.data.key as Record<string, unknown>, false);
		expect(payload.oauth_key_config).toMatchObject({ grant_type: "browser_login" });
		expect(payload.value).toEqual({ value: "" });
	});

	it("drops the block a rejected key would have sent", () => {
		const payload = applyAuthMethod(
			{ ...base, value: secret("sk-pasted"), oauth_key_config: { ...bundle(), _auth_type: "api_key" } },
			false,
		);
		expect(payload.oauth_key_config).toBeUndefined();
		expect(payload.value).toEqual(secret("sk-pasted"));
	});
});