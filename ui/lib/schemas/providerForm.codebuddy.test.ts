import { describe, expect, it } from "vitest";
import { DefaultNetworkConfig } from "@/lib/constants/config";
import { codebuddyCNOAuthComplete, codebuddyCNTokenURL, ProviderFormSchema } from "./providerForm";

// A codebuddy-cn key has exactly two auth modes and the server refuses any other combination:
// a pasted API key (X-API-Key) or a browser_login bundle (Authorization). The form must agree,
// because zodResolver strips what the schema does not declare and a form that posts either both
// or neither reaches the API as a 400 rather than an inline field error.
describe("ProviderFormSchema codebuddy-cn credentials", () => {
	const literal = (value: string) => ({ value, ref: "" });
	const oauth = (overrides: Record<string, unknown> = {}) => ({
		grant_type: "browser_login",
		token_url: literal("https://copilot.tencent.com/v2/plugin/auth/token/refresh"),
		access_token: literal("access-abc"),
		refresh_token: literal("refresh-xyz"),
		expires_at: "2026-10-22T12:00:00Z",
		...overrides,
	});

	const form = (keyOverrides: Record<string, unknown>) => ({
		selectedProvider: "codebuddy-cn",
		isDirty: true,
		networkConfig: DefaultNetworkConfig,
		keys: [{ id: "k1", name: "cb", models: ["*"], weight: 1, ...keyOverrides }],
	});

	const parse = (keyOverrides: Record<string, unknown>) => ProviderFormSchema.safeParse(form(keyOverrides));

	it("accepts an oauth-only key with an empty value", () => {
		const result = parse({ value: "", oauth_key_config: oauth() });

		expect(result.success, result.success ? "" : JSON.stringify(result.error.issues)).toBe(true);
		if (!result.success) return;

		// The block must survive parsing: a stripped bundle would save a key with no credential.
		const key = result.data.keys[0];
		expect(key.oauth_key_config?.grant_type).toBe("browser_login");
		expect(key.oauth_key_config?.refresh_token?.value).toBe("refresh-xyz");
	});

	it("accepts a pasted api key with no oauth config", () => {
		expect(parse({ value: "sk-pasted" }).success).toBe(true);
	});

	it("rejects a key with both auth modes", () => {
		const r = parse({ value: "sk-pasted", oauth_key_config: oauth() });
		expect(r.success, "a key carrying both a pasted key and a login must not save").toBe(false);
		if (r.success) return;
		// The issue must land on the block, not on the value: that is the field the message
		// points at, and a future rule that rejected for some unrelated reason would fail here.
		expect(r.error.issues.map((issue) => issue.path.join("."))).toContain("keys.0.oauth_key_config");
	});

	it("rejects a key with neither auth mode", () => {
		const r = parse({ value: "", oauth_key_config: undefined });
		expect(r.success, "a key with no credential at all must not save").toBe(false);
		if (r.success) return;
		expect(r.error.issues.map((issue) => issue.path.join("."))).toContain("keys.0.value");
	});

	it("rejects an incomplete oauth bundle", () => {
		expect(parse({ value: "", oauth_key_config: oauth({ refresh_token: literal("") }) }).success).toBe(false);
	});

	// The shared block's "has anyone started typing" heuristic lets a grant with no credential
	// through, so a grant-only bundle is the case the old check missed.
	it("rejects a grant-only bundle", () => {
		const r = parse({ value: "", oauth_key_config: { grant_type: "browser_login" } });
		expect(r.success).toBe(false);
		if (r.success) return;
		expect(r.error.issues.map((issue) => issue.path.join("."))).toEqual(
			expect.arrayContaining(["keys.0.oauth_key_config.token_url", "keys.0.oauth_key_config.refresh_token"]),
		);
	});

	// The server parses the stored string as it arrives, so padding must fail here.
	it("rejects a padded expiry", () => {
		expect(parse({ value: "", oauth_key_config: oauth({ expires_at: " 2026-10-22T12:00:00Z " }) }).success).toBe(false);
	});

	// Only browser_login is valid here: the server refuses any other grant on this provider.
	it("rejects an oauth block using another grant", () => {
		const clientCredentials = {
			grant_type: "client_credentials",
			token_url: literal("https://idp.example.com/token"),
			client_id: literal("id"),
			client_secret: literal("secret"),
		};
		expect(parse({ value: "", oauth_key_config: clientCredentials }).success).toBe(false);
	});

	// The server parses expires_at with time.RFC3339, so a value it cannot read must fail here.
	it("rejects an oauth bundle whose expiry is not RFC3339", () => {
		expect(parse({ value: "", oauth_key_config: oauth({ expires_at: "22/10/2026 12:00" }) }).success).toBe(false);
	});

	// The shared oauth_key_config field is provider-agnostic; the codebuddy-cn branch must not
	// narrow it for everyone else.
	it("leaves another provider's client credentials key valid", () => {
		const other = ProviderFormSchema.safeParse({
			selectedProvider: "openai",
			isDirty: true,
			networkConfig: DefaultNetworkConfig,
			keys: [
				{
					id: "k1",
					name: "openai",
					value: "",
					models: ["*"],
					weight: 1,
					oauth_key_config: {
						_auth_type: "oauth",
						grant_type: "client_credentials",
						token_url: literal("https://idp.example.com/token"),
						client_id: literal("id"),
						client_secret: literal("secret"),
					},
				},
			],
		});
		expect(other.success, other.success ? "" : JSON.stringify(other.error.issues)).toBe(true);
	});
});

// Task 9's form fragment renders "connected" from this predicate and its modal hands the
// generated bundle back, so it has to agree with the schema above field for field.
describe("codebuddyCNOAuthComplete", () => {
	const literal = (value: string) => ({ value, ref: "" });
	const bundle = (overrides: Record<string, unknown> = {}) => ({
		grant_type: "browser_login",
		token_url: literal("https://copilot.tencent.com/v2/plugin/auth/token/refresh"),
		access_token: literal("access-abc"),
		refresh_token: literal("refresh-xyz"),
		expires_at: "2026-10-22T12:00:00Z",
		...overrides,
	});

	it("accepts a whole browser-login bundle, with or without an access token", () => {
		expect(codebuddyCNOAuthComplete(bundle())).toBe(true);
		// The server mints the first access token from the refresh token, so a bundle straight
		// out of the login response may not carry one.
		expect(codebuddyCNOAuthComplete(bundle({ access_token: undefined }))).toBe(true);
	});

	it("accepts an empty expiry, which means refresh on use", () => {
		expect(codebuddyCNOAuthComplete(bundle({ expires_at: "" }))).toBe(true);
		expect(codebuddyCNOAuthComplete(bundle({ expires_at: undefined }))).toBe(true);
	});

	it("rejects nothing, another grant and an unreadable expiry", () => {
		expect(codebuddyCNOAuthComplete(undefined)).toBe(false);
		expect(codebuddyCNOAuthComplete(null)).toBe(false);
		expect(codebuddyCNOAuthComplete({ ...bundle(), grant_type: "client_credentials" })).toBe(false);
		expect(codebuddyCNOAuthComplete(bundle({ expires_at: "not a date" }))).toBe(false);
		expect(codebuddyCNOAuthComplete(bundle({ refresh_token: literal("") }))).toBe(false);
	});

	// The shared schema lets a grant with no credential through; this predicate must not.
	it("rejects a grant with no credential fields", () => {
		expect(codebuddyCNOAuthComplete({ grant_type: "browser_login" })).toBe(false);
		expect(
			codebuddyCNOAuthComplete({
				grant_type: "browser_login",
				token_url: literal("https://copilot.tencent.com/v2/plugin/auth/token/refresh"),
			}),
		).toBe(false);
	});
});

// Task 9 builds the bundle from the poll response, which carries no token URL: the host comes
// from the provider's configured base_url, exactly as the login handler resolves it.
describe("codebuddyCNTokenURL", () => {
	it("defaults to the CN gateway", () => {
		expect(codebuddyCNTokenURL()).toBe("https://copilot.tencent.com/v2/plugin/auth/token/refresh");
		expect(codebuddyCNTokenURL("")).toBe("https://copilot.tencent.com/v2/plugin/auth/token/refresh");
		expect(codebuddyCNTokenURL("   ")).toBe("https://copilot.tencent.com/v2/plugin/auth/token/refresh");
	});

	it("follows a configured base URL, with or without a trailing slash", () => {
		const expected = "https://codebuddy.internal.example/v2/plugin/auth/token/refresh";
		expect(codebuddyCNTokenURL("https://codebuddy.internal.example")).toBe(expected);
		expect(codebuddyCNTokenURL("https://codebuddy.internal.example/")).toBe(expected);
		expect(codebuddyCNTokenURL("https://codebuddy.internal.example///")).toBe(expected);
		expect(codebuddyCNTokenURL(" http://127.0.0.1:8080 ")).toBe("http://127.0.0.1:8080/v2/plugin/auth/token/refresh");
	});

	it("produces a URL the bundle schema accepts", () => {
		expect(
			codebuddyCNOAuthComplete({
				grant_type: "browser_login",
				token_url: { value: codebuddyCNTokenURL("https://proxy.example") },
				refresh_token: { value: "r" },
			}),
		).toBe(true);
	});

	// Task 9 may import from either module; they must be the same function, not two copies that
	// can drift.
	it("is the same helper the shared module exports", async () => {
		const shared = await import("@/lib/types/schemas");
		expect(shared.codebuddyCNTokenURL).toBe(codebuddyCNTokenURL);
		expect(shared.codebuddyCNOAuthComplete).toBe(codebuddyCNOAuthComplete);
	});
});

// A bundle the save path drops must not read as connected: the predicate and
// stripOAuthAuthDiscriminator ask the same question so the form cannot show a credential the
// save silently discards.
describe("codebuddyCNOAuthComplete and the save path", () => {
	const literal = (value: string) => ({ value, ref: "" });
	const whole = {
		grant_type: "browser_login",
		token_url: literal("https://copilot.tencent.com/v2/plugin/auth/token/refresh"),
		refresh_token: literal("refresh-xyz"),
	};

	it("reads a complete bundle with no discriminator as connected", () => {
		expect(codebuddyCNOAuthComplete(whole)).toBe(true);
	});

	it("does not read the api-key tab's discriminator as connected", () => {
		expect(codebuddyCNOAuthComplete({ ...whole, _auth_type: "api_key" })).toBe(false);
	});

	it("reads an explicit oauth choice as connected once the bundle is whole", () => {
		expect(codebuddyCNOAuthComplete({ ...whole, _auth_type: "oauth" })).toBe(true);
	});
});

// The key form seeds `_auth_type: "api_key"` on mount as the inert placeholder for the API-key
// tab. The shared schema skips its checks for that value, so completeness must not be fooled by it.
describe("codebuddyCNOAuthComplete and the inert discriminator", () => {
	const literal = (value: string) => ({ value, ref: "" });

	it("does not read a placeholder bundle as connected", () => {
		expect(
			codebuddyCNOAuthComplete({
				_auth_type: "api_key",
				grant_type: "browser_login",
				token_url: literal("https://copilot.tencent.com/v2/plugin/auth/token/refresh"),
			}),
		).toBe(false);
	});
});