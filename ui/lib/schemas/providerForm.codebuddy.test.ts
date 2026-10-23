import { describe, expect, it } from "vitest";
import { DefaultNetworkConfig } from "@/lib/constants/config";
import { ProviderFormSchema } from "./providerForm";

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
	});

	it("rejects a key with neither auth mode", () => {
		const r = parse({ value: "", oauth_key_config: undefined });
		expect(r.success, "a key with no credential at all must not save").toBe(false);
	});

	it("rejects an incomplete oauth bundle", () => {
		expect(parse({ value: "", oauth_key_config: oauth({ refresh_token: literal("") }) }).success).toBe(false);
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