import { describe, expect, it } from "vitest";
import { resolveProviderIconKey } from "./icons";

describe("resolveProviderIconKey", () => {
	it("resolves a provider that has a mark of its own", () => {
		expect(resolveProviderIconKey("openai")).toBe("openai");
	});

	// The icon key is the provider string itself, so a "codebuddy" entry would silently leave
	// CodeBuddy CN without a mark: resolveProviderIconKey does an exact own-property lookup.
	it("resolves the codebuddy-cn provider string", () => {
		expect(resolveProviderIconKey("codebuddy-cn")).toBe("codebuddy-cn");
	});

	it("falls back to the base provider type for a custom provider", () => {
		expect(resolveProviderIconKey("my-gateway", "openai")).toBe("openai");
	});

	it("returns undefined for a provider with no mark and no base type", () => {
		expect(resolveProviderIconKey("my-gateway")).toBeUndefined();
	});

	// `in` walks the prototype chain, so inherited keys look like real icon entries and
	// RenderProviderIcon then calls a non-component as a component.
	it("does not treat inherited object keys as icons", () => {
		for (const inherited of ["__proto__", "constructor", "toString", "hasOwnProperty", "valueOf"]) {
			expect(resolveProviderIconKey(inherited), inherited).toBeUndefined();
		}
	});

	it("does not resolve an inherited key reached through the base provider type", () => {
		expect(resolveProviderIconKey("my-gateway", "constructor")).toBeUndefined();
	});
});