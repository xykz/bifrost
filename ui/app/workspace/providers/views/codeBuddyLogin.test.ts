import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { codebuddyCNOAuthComplete } from "@/lib/types/schemas";
import type { CodeBuddyLoginStart, CodeBuddyLoginStatus } from "@/lib/types/config";
import {
	codeBuddyLoginAPIKeyModeConfig,
	codeBuddyLoginAuthMode,
	codeBuddyLoginErrorFromForm,
	codeBuddyLoginOAuthConfig,
	codeBuddyLoginPendingOAuthConfig,
	pollCodeBuddyLogin,
	startCodeBuddyLogin,
	type CodeBuddyLoginDeps,
	type CodeBuddyLoginPopup,
	type CodeBuddyLoginResult,
} from "./codeBuddyLogin";
import { providerKeyFormSchema, stripOAuthAuthDiscriminator } from "./providerKeyForm.utils";

const POLL_MS = 2000;

const FLOW: CodeBuddyLoginStart = {
	flow_id: "flow-1",
	auth_url: "https://copilot.tencent.com/v2/plugin/auth?state=abc",
	flow_expires_at: "2026-10-22T12:15:00Z",
};

const RESULT: CodeBuddyLoginResult = {
	access_token: "access-abc",
	refresh_token: "refresh-xyz",
	expires_at: "2026-10-22T13:00:00Z",
};

const PENDING: CodeBuddyLoginStatus = { status: "pending" };
const COMPLETED: CodeBuddyLoginStatus = { status: "completed", token_type: "Bearer", ...RESULT };

type FakePopup = CodeBuddyLoginPopup & { closeCount: number; navigatedTo: string[] };

const makePopup = (): FakePopup => {
	const popup: FakePopup = {
		closed: false,
		closeCount: 0,
		navigatedTo: [],
		close: () => {
			popup.closed = true;
			popup.closeCount += 1;
		},
		navigate: (url) => {
			popup.navigatedTo.push(url);
		},
	};
	return popup;
};

const deps = (overrides: Partial<CodeBuddyLoginDeps>): CodeBuddyLoginDeps => ({
	openPopup: () => makePopup(),
	start: () => Promise.resolve(FLOW),
	poll: () => Promise.resolve(PENDING),
	onResult: () => {},
	...overrides,
});

// Lets the start promise's .then run and the interval install, without moving the clock.
const flush = () => vi.advanceTimersByTimeAsync(0);
const tick = (times = 1) => vi.advanceTimersByTimeAsync(POLL_MS * times);

describe("startCodeBuddyLogin", () => {
	beforeEach(() => {
		vi.useFakeTimers();
		// The flow deadline is a wall-clock instant: pin it before the fixtures' deadline so the
		// happy paths are not timeouts. Individual cases move the clock past it.
		vi.setSystemTime(new Date("2026-10-22T12:00:00Z"));
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	// The browser only keeps the click's transient user activation until the handler
	// returns. A window.open issued after any await is blocked outright, so the popup
	// has to be opened by the synchronous part of the call, before start() is even asked.
	it("opens the popup before the start request resolves", async () => {
		const order: string[] = [];
		const popup = makePopup();
		let resolveStart: (flow: CodeBuddyLoginStart) => void = () => {};

		const run = startCodeBuddyLogin(
			deps({
				openPopup: () => {
					order.push("openPopup");
					return popup;
				},
				start: () => {
					order.push("start");
					return new Promise<CodeBuddyLoginStart>((resolve) => {
						resolveStart = resolve;
					});
				},
			}),
		);

		// Both ran synchronously, in this order, and nothing navigated yet: start is still
		// unresolved, so a navigate here could only have come from the auth_url.
		expect(order).toEqual(["openPopup", "start"]);
		expect(popup.navigatedTo).toEqual([]);

		resolveStart(FLOW);
		await flush();

		expect(popup.navigatedTo).toEqual([FLOW.auth_url]);
		run.cancel();
	});

	it("navigates the popup to the auth url and closes it on completion", async () => {
		const popup = makePopup();
		const onResult = vi.fn();
		let polls = 0;

		const run = startCodeBuddyLogin(
			deps({
				openPopup: () => popup,
				onResult,
				poll: () => {
					polls += 1;
					return Promise.resolve(polls < 3 ? PENDING : COMPLETED);
				},
			}),
		);

		await flush();
		expect(popup.navigatedTo).toEqual([FLOW.auth_url]);

		await tick(3);

		expect(polls).toBe(3);
		expect(popup.closeCount).toBe(1);
		expect(onResult).toHaveBeenCalledTimes(1);
		expect(onResult).toHaveBeenCalledWith(RESULT);

		await tick(3);
		expect(polls).toBe(3);
		run.cancel();
	});

	it("stops polling and closes the popup when dismissed mid-flight", async () => {
		const popup = makePopup();
		const onResult = vi.fn();
		let polls = 0;

		const run = startCodeBuddyLogin(
			deps({
				openPopup: () => popup,
				onResult,
				poll: () => {
					polls += 1;
					return Promise.resolve(PENDING);
				},
			}),
		);

		await flush();
		await tick(2);
		expect(polls).toBe(2);

		run.cancel();
		expect(popup.closeCount).toBe(1);

		await tick(5);
		expect(polls).toBe(2);
		expect(onResult).not.toHaveBeenCalled();
	});

	it("surfaces a failed flow without retrying", async () => {
		const popup = makePopup();
		const onResult = vi.fn();
		let polls = 0;

		startCodeBuddyLogin(
			deps({
				openPopup: () => popup,
				onResult,
				poll: () => {
					polls += 1;
					return Promise.resolve<CodeBuddyLoginStatus>(
						polls < 2 ? PENDING : { status: "failed", error: "The CodeBuddy login was denied." },
					);
				},
			}),
		);

		await flush();
		await tick(2);

		expect(onResult).toHaveBeenCalledTimes(1);
		expect(onResult).toHaveBeenCalledWith({ error: "The CodeBuddy login was denied." });
		expect(popup.closeCount).toBe(1);

		await tick(5);
		expect(polls).toBe(2);
	});

	// A 502 from the gateway (the upstream poll failed once) is not an outcome: the flow is
	// still alive server-side, so the browser has to keep polling it.
	it("treats a poll error as transient while the flow is still alive", async () => {
		const popup = makePopup();
		const onResult = vi.fn();
		let polls = 0;

		startCodeBuddyLogin(
			deps({
				openPopup: () => popup,
				onResult,
				poll: () => {
					polls += 1;
					if (polls === 1) return Promise.reject(new Error("502 Bad Gateway"));
					return Promise.resolve(COMPLETED);
				},
			}),
		);

		await flush();
		await tick(2);

		expect(polls).toBe(2);
		expect(onResult).toHaveBeenCalledTimes(1);
		expect(onResult).toHaveBeenCalledWith(RESULT);
		expect(popup.closeCount).toBe(1);
	});

	it("gives up when the flow deadline passes", async () => {
		const popup = makePopup();
		const onResult = vi.fn();
		let polls = 0;
		let clock = Date.parse("2026-10-22T12:00:00Z");

		startCodeBuddyLogin(
			deps({
				openPopup: () => popup,
				onResult,
				now: () => clock,
				poll: () => {
					polls += 1;
					return Promise.resolve(PENDING);
				},
			}),
		);

		await flush();
		await tick(2);
		expect(polls).toBe(2);

		clock = Date.parse("2026-10-22T12:16:00Z");
		await tick(1);

		expect(onResult).toHaveBeenCalledTimes(1);
		const outcome = onResult.mock.calls[0][0] as { error?: string };
		expect(outcome.error).toMatch(/timed out/i);
		expect(popup.closeCount).toBe(1);

		await tick(5);
		expect(polls).toBe(2);
	});

	// A poll that never answers must not keep the dialog open past the flow deadline: the
	// server has already dropped the flow by then, so waiting on the promise can only hang.
	it("times out even while a poll is still in flight", async () => {
		const popup = makePopup();
		const onResult = vi.fn();
		let clock = Date.parse("2026-10-22T12:00:00Z");

		startCodeBuddyLogin(
			deps({
				openPopup: () => popup,
				onResult,
				now: () => clock,
				poll: () => new Promise<CodeBuddyLoginStatus>(() => {}),
			}),
		);

		await flush();
		await tick(1);
		expect(onResult).not.toHaveBeenCalled();

		clock = Date.parse("2026-10-22T12:16:00Z");
		await tick(1);

		expect(onResult).toHaveBeenCalledTimes(1);
		expect((onResult.mock.calls[0][0] as { error?: string }).error).toMatch(/timed out/i);
		expect(popup.closeCount).toBe(1);
	});

	it("reports a blocked popup without starting a flow", async () => {
		const onResult = vi.fn();
		const start = vi.fn(() => Promise.resolve(FLOW));

		startCodeBuddyLogin(deps({ openPopup: () => null, start, onResult }));

		expect(start).not.toHaveBeenCalled();
		expect(onResult).toHaveBeenCalledTimes(1);
		const outcome = onResult.mock.calls[0][0] as { error?: string };
		expect(outcome.error).toMatch(/blocked/i);
	});

	it("treats an already-closed popup as blocked", async () => {
		const popup = makePopup();
		popup.closed = true;
		const start = vi.fn(() => Promise.resolve(FLOW));
		const onResult = vi.fn();

		startCodeBuddyLogin(deps({ openPopup: () => popup, start, onResult }));

		expect(start).not.toHaveBeenCalled();
		expect((onResult.mock.calls[0][0] as { error?: string }).error).toMatch(/blocked/i);
		// It was already gone; closing it again would be a no-op on a stale handle.
		expect(popup.closeCount).toBe(0);
	});

	it("surfaces a start failure with the message the caller prepared", async () => {
		const popup = makePopup();
		const onResult = vi.fn();

		startCodeBuddyLogin(
			deps({
				openPopup: () => popup,
				start: () => Promise.reject(new Error("CodeBuddy login requires an authenticated admin session.")),
				onResult,
			}),
		);

		await flush();

		expect(onResult).toHaveBeenCalledTimes(1);
		expect((onResult.mock.calls[0][0] as { error?: string }).error).toBe("CodeBuddy login requires an authenticated admin session.");
		expect(popup.closeCount).toBe(1);
	});

	// Cancel closes the popup and stops polling, but it is not an outcome. A poll already
	// in flight still resolves afterwards and must not report a result into a form the
	// admin has moved on from.
	it("ignores a poll that resolves after cancel", async () => {
		const popup = makePopup();
		const onResult = vi.fn();
		let polls = 0;
		let release: (status: CodeBuddyLoginStatus) => void = () => {};

		const run = startCodeBuddyLogin(
			deps({
				openPopup: () => popup,
				onResult,
				poll: () => {
					polls += 1;
					if (polls < 3) return Promise.resolve(PENDING);
					return new Promise<CodeBuddyLoginStatus>((resolve) => {
						release = resolve;
					});
				},
			}),
		);

		await flush();
		await tick(3);
		expect(polls).toBe(3);

		run.cancel();
		expect(popup.closeCount).toBe(1);

		release(COMPLETED);
		await flush();

		expect(onResult).not.toHaveBeenCalled();
		expect(popup.closeCount).toBe(1);
	});
});

describe("pollCodeBuddyLogin", () => {
	// The gateway answers 502 when the upstream poll itself fails. That is a transport fault,
	// not a verdict on the flow, and the state machine depends on that reading.
	it("classifies a rejected poll as pending", async () => {
		await expect(pollCodeBuddyLogin(() => Promise.reject(new Error("502")), "flow-1")).resolves.toEqual({ kind: "pending" });
	});

	it("carries the three token fields through a completed answer", async () => {
		await expect(pollCodeBuddyLogin(() => Promise.resolve(COMPLETED), "flow-1")).resolves.toEqual({ kind: "completed", result: RESULT });
	});

	it("keeps the server's message on a failed flow", async () => {
		await expect(pollCodeBuddyLogin(() => Promise.resolve({ status: "failed", error: "Sign-in was denied." }), "flow-1")).resolves.toEqual({
			kind: "failed",
			error: "Sign-in was denied.",
		});
	});

	// A failure with no message must still read as an actionable sentence, not an empty box.
	it("falls back to a sentence when the failure carries no message", async () => {
		const outcome = await pollCodeBuddyLogin(() => Promise.resolve({ status: "failed" }), "flow-1");
		expect(outcome.kind).toBe("failed");
		expect(outcome.kind === "failed" ? outcome.error : "").toMatch(/try again/i);
	});
});

describe("codeBuddyLoginOAuthConfig", () => {
	const literal = (value: string) => ({ value, ref: "" });

	// What the fragment stores after a login: the save path has to keep the whole bundle,
	// because a block it drops leaves the key with no credential at all.
	it("builds a browser-login bundle the save path keeps", () => {
		const config = codeBuddyLoginOAuthConfig(RESULT);

		expect(config.grant_type).toBe("browser_login");
		expect(config.token_url).toEqual(literal("https://copilot.tencent.com/v2/plugin/auth/token/refresh"));
		expect(config.refresh_token).toEqual(literal(RESULT.refresh_token));
		expect(config.expires_at).toBe(RESULT.expires_at);
		expect(codebuddyCNOAuthComplete(config)).toBe(true);

		const saved = stripOAuthAuthDiscriminator(config);
		expect(saved).not.toHaveProperty("_auth_type");
		expect(saved?.grant_type).toBe("browser_login");
		expect(saved?.refresh_token).toEqual(literal(RESULT.refresh_token));
	});

	it("derives the token url from the provider base url", () => {
		const config = codeBuddyLoginOAuthConfig(RESULT, "https://codebuddy.internal.example/");
		expect(config.token_url).toEqual(literal("https://codebuddy.internal.example/v2/plugin/auth/token/refresh"));
	});

	// The whole point of clearing the key value in the same write: a codebuddy key carrying
	// both a pasted key and the login bundle is refused by the live resolver, so the form
	// state after a successful sign-in must pass on its own.
	it("pairs with a cleared value into a key the live resolver accepts", () => {
		const key = {
			id: "k1",
			name: "cb",
			models: ["*"],
			weight: 1,
			value: literal(""),
			oauth_key_config: codeBuddyLoginOAuthConfig(RESULT),
		};

		const accepted = providerKeyFormSchema("codebuddy-cn").safeParse({ key });
		expect(accepted.success, accepted.success ? "" : JSON.stringify(accepted.error.issues)).toBe(true);

		const both = providerKeyFormSchema("codebuddy-cn").safeParse({ key: { ...key, value: literal("sk-pasted") } });
		expect(both.success).toBe(false);
	});
});

describe("codeBuddyLogin mode switch", () => {
	const literal = (value: string) => ({ value, ref: "" });
	const base = { id: "k1", name: "cb", models: ["*"], weight: 1 };
	const parse = (key: Record<string, unknown>) => providerKeyFormSchema("codebuddy-cn").safeParse({ key: { ...base, ...key } });

	// Switching back to the API-key tab has to clear the three token fields, or the same
	// "both auth modes" rule that guards the login direction breaks on the way back.
	it("clears the browser-login fields when switching to the API key tab", () => {
		const connected = { value: literal(""), oauth_key_config: codeBuddyLoginOAuthConfig(RESULT) };
		expect(parse(connected).success).toBe(true);

		const switched = { ...connected, oauth_key_config: codeBuddyLoginAPIKeyModeConfig(), value: literal("sk-pasted") };
		const accepted = parse(switched);
		expect(accepted.success, accepted.success ? "" : JSON.stringify(accepted.error.issues)).toBe(true);

		// Nothing of the old bundle can still be a credential: the save path drops the block,
		// and the key carries exactly one auth mode.
		expect(stripOAuthAuthDiscriminator(switched.oauth_key_config)).toBeUndefined();
		expect(codebuddyCNOAuthComplete(switched.oauth_key_config)).toBe(false);

		// And the reverse holds: the switched state no longer passes without a pasted key.
		expect(parse({ ...switched, value: literal("") }).success).toBe(false);
	});

	it("seeds the OAuth tab without claiming it is connected", () => {
		const pending = codeBuddyLoginPendingOAuthConfig("https://codebuddy.internal.example");
		expect(pending.grant_type).toBe("browser_login");
		expect(pending.token_url).toEqual(literal("https://codebuddy.internal.example/v2/plugin/auth/token/refresh"));
		expect(pending.access_token).toBeUndefined();
		expect(pending.refresh_token).toBeUndefined();

		// A key saved from this state is refused rather than silently storing no credential.
		const result = parse({ value: literal(""), oauth_key_config: pending });
		expect(result.success).toBe(false);
	});

	it("reads the mode off a stored key with no discriminator", () => {
		expect(codeBuddyLoginAuthMode(undefined)).toBe("api_key");
		expect(codeBuddyLoginAuthMode({ _auth_type: "api_key" })).toBe("api_key");
		expect(codeBuddyLoginAuthMode(codeBuddyLoginOAuthConfig(RESULT))).toBe("oauth");

		// A reset drops the discriminator; a whole bundle is still a login.
		const saved = stripOAuthAuthDiscriminator(codeBuddyLoginOAuthConfig(RESULT));
		expect(codeBuddyLoginAuthMode(saved)).toBe("oauth");
		expect(codeBuddyLoginAuthMode({ grant_type: "browser_login" })).toBe("api_key");
	});
});

describe("codeBuddyLoginErrorFromForm", () => {
	const keyError = (oauth: unknown) => ({ key: { oauth_key_config: oauth } });

	// The tab's own fields have no input for these paths, so this is the only thing that can
	// put the schema's sentence on screen.
	it("finds a message the other tabs' FormMessages cannot show", () => {
		expect(
			codeBuddyLoginErrorFromForm(keyError({ message: "A CodeBuddy CN key takes either a pasted API key or an OAuth login, not both" })),
		).toBe("A CodeBuddy CN key takes either a pasted API key or an OAuth login, not both");
		expect(codeBuddyLoginErrorFromForm(keyError({ refresh_token: { message: "Refresh token is required for a browser login" } }))).toBe(
			"Refresh token is required for a browser login",
		);
		expect(codeBuddyLoginErrorFromForm(keyError({ grant_type: { message: "CodeBuddy CN keys use the browser login grant" } }))).toBe(
			"CodeBuddy CN keys use the browser login grant",
		);
	});

	it("returns nothing when the block is fine or the tree is empty", () => {
		expect(codeBuddyLoginErrorFromForm(undefined)).toBeUndefined();
		expect(codeBuddyLoginErrorFromForm({})).toBeUndefined();
		expect(codeBuddyLoginErrorFromForm(keyError({}))).toBeUndefined();
		expect(codeBuddyLoginErrorFromForm({ key: { name: { message: "Name is required" } } })).toBeUndefined();
	});
});