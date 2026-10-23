import { codebuddyCNOAuthComplete, codebuddyCNTokenURL } from "@/lib/types/schemas";
import type { CodeBuddyLoginStart, CodeBuddyLoginStatus, OAuthKeyConfig } from "@/lib/types/config";

// The popup/poll state machine behind the CodeBuddy sign-in dialog. Every effect it needs is
// injected, so the ordering rules (the popup opens before the first await, a late poll cannot
// report after cancel) are testable without a DOM or a component tree. The modal supplies the
// real window.open and the RTK endpoints; nothing here imports React or the store.

// The three fields of a completed login the key form stores. token_type is deliberately not
// part of it: the bundle only ever carries a Bearer, so there is nothing to record.
export type CodeBuddyLoginResult = {
	access_token: string;
	refresh_token: string;
	expires_at: string;
};

// The slice of window.open a caller needs. `closed` is read as a property because a popup that
// the admin (or the redirect page) closed is no longer ours to close.
export type CodeBuddyLoginPopup = {
	closed: boolean;
	close: () => void;
	navigate: (url: string) => void;
};

export type CodeBuddyLoginDeps = {
	openPopup: () => CodeBuddyLoginPopup | null;
	start: () => Promise<CodeBuddyLoginStart>;
	poll: (flowId: string) => Promise<CodeBuddyLoginStatus>;
	onResult: (result: CodeBuddyLoginResult | { error: string }) => void;
	now?: () => number;
};

// Two seconds, matching the MCP OAuth authorizer: the upstream answers a pending poll with a
// cheap code and the admin is watching the dialog, so a slower cadence only adds dead time.
export const CODEBUDDY_LOGIN_POLL_INTERVAL_MS = 2000;

const POPUP_BLOCKED_MESSAGE = "Your browser blocked the sign-in window. Allow popups for this site, then try again.";
const START_FAILED_MESSAGE = "Could not start the CodeBuddy sign-in. Try again.";
const TIMEOUT_MESSAGE = "The CodeBuddy sign-in timed out. Try again.";
const FAILED_MESSAGE = "The CodeBuddy sign-in did not complete. Try again.";

// errorMessage keeps a message the caller already turned into one (the modal wraps RTK's
// FetchBaseQueryError with getErrorMessage) and falls back to an actionable sentence otherwise.
const errorMessage = (error: unknown): string => {
	if (error && typeof error === "object" && "message" in error) {
		const message = (error as { message?: unknown }).message;
		if (typeof message === "string" && message.trim()) return message;
	}
	return START_FAILED_MESSAGE;
};

const deadlineOf = (flowExpiresAt: string): number => {
	const parsed = Date.parse(flowExpiresAt);
	return Number.isNaN(parsed) ? Number.POSITIVE_INFINITY : parsed;
};

// A single poll's meaning, with the transport flattened out: a rejected poll is not an outcome
// (the server still owns the flow), so it reads as pending alongside the upstream's own pending
// answer. The caller owns the deadline and the lifecycle.
export type CodeBuddyPollOutcome =
	| { kind: "pending" }
	| { kind: "completed"; result: CodeBuddyLoginResult }
	| { kind: "failed"; error: string };

export async function pollCodeBuddyLogin(poll: CodeBuddyLoginDeps["poll"], flowId: string): Promise<CodeBuddyPollOutcome> {
	let status: CodeBuddyLoginStatus;
	try {
		status = await poll(flowId);
	} catch {
		// A 502 from the gateway means the upstream poll failed this once, not that the flow is
		// dead: the server still owns it and the next tick may well complete it.
		return { kind: "pending" };
	}
	if (status.status === "completed") {
		return {
			kind: "completed",
			result: { access_token: status.access_token, refresh_token: status.refresh_token, expires_at: status.expires_at },
		};
	}
	if (status.status === "failed") {
		return { kind: "failed", error: status.error?.trim() ? status.error : FAILED_MESSAGE };
	}
	return { kind: "pending" };
}

export function startCodeBuddyLogin(deps: CodeBuddyLoginDeps, opts?: { pollIntervalMs?: number }): { cancel: () => void } {
	const intervalMs = opts?.pollIntervalMs ?? CODEBUDDY_LOGIN_POLL_INTERVAL_MS;
	const now = deps.now ?? Date.now;

	// `settled` is the single source of truth for "this run is over". Every terminal path sets it
	// first and checks it again after each await, so a poll that resolves after the dialog was
	// dismissed cannot write into the form the admin has moved on from.
	let settled = false;
	let timer: ReturnType<typeof setInterval> | null = null;
	let popup: CodeBuddyLoginPopup | null = null;
	let inFlight = false;
	let deadline = Number.POSITIVE_INFINITY;

	const stopPolling = () => {
		if (timer === null) return;
		clearInterval(timer);
		timer = null;
	};

	const closePopup = () => {
		if (popup && !popup.closed) popup.close();
	};

	const finish = (outcome: CodeBuddyLoginResult | { error: string }) => {
		if (settled) return;
		settled = true;
		stopPolling();
		closePopup();
		deps.onResult(outcome);
	};

	const pollOnce = async (flowId: string) => {
		if (settled) return;
		// Checked before the in-flight guard: a request that never answers must still hit the
		// deadline rather than leaving the dialog waiting forever on a promise nobody resolves.
		if (now() > deadline) {
			finish({ error: TIMEOUT_MESSAGE });
			return;
		}
		if (inFlight) return;
		inFlight = true;
		const outcome = await pollCodeBuddyLogin(deps.poll, flowId);
		inFlight = false;
		if (settled) return;
		if (outcome.kind === "completed") {
			finish(outcome.result);
		} else if (outcome.kind === "failed") {
			finish({ error: outcome.error });
		}
	};

	const cancel = () => {
		if (settled) return;
		settled = true;
		stopPolling();
		closePopup();
	};

	// Must happen synchronously, before any await: the click's transient user activation is gone
	// by the time a start request resolves, and window.open from that point is blocked outright.
	try {
		popup = deps.openPopup();
	} catch {
		popup = null;
	}
	if (!popup || popup.closed) {
		finish({ error: POPUP_BLOCKED_MESSAGE });
		return { cancel };
	}
	const opened = popup;

	let starting: Promise<CodeBuddyLoginStart>;
	try {
		starting = deps.start();
	} catch (error) {
		// A caller whose start() throws inline (rather than rejecting) must not escape the click
		// handler and leave the dialog spinning.
		finish({ error: errorMessage(error) });
		return { cancel };
	}

	void starting.then(
		(flow) => {
			if (settled) return;
			opened.navigate(flow.auth_url);
			deadline = deadlineOf(flow.flow_expires_at);
			timer = setInterval(() => void pollOnce(flow.flow_id), intervalMs);
		},
		(error: unknown) => finish({ error: errorMessage(error) }),
	);

	return { cancel };
}

// codeBuddyLoginErrorFromForm surfaces the key schema's verdict on the OAuth block. Its paths
// (oauth_key_config, .refresh_token) are nested inside an object field with no input of its own
// on the OAuth tab — the bundle is written by the sign-in, not typed — so a FormMessage never
// renders them, and without this a refused save looks like a dead button.
export function codeBuddyLoginErrorFromForm(errors: unknown): string | undefined {
	const message = (path: readonly string[]): string | undefined => {
		let node: unknown = errors;
		for (const key of path) {
			if (!node || typeof node !== "object") return undefined;
			node = (node as Record<string, unknown>)[key];
		}
		return typeof node === "string" && node.trim() ? node : undefined;
	};
	return (
		message(["key", "oauth_key_config", "message"]) ??
		message(["key", "oauth_key_config", "grant_type", "message"]) ??
		message(["key", "oauth_key_config", "refresh_token", "message"])
	);
}

// codeBuddyLoginOAuthConfig is the form state a completed login writes: a browser_login bundle
// the save path keeps. token_url is derived from the provider's base_url, not from the login
// answer, which carries only tokens and an expiry.
export function codeBuddyLoginOAuthConfig(result: CodeBuddyLoginResult, baseURL?: string): OAuthKeyConfig {
	return {
		_auth_type: "oauth",
		grant_type: "browser_login",
		token_url: { value: codebuddyCNTokenURL(baseURL), ref: "" },
		access_token: { value: result.access_token, ref: "" },
		refresh_token: { value: result.refresh_token, ref: "" },
		expires_at: result.expires_at,
	};
}

// codeBuddyLoginPendingOAuthConfig is what choosing the OAuth tab seeds before any sign-in: the
// grant and the token URL the completed bundle will carry, so the only thing still missing is a
// refresh token and the form can say exactly that.
export function codeBuddyLoginPendingOAuthConfig(baseURL?: string): OAuthKeyConfig {
	return {
		_auth_type: "oauth",
		grant_type: "browser_login",
		token_url: { value: codebuddyCNTokenURL(baseURL), ref: "" },
	};
}

// codeBuddyLoginAPIKeyModeConfig is what switching back to the API-key tab writes. Replacing the
// block rather than deleting fields is what clears the three token fields in one write: the
// discriminator makes the save path drop the block, and the key rule then sees one credential.
export function codeBuddyLoginAPIKeyModeConfig(): Pick<OAuthKeyConfig, "_auth_type"> {
	return { _auth_type: "api_key" };
}

// codeBuddyLoginAuthMode reads the connected tab off a stored key. The discriminator is not
// re-seeded after a form reset, so a stored key is judged by its credential when it is absent.
// Partial because form state is exactly that: a key can carry only the tab discriminator.
export function codeBuddyLoginAuthMode(config: Partial<OAuthKeyConfig> | undefined): "api_key" | "oauth" {
	if (!config) return "api_key";
	if (config._auth_type === "api_key") return "api_key";
	if (config._auth_type === "oauth") return "oauth";
	const rest = { ...config };
	delete rest._auth_type;
	return codebuddyCNOAuthComplete(rest) ? "oauth" : "api_key";
}