import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { getErrorMessage } from "@/lib/store/apis/baseApi";
import { useLazyGetCodeBuddyLoginStatusQuery, useStartCodeBuddyLoginMutation } from "@/lib/store/apis/providersApi";
import { AlertTriangle, CheckCircle2, Loader2, RefreshCw, ShieldCheck, XCircle } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { startCodeBuddyLogin, type CodeBuddyLoginPopup, type CodeBuddyLoginResult } from "./codeBuddyLogin";

interface Props {
	open: boolean;
	// The provider the key belongs to. It is the API path segment, and the backend resolves the
	// login target from that provider's own configuration.
	provider: string;
	onOpenChange: (open: boolean) => void;
	onSuccess: (result: CodeBuddyLoginResult) => void;
}

type Status = "confirm" | "polling" | "failed";

// The popup is opened here, from the click handler, before any request is made: browsers drop the
// click's user activation as soon as the handler awaits, and a window.open from that point is
// blocked without the admin ever seeing why.
const openPopup = (): CodeBuddyLoginPopup | null => {
	const width = 600;
	const height = 700;
	const left = window.screen.width / 2 - width / 2;
	const top = window.screen.height / 2 - height / 2;
	const popup = window.open(
		"about:blank",
		"codebuddy_login",
		`width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes`,
	);
	if (!popup) return null;
	return {
		get closed() {
			return popup.closed;
		},
		close: () => {
			if (!popup.closed) popup.close();
		},
		navigate: (url) => {
			popup.location.href = url;
		},
	};
};

const STATUS_ICON = {
	confirm: <ShieldCheck className="size-4" />,
	polling: <Loader2 className="size-4 animate-spin" />,
	failed: <XCircle className="size-4" />,
} as const;

export function CodeBuddyLoginModal({ open, provider, onOpenChange, onSuccess }: Props) {
	const [status, setStatus] = useState<Status>("confirm");
	const [errorMessage, setErrorMessage] = useState<string | null>(null);
	const [startLogin] = useStartCodeBuddyLoginMutation();
	const [getLoginStatus] = useLazyGetCodeBuddyLoginStatusQuery();
	const runRef = useRef<{ cancel: () => void } | null>(null);
	// The lazy trigger returns a subscription that keeps the result in the cache. Polling for up
	// to fifteen minutes would pile one up every two seconds, so the previous one is dropped
	// before the next tick and the last one when the dialog closes.
	const pollSubscriptionRef = useRef<{ unsubscribe: () => void } | null>(null);

	const stop = useCallback(() => {
		pollSubscriptionRef.current?.unsubscribe();
		pollSubscriptionRef.current = null;
		runRef.current?.cancel();
		runRef.current = null;
	}, []);

	// Dismissing the dialog (escape, the close button, cancel) ends the flow: the popup closes
	// and no late poll can write into a form the admin has moved on from.
	const handleDismiss = useCallback(() => {
		stop();
		setStatus("confirm");
		setErrorMessage(null);
		onOpenChange(false);
	}, [onOpenChange, stop]);

	useEffect(() => {
		if (open) return;
		stop();
		setStatus("confirm");
		setErrorMessage(null);
	}, [open, stop]);

	useEffect(() => stop, [stop]);

	const signIn = () => {
		stop();
		setErrorMessage(null);
		setStatus("polling");
		runRef.current = startCodeBuddyLogin({
			openPopup,
			start: async () => {
				try {
					return await startLogin({ provider }).unwrap();
				} catch (error) {
					// The state machine reports whatever message it is given, and an RTK error
					// object does not carry one on its own.
					throw new Error(getErrorMessage(error));
				}
			},
			// preferCacheValue=false: every tick must reach the server, or a pending answer
			// would be replayed from the cache forever.
			poll: (flowId) => {
				pollSubscriptionRef.current?.unsubscribe();
				const subscription = getLoginStatus({ provider, flowId }, false);
				pollSubscriptionRef.current = subscription;
				return subscription.unwrap();
			},
			onResult: (result) => {
				if ("error" in result) {
					setStatus("failed");
					setErrorMessage(result.error);
					return;
				}
				stop();
				onSuccess(result);
				onOpenChange(false);
			},
		});
	};

	return (
		<Dialog
			open={open}
			onOpenChange={(next) => {
				if (!next) handleDismiss();
			}}
		>
			<DialogContent
				data-testid="codebuddy-login-dialog"
				className="gap-0 overflow-hidden p-0 sm:max-w-md"
				onInteractOutside={(e) => {
					e.preventDefault();
					handleDismiss();
				}}
				onEscapeKeyDown={(e) => {
					e.preventDefault();
					handleDismiss();
				}}
			>
				<DialogHeader className="border-b px-5 py-4 text-left">
					<div className="flex items-start gap-3">
						<div className="bg-muted text-muted-foreground mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-sm">
							{STATUS_ICON[status]}
						</div>
						<div className="min-w-0 space-y-0.5">
							<DialogTitle className="text-sm leading-snug font-medium">
								{status === "failed" ? "Sign-in failed" : "Sign in to CodeBuddy"}
							</DialogTitle>
							<DialogDescription className="text-xs leading-relaxed">
								{status === "polling"
									? "Complete the sign-in in the popup window. This dialog updates on its own."
									: status === "failed"
										? "The CodeBuddy sign-in did not complete."
										: "A popup opens on Tencent's sign-in page. The tokens it returns are saved with this key when you click Save."}
							</DialogDescription>
						</div>
					</div>
				</DialogHeader>

				<div className="space-y-3 px-5 py-4">
					{status === "confirm" && (
						<div className="flex justify-end gap-2">
							<Button type="button" size="sm" variant="outline" onClick={handleDismiss} data-testid="codebuddy-login-cancel">
								Cancel
							</Button>
							<Button type="button" size="sm" onClick={signIn} data-testid="codebuddy-login-sign-in">
								<CheckCircle2 className="size-3.5" />
								Sign in
							</Button>
						</div>
					)}

					{status === "polling" && (
						<div className="flex items-center justify-between">
							<p className="text-muted-foreground flex items-center gap-2 text-xs">
								<Loader2 className="size-3.5 animate-spin" />
								Waiting for sign-in…
							</p>
							<Button type="button" size="sm" variant="outline" onClick={handleDismiss} data-testid="codebuddy-login-cancel">
								Cancel
							</Button>
						</div>
					)}

					{status === "failed" && (
						<>
							<div className="bg-destructive/5 border-destructive/30 flex items-start gap-2 rounded-md border p-3">
								<AlertTriangle className="text-destructive mt-0.5 size-4 shrink-0" />
								<p className="text-destructive text-sm" data-testid="codebuddy-login-error">
									{errorMessage ?? "Check the provider's base URL and try again."}
								</p>
							</div>
							<div className="flex justify-end gap-2">
								<Button type="button" size="sm" variant="outline" onClick={handleDismiss} data-testid="codebuddy-login-cancel">
									Close
								</Button>
								<Button type="button" size="sm" onClick={signIn} data-testid="codebuddy-login-retry">
									<RefreshCw className="size-3.5" />
									Retry
								</Button>
							</div>
						</>
					)}
				</div>
			</DialogContent>
		</Dialog>
	);
}