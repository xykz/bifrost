package handlers

import (
	"context"
	"sync/atomic"

	"github.com/maximhq/bifrost/core/providers/codebuddycn"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/v2/bifrost-http/lib"
)

// credentialSinkInstallGen orders installs within this process. Each install takes a number and its
// uninstall clears the sink only while that number is still the latest, so server A shutting down
// after server B booted cannot take B's sink with it.
var credentialSinkInstallGen atomic.Uint64

// InstallCodeBuddyCredentialSink wires the provider's rotation callback to the config store and
// returns the function that uninstalls it. It is called once, at boot, from the place that already
// builds the provider handler, and the uninstall is called from the server's shutdown path.
//
// The returned func is idempotent and ownership-checked: calling it twice is a no-op, and calling
// it after a later install has replaced this sink leaves the later sink in place.
//
// The sink is process-wide rather than per provider on purpose: schemas.ProviderConfig is shared
// by every provider, and one CodeBuddy-specific field there would be paid by all of them. The
// callback therefore names the provider it is reporting for, and this function only has to know
// where that provider's keys live.
//
// The provider package cannot import handlers — handlers imports it — so the wiring lives here and
// the provider only exposes SetCredentialSink.
func InstallCodeBuddyCredentialSink(config *lib.Config) func() {
	noop := func() {}
	if config == nil {
		return noop
	}
	// Two servers in one process would otherwise silently share whichever sink booted last, and a
	// test that installs without uninstalling would leak one into the next case. Logged rather than
	// refused: the single-server boot that replaces a stale sink is exactly the case that must
	// still work.
	if codebuddycn.HasCredentialSink() && logger != nil {
		logger.Warn("replacing an already-installed codebuddy-cn credential sink; two servers in one process share one sink")
	}
	gen := credentialSinkInstallGen.Add(1)
	codebuddycn.SetCredentialSink(func(provider schemas.ModelProvider, keyID, accessToken, refreshToken, expiresAt string) {
		persistRotatedCredential(config, provider, keyID, accessToken, refreshToken, expiresAt)
	})
	return func() {
		// Ownership-checked: a later install owns the sink now, and clearing it would break that
		// server rather than this one. Compare-then-clear is safe against a concurrent install
		// because the generation only moves forward; the worst case is that one clear is skipped.
		if credentialSinkInstallGen.Load() != gen {
			return
		}
		codebuddycn.SetCredentialSink(nil)
	}
}

// persistRotatedCredential hands a rotation the provider just performed to the config store.
//
// This runs on the inference path, and under a token cache mutex: tokencache invokes onRotate while
// it holds that credential's slot lock (see BrowserLoginMinter's contract), so it must not block.
// Config.UpdateProviderKeyTokens therefore applies the token to memory synchronously and schedules
// the row write on a bounded goroutine (lib.TokenPersistTimeout). The request that triggered the
// mint is served as soon as the in-memory token is visible; the store catching up afterwards
// changes nothing the caller can observe.
//
// The write goes through Config.UpdateProviderKeyTokens and not Config.UpdateProviderKey: the
// latter rebuilds the provider's worker queue, which is right for an operator saving a key and
// wrong for a routine refresh. A store failure is logged rather than returned, so a restart after a
// failed write needs a re-login for that key instead of turning the failure into an inference
// outage. That durability trade-off is documented on UpdateProviderKeyTokens.
//
// An empty accessToken is the provider reporting that the upstream refused the token it was
// serving (a revoked-but-unexpired credential). applyProviderKeyTokens writes the empty value
// through, which is what stops resolveKey's stored-token fast path from offering it again.
func persistRotatedCredential(config *lib.Config, provider schemas.ModelProvider, keyID, accessToken, refreshToken, expiresAt string) {
	// context.Background rather than the request's context: tokencache runs the mint on a context
	// that already survives client disconnects (context.WithoutCancel), so a rotation must land even
	// if the client that happened to trigger it hangs up. The background write applies its own
	// timeout.
	if err := config.UpdateProviderKeyTokens(context.Background(), provider, keyID, accessToken, refreshToken, expiresAt); err != nil {
		if logger != nil {
			logger.Warn("Failed to apply rotated codebuddy-cn credential for key %s of provider %s: %v", keyID, provider, err)
		}
	}
}
