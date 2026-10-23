package handlers

import (
	"context"

	"github.com/maximhq/bifrost/core/providers/codebuddycn"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/v2/bifrost-http/lib"
)

// InstallCodeBuddyCredentialSink wires the provider's rotation callback to the config store. It is
// called once, at boot, from the place that already builds the provider handler.
//
// The sink is process-wide rather than per provider on purpose: schemas.ProviderConfig is shared
// by every provider, and one CodeBuddy-specific field there would be paid by all of them. The
// callback therefore names the provider it is reporting for, and this function only has to know
// where that provider's keys live.
//
// The provider package cannot import handlers — handlers imports it — so the wiring lives here and
// the provider only exposes SetCredentialSink.
func InstallCodeBuddyCredentialSink(config *lib.Config) {
	if config == nil {
		return
	}
	codebuddycn.SetCredentialSink(func(provider schemas.ModelProvider, keyID, accessToken, refreshToken, expiresAt string) {
		persistRotatedCredential(config, provider, keyID, accessToken, refreshToken, expiresAt)
	})
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
