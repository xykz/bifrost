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

// persistRotatedCredential writes a rotation the provider just performed. It deliberately does not
// return an error to the caller: the mint already succeeded and the request that triggered it is
// about to be served, so failing it would turn a persistence problem into an inference outage.
// The loss is loud in the log instead, and the consequence is bounded — the credential degrades to
// a re-login rather than to a retry storm.
//
// A refresh runs on the inference path, which is why the write goes through
// Config.UpdateProviderKeyTokens and not Config.UpdateProviderKey: the latter rebuilds the
// provider's worker queue, which is right for an operator saving a key and wrong here.
func persistRotatedCredential(config *lib.Config, provider schemas.ModelProvider, keyID, accessToken, refreshToken, expiresAt string) {
	// context.Background rather than a request context: the cache runs the mint on a detached
	// context (tokencache.Cache.Get uses context.WithoutCancel), so the rotation outlives the client
	// that happened to trigger it, and the write must not be cancelled halfway for the same reason.
	ctx := context.Background()
	if err := config.UpdateProviderKeyTokens(ctx, provider, keyID, accessToken, refreshToken, expiresAt); err != nil {
		if logger != nil {
			logger.Warn("Failed to persist rotated codebuddy-cn credential for key %s of provider %s: %v", keyID, provider, err)
		}
	}
}
