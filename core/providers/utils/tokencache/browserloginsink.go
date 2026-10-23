package tokencache

import (
	"context"
	"net/http"
	"time"

	schemas "github.com/maximhq/bifrost/core/schemas"
)

// ResolveBearerFromWithSink is ResolveBearerFrom plus a rotation callback. The callback is handed
// to BrowserLoginMinter on the cold path only, so a warm request pays exactly what the plain entry
// point pays. browser_login is the only grant that rotates, so for the other grants onRotate is
// never invoked.
//
// onRotate may be nil, which is how ResolveBearerFrom delegates here: the two paths cannot drift,
// and a caller that owns persistence reaches the same cache, margin and error handling as one that
// does not.
func ResolveBearerFromWithSink(ctx context.Context, cache *Cache[string], cfg schemas.OAuthKeyConfig, hc *http.Client, onRotate func(accessToken, refreshToken string, expiresAt time.Time)) (map[string]string, *schemas.BifrostError) {
	// The minter is built only on the cold path: a warm request pays for the cache key and
	// the lookup, not for a clientcredentials.Config it will never use.
	cacheKey, bErr := validateConfig(&cfg)
	if bErr != nil {
		return nil, bErr
	}
	entry, bErr := cache.Get(ctx, cacheKey, func(ctx context.Context, prev *Entry[string]) (*Entry[string], *schemas.BifrostError) {
		_, mint, bErr := minterForConfig(&cfg, hc, onRotate)
		if bErr != nil {
			return nil, bErr
		}
		return mint(ctx, prev)
	})
	if bErr != nil {
		return nil, bErr
	}
	return map[string]string{"Authorization": "Bearer " + entry.Value}, nil
}
