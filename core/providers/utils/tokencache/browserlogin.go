package tokencache

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	schemas "github.com/maximhq/bifrost/core/schemas"
)

const (
	// browserLoginFallbackLifetime is assumed when the refresh endpoint reports no expires_in.
	browserLoginFallbackLifetime = 2 * time.Minute
	// browserLoginProduct is the X-Product value the refresh endpoint requires.
	browserLoginProduct = "SaaS"
	// deadRefreshTokenCode is the endpoint's "this refresh token is gone" code.
	deadRefreshTokenCode = 12153
	// browserLoginRequestBody is the entire request body: the token rides in a header.
	browserLoginRequestBody = "{}"
)

// browserLoginResponse is the refresh endpoint's envelope: a numeric code stands in for the
// HTTP status, and the minted token sits under data.
type browserLoginResponse struct {
	Code int                  `json:"code"` // 0 on success, any other value is a refusal
	Msg  string               `json:"msg"`  // Human-readable detail for a refusal
	Data browserLoginTokenSet `json:"data"` // The minted token, present when Code is 0
}

// browserLoginTokenSet is the payload of a successful refresh.
type browserLoginTokenSet struct {
	AccessToken  string `json:"accessToken"`  // Bearer token for inference
	RefreshToken string `json:"refreshToken"` // Rotated durable credential
	ExpiresIn    int64  `json:"expiresIn"`    // Access token lifetime in seconds
}

// BrowserLoginMinter returns a Minter that exchanges the config's refresh token for an access
// token. The refresh token rides in the X-Refresh-Token header (the endpoint ignores the body),
// and a successful exchange usually returns a rotated refresh token. Rotation is reported
// through onRotate, which may be nil: tokencache.Entry has no metadata channel, and adding one
// would change a struct every provider's cache shares.
//
// cfg must have passed validateConfig; MinterForConfig is the only caller and validates first.
// The endpoint and refresh token are read once, when the minter is built on the cold path, so
// a mint costs one request and no per-call field resolution.
//
// onRotate runs before the entry is returned, so a caller that persists the rotated refresh
// token has stored it by the time the request that triggered the mint proceeds. It runs while
// the cache holds the slot mutex, so it must not block: callers for the same credential wait
// behind it. A nil callback is the normal case for a key whose refresh token is not rotated
// back into storage.
func BrowserLoginMinter(cfg *schemas.OAuthKeyConfig, hc *http.Client, onRotate func(accessToken, refreshToken string, expiresAt time.Time)) Minter[string] {
	refreshURL := strings.TrimSpace(cfg.TokenURL.GetValue())
	refreshToken := secret(cfg.RefreshToken)
	// Bounded first, then guarded: a nil client gets the fallback timeout and the redirect policy.
	hc = guardRedirects(exchangeClient(hc))
	return func(ctx context.Context, _ *Entry[string]) (*Entry[string], *schemas.BifrostError) {
		accessToken, rotated, expiresIn, bErr := refreshCodeBuddyToken(ctx, hc, refreshURL, refreshToken)
		if bErr != nil {
			return nil, bErr
		}
		// RefreshAt sits a minute before expiry so the cache mints during the refresh margin,
		// not after the upstream has already started rejecting the token.
		expiresAt := time.Now().Add(expiresIn)
		if rotated == "" {
			rotated = refreshToken
		}
		if onRotate != nil {
			onRotate(accessToken, rotated, expiresAt)
		}
		return &Entry[string]{
			Value:     accessToken,
			ExpiresAt: expiresAt,
			RefreshAt: expiresAt.Add(-DefaultRefreshMargin),
		}, nil
	}
}

// refreshCodeBuddyToken performs one refresh exchange. The wire is CodeBuddy's own rather than
// RFC 6749: the durable credential travels in an X-Refresh-Token header, X-Product names the
// product family, the body is an empty JSON object, and the minted fields arrive under a data
// envelope whose numeric code is the real status. expiresIn is the endpoint's lifetime, or
// browserLoginFallbackLifetime when it reported none or a non-positive one: trusting an
// unknown lifetime would keep a dead token in the cache indefinitely.
//
// The rotated refresh token is returned as-is; delivering it is the caller's business, since
// Entry has no room for it.
func refreshCodeBuddyToken(ctx context.Context, hc *http.Client, refreshURL, refreshToken string) (accessToken, newRefreshToken string, expiresIn time.Duration, bErr *schemas.BifrostError) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL, strings.NewReader(browserLoginRequestBody))
	if err != nil {
		return "", "", 0, configurationError("oauth browser_login refresh request could not be built: " + err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Product", browserLoginProduct)
	req.Header.Set("X-Refresh-Token", refreshToken)

	resp, err := hc.Do(req)
	if err != nil {
		return "", "", 0, transportError(refreshURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if err != nil {
		return "", "", 0, providerUtils.NewProviderAPIError(
			fmt.Sprintf("oauth browser_login refresh response from %s could not be read", redactURL(refreshURL)),
			sanitizeTransportError(refreshURL, err), 0, nil, nil)
	}

	var parsed browserLoginResponse
	_ = sonic.Unmarshal(body, &parsed)
	msg := strings.TrimSpace(parsed.Msg)
	// A 401 and the documented dead-token code both mean the durable credential is gone: no
	// retry and no fallback provider repairs it, only a new sign-in does.
	if resp.StatusCode == http.StatusUnauthorized || parsed.Code == deadRefreshTokenCode {
		return "", "", 0, deadRefreshTokenError(refreshURL, scrubSubmitted(msg, []string{refreshToken}))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		bErr := tokenEndpointError(refreshURL, resp.StatusCode, scrubSubmitted(msg, []string{refreshToken}))
		providerUtils.ApplyRetryAfterHTTP(bErr, resp.Header)
		return "", "", 0, bErr
	}
	if parsed.Code != 0 {
		return "", "", 0, refreshCodeError(refreshURL, parsed.Code, scrubSubmitted(msg, []string{refreshToken}))
	}
	if parsed.Data.AccessToken == "" {
		return "", "", 0, emptyTokenError(refreshURL, resp.StatusCode)
	}
	expiresIn = time.Duration(parsed.Data.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = browserLoginFallbackLifetime
	}
	return parsed.Data.AccessToken, parsed.Data.RefreshToken, expiresIn, nil
}

// deadRefreshTokenError is the permanent failure for a refresh token the endpoint will not
// accept again. It carries 401, the status the client receives, and blocks fallbacks: another
// provider cannot repair this key, and a silent failover would hide the dead credential behind
// a working fallback until the whole lane was failing. The message names the action the
// operator has to take, since nothing on the request path can.
func deadRefreshTokenError(refreshURL, detail string) *schemas.BifrostError {
	if detail == "" {
		detail = "(no detail)"
	}
	bErr := providerUtils.NewProviderAPIError(
		fmt.Sprintf("the browser_login refresh token for %s was rejected (%s); re-authenticate to obtain a new one",
			redactURL(refreshURL), detail),
		nil, http.StatusUnauthorized, nil, nil)
	bErr.AllowFallbacks = schemas.Ptr(false)
	return bErr
}

// refreshCodeError is a 2xx answer carrying a non-zero code: the endpoint refused the exchange
// without an HTTP status to say why. 502 keeps the failure transient, since an unknown refusal
// may be a temporary upstream condition; the cache then retries after a short backoff instead
// of pinning the key as permanently broken.
func refreshCodeError(refreshURL string, code int, detail string) *schemas.BifrostError {
	if detail == "" {
		detail = "(no detail)"
	}
	return providerUtils.NewProviderAPIError(
		fmt.Sprintf("oauth browser_login refresh to %s failed (code %d): %s", redactURL(refreshURL), code, detail),
		nil, http.StatusBadGateway, nil, nil)
}
