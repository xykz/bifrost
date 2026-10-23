# CodeBuddy CN Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Tencent CodeBuddy (China, `copilot.tencent.com`) as a first-class Bifrost provider, with keys authenticated either by a pasted API key or by a browser login performed from the Bifrost UI.

**Architecture:** An OpenAI-compatible provider package (`core/providers/codebuddycn/`) that delegates request/response shaping to the existing `openai` helpers, adding only CodeBuddy's editor-identity headers and auth-header choice. Credentials reuse the existing `oauth_key_config` on `schemas.Key` behind a new `browser_login` grant, so no database migration is needed; refresh is a `tokencache.Minter` that exchanges a refresh token for an access token. Two transport endpoints drive an upstream device-style login flow held server-side, which the key form's modal polls.

**Tech Stack:** Go 1.27.3 (multi-module workspace: `core`, `framework`, `transports`), `fasthttp`, `sonic`, `bytedance/sonic`, `tidwall/gjson`, `tokencache`, React 19 + TypeScript + TanStack Router + RTK Query + zod v4 + react-hook-form, vitest, Playwright.

**Spec:** `docs/superpowers/specs/2026-10-22-codebuddy-cn-provider-design.md`

## Global Constraints

- Provider identifier string is exactly `codebuddy-cn`; Go constant is `schemas.CodeBuddyCN`.
- Base URL default: `https://copilot.tencent.com`. Login state path `/v2/plugin/auth/state?platform=CLI`; token poll `/v2/plugin/auth/token?state=<state>`; refresh `/v2/plugin/auth/token/refresh`; inference `/v2/chat/completions`.
- Refresh sends the refresh token in the **`X-Refresh-Token` header**, body `{}`, and `X-Product: SaaS`.
- Inference headers: `X-Product: SaaS`, `X-IDE-Type: CLI`, `X-IDE-Name: CodeBuddy`, `X-IDE-Version: 0.0.0`, plus `Authorization: Bearer <token>` for OAuth keys or `X-API-Key: <value>` for pasted keys.
- Login pending signal is HTTP 200 with body `code: 11217`; success is `code: 0` with `data.accessToken`/`data.refreshToken`/`data.expiresIn`. Dead refresh token is HTTP 401 or `code: 12153`.
- Refresh margin is 60 seconds before `expires_at`.
- Go filenames: no underscores except `_test.go`. Tests go in the package's existing test file, never a new one.
- Every change to a shared file is an additive branch (`case`, allowlist entry, struct field). Never rewrite a shared function body.
- Provider `Provider` interface methods that CodeBuddy does not support return `providerUtils.NewUnsupportedOperationError(<operation>, "codebuddy-cn")`.
- `CodeBuddyCN` must be added to `StandardProviders`, `CanProviderKeyValueBeEmpty`, and `ProviderSupportsOAuthKeyConfig`.
- Do not send `stream` differently from the caller: pass it through. A live probe (Task 4) confirms upstream accepts both.
- Login endpoints require an authenticated admin session; without one they return 403 via the existing `isAuthBypassed(ctx)` guard.
- The login upstream endpoint derives from the provider's `network_config.base_url`, never from a request body or query parameter.

## Review Focus

1. **A token refreshed concurrently by two requests on the same key.** Expected: exactly one upstream refresh exchange; the second caller reuses the cached access token, never burning or invalidating a rotated refresh token.
2. **A config.json-managed key whose token refreshed at runtime.** Expected: reconciliation does not see a "changed" key and overwrite the refreshed credential with the file's stale one.
3. **A `codebuddy-cn` key with both `value` and `oauth_key_config` set, or neither.** Expected: a validation error naming the conflict at save time, not a confusing upstream 401 at first inference.
4. **A GET of a key holding an OAuth bundle.** Expected: both tokens masked; a subsequent PUT echoing those masks resolves to the stored values rather than storing mask text.
5. **The login poll outliving the popup, or the admin closing the modal mid-flow.** Expected: polling stops, no goroutine leaks, and a later poll of the same flow returns a terminal state rather than hanging.

---

## File Structure

**Create**
- `core/providers/codebuddycn/codebuddycn.go` — provider struct, constructor, `Provider` interface surface, credential resolution.
- `core/providers/codebuddycn/credentials.go` — the `tokencache.Minter` for `browser_login`; expiry decision; refresh exchange.
- `core/providers/codebuddycn/headers.go` — editor-identity and auth header construction; base URL defaults.
- `core/providers/codebuddycn/errors.go` — `code`/`msg` envelope → `*schemas.BifrostError`.
- `core/providers/codebuddycn/models.go` — static model catalog.
- `core/providers/codebuddycn/codebuddycn_test.go` — unit tests for the package.
- `core/providers/codebuddycn/credentials_test.go` — unit tests for refresh + expiry (separate because `credentials.go` is the highest-risk file).
- `transports/bifrost-http/handlers/codebuddylogin.go` — the two login endpoints and the flow store.
- `transports/bifrost-http/handlers/codebuddylogin_test.go` — handler tests.
- `ui/app/workspace/providers/views/codeBuddyLoginModal.tsx` — the login modal.
- `ui/app/workspace/providers/views/codeBuddyLoginModal.test.tsx` — modal test.
- `ui/lib/schemas/providerForm.codebuddy.test.ts` — zod cases.
- `docs/providers/supported-providers/codebuddy-cn.mdx` — provider documentation.

**Modify**
- `core/schemas/bifrost.go` — `CodeBuddyCN` constant, `StandardProviders` entry.
- `core/schemas/account.go` — `OAuthGrantBrowserLogin` constant; three `OAuthKeyConfig` fields; `Validate`, `Redacted` branches.
- `core/providers/utils/tokencache/oauthkey.go` — `MinterForConfig` branch, `validateConfig` branch, cache-key branch.
- `core/bifrost.go` — provider construction case.
- `core/utils.go` — two allowlists.
- `framework/configstore/clientconfig.go` — `oauthKeyConfigHashView` excludes rotating state.
- `transports/bifrost-http/handlers/provider_keys.go` — two entries in the mask-preserve loop.
- `transports/bifrost-http/handlers/providers.go` — register the two login routes.
- `transports/config.schema.json` — provider entry plus enum entry (two locations).
- `transports/bifrost-http/integrations` — no change required; verified in Task 9.
- `ui/lib/constants/config.ts`, `ui/lib/constants/icons.tsx`, `ui/lib/constants/logs.ts` — provider presence.
- `ui/lib/types/schemas.ts`, `ui/lib/schemas/providerForm.ts` — key config shape and cross-field rule.
- `ui/app/workspace/providers/fragments/apiKeysFormFragment.tsx` — the OAuth login block.
- `ui/lib/store/services/providersApi.ts` (path verified in Task 10) — two endpoints.
- `docs/openapi/openapi.json` — provider + endpoints spec.
- `docs/docs.json` — navigation entry.

---

### Task 1: Provider identity and the `browser_login` grant shape

**Files:**
- Modify: `core/schemas/bifrost.go` (constant block near line 58, `StandardProviders` near line 100)
- Modify: `core/schemas/account.go:1068-1110` (`OAuthKeyConfig`, `Redacted`), `:1042-1048` (grant consts), `:1124-1180` (`Validate`)
- Modify: `core/utils.go:79-81`, `:247-250`
- Test: `core/schemas/account_test.go` (extend existing file; create only if absent)

**Interfaces:**
- Produces: `schemas.CodeBuddyCN` (`ModelProvider = "codebuddy-cn"`); `schemas.OAuthGrantBrowserLogin` (`OAuthGrantType = "browser_login"`); `OAuthKeyConfig.AccessToken *SecretVar`, `.RefreshToken *SecretVar`, `.ExpiresAt string`.
- Consumes: nothing.

- [ ] **Step 1: Write the failing test**

In `core/schemas/account_test.go` (the file is `package schemas`, so call `NewSecretVar` unqualified):

```go
func TestOAuthKeyConfigBrowserLoginGrant(t *testing.T) {
	valid := &OAuthKeyConfig{
		GrantType:    OAuthGrantBrowserLogin,
		TokenURL:     *NewSecretVar("https://copilot.tencent.com/v2/plugin/auth/token/refresh"),
		AccessToken:  NewSecretVar("access-abc"),
		RefreshToken: NewSecretVar("refresh-xyz"),
		ExpiresAt:    "2026-10-22T12:00:00Z",
	}
	require.NoError(t, valid.Validate())

	noTokenURL := *valid
	noTokenURL.TokenURL = SecretVar{}
	require.ErrorContains(t, noTokenURL.Validate(), "token_url is required")

	// browser_login must not demand client_credentials or jwt_bearer fields.
	require.Nil(t, valid.ClientID)
	require.Nil(t, valid.PrivateKey)

	plainHTTP := *valid
	plainHTTP.TokenURL = *NewSecretVar("http://copilot.tencent.com/v2/plugin/auth/token/refresh")
	require.ErrorContains(t, plainHTTP.Validate(), "must be https")
}

func TestOAuthKeyConfigRedactedMasksBrowserLoginTokens(t *testing.T) {
	cfg := &OAuthKeyConfig{
		GrantType:    OAuthGrantBrowserLogin,
		TokenURL:     *NewSecretVar("https://copilot.tencent.com/v2/plugin/auth/token/refresh"),
		AccessToken:  NewSecretVar("access-abc"),
		RefreshToken: NewSecretVar("refresh-xyz"),
	}
	got := cfg.Redacted()
	require.NotEqual(t, "access-abc", got.AccessToken.GetValue())
	require.NotEqual(t, "refresh-xyz", got.RefreshToken.GetValue())
	require.True(t, got.AccessToken.IsMaskedPlaceholder())
	require.True(t, got.RefreshToken.IsMaskedPlaceholder())
	// The original must be untouched: Redacted returns a copy.
	require.Equal(t, "access-abc", cfg.AccessToken.GetValue())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd core && go test ./schemas/ -run 'TestOAuthKeyConfigBrowserLogin|TestOAuthKeyConfigRedactedMasksBrowserLogin' -v`
Expected: FAIL — `undefined: OAuthGrantBrowserLogin`, and the `AccessToken` field does not exist.

- [ ] **Step 3: Add the constant, the fields, and the branches**

In `core/schemas/bifrost.go` add to the const block, alphabetically near `Cohere`:

```go
CodeBuddyCN ModelProvider = "codebuddy-cn"
```

and to `StandardProviders` (keep the list's existing alphabetical order):

```go
CodeBuddyCN,
```

In `core/schemas/account.go`, after `OAuthGrantJWTBearer`:

```go
// OAuthGrantBrowserLogin is an interactive browser login: the operator signs in once in the
// dashboard, and the durable credential is a refresh token that mints short-lived access
// tokens. The token endpoint is a refresh endpoint, so client_id/client_secret are not used.
OAuthGrantBrowserLogin OAuthGrantType = "browser_login"
```

Add the three fields to `OAuthKeyConfig` after `AuthStyle`:

```go
AccessToken  *SecretVar `json:"access_token,omitempty"`  // browser_login: short-lived bearer, refreshed before use
RefreshToken *SecretVar `json:"refresh_token,omitempty"` // browser_login: durable credential that mints access tokens
ExpiresAt    string     `json:"expires_at,omitempty"`    // browser_login: RFC3339 expiry; empty means refresh on use
```

In `Redacted()`, alongside the existing masks:

```go
cfg.AccessToken = cfg.AccessToken.Redacted()
cfg.RefreshToken = cfg.RefreshToken.Redacted()
```

In `Validate()`'s `switch c.GrantType`, add a case:

```go
case OAuthGrantBrowserLogin:
	if !has(c.RefreshToken) {
		return fmt.Errorf("oauth_key_config.refresh_token is required for the browser_login grant")
	}
	if c.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, c.ExpiresAt); err != nil {
			return fmt.Errorf("oauth_key_config.expires_at must be RFC3339")
		}
	}
```

and extend the final `default:` message to name all three grants.

In `core/utils.go`:

```go
func CanProviderKeyValueBeEmpty(providerKey schemas.ModelProvider) bool {
	return providerKey == schemas.Vertex || ... || providerKey == schemas.GithubCopilot || providerKey == schemas.CodeBuddyCN
}

func ProviderSupportsOAuthKeyConfig(providerKey schemas.ModelProvider) bool {
	return providerKey == schemas.OpenAI || providerKey == schemas.CodeBuddyCN
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd core && go test ./schemas/ -run 'TestOAuthKeyConfigBrowserLogin|TestOAuthKeyConfigRedactedMasksBrowserLogin' -v`
Expected: PASS. Also run `cd core && go build ./...` — the `OAuthGrantBrowserLogin` case must not break `MinterForConfig`, which currently has no branch for it (that is Task 3; a temporary `default` returning a clear "unsupported grant" error is acceptable until then).

- [ ] **Step 5: Commit**

```bash
git add core/schemas/bifrost.go core/schemas/account.go core/schemas/account_test.go core/utils.go
git commit -m "feat(schemas): add codebuddy-cn provider id and browser_login oauth grant"
```

---

### Task 2: Refresh flow as a `tokencache.Minter`

**Files:**
- Modify: `core/providers/utils/tokencache/oauthkey.go:65-200` (`MinterForConfig`, `validateConfig`, `oauthKeyCacheKey`)
- Create: `core/providers/utils/tokencache/browserlogin.go`
- Test: `core/providers/utils/tokencache/oauthkey_test.go` (extend the existing file — the package already has `oauthkey_test.go`, `clientcredentials_test.go`, `jwtbearer_test.go`; do not create a new one)

**Interfaces:**
- Consumes: `schemas.OAuthGrantBrowserLogin`, `OAuthKeyConfig.AccessToken`/`.RefreshToken`/`.ExpiresAt` from Task 1.
- Produces: `func BrowserLoginMinter(cfg *schemas.OAuthKeyConfig, hc *http.Client, onRotate func(accessToken, refreshToken string, expiresAt time.Time)) Minter[string]`; `func refreshCodeBuddyToken(ctx context.Context, hc *http.Client, refreshURL, refreshToken string) (accessToken, newRefreshToken string, expiresIn time.Duration, bErr *schemas.BifrostError)`. `MinterForConfig` routes `browser_login` to `BrowserLoginMinter(cfg, hc, nil)`.
- Does **not** modify `tokencache.Entry`: rotation is delivered through the `onRotate` callback, not a new struct field.

- [ ] **Step 1: Write the failing test**

Extend `core/providers/utils/tokencache/oauthkey_test.go` (`package tokencache`) with a fake refresh server:

```go
func TestBrowserLoginMinterRefreshesAndRotates(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.Equal(t, "POST", r.Method)
		// The refresh token travels in the header, never the body.
		require.Equal(t, "refresh-1", r.Header.Get("X-Refresh-Token"))
		require.Equal(t, "SaaS", r.Header.Get("X-Product"))
		body, _ := io.ReadAll(r.Body)
		require.JSONEq(t, "{}", string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-2","refreshToken":"refresh-2","expiresIn":3600}}`))
	}))
	defer srv.Close()

	cfg := &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(srv.URL),
		RefreshToken: schemas.NewSecretVar("refresh-1"),
	}
	cache := New[string](Options{})
	headers, bErr := ResolveBearerFrom(context.Background(), cache, *cfg, srv.Client())
	require.Nil(t, bErr)
	require.Equal(t, "Bearer access-2", headers["Authorization"])
	require.EqualValues(t, 1, calls.Load())

	// A second call within the token's lifetime must not hit the network.
	_, bErr = ResolveBearerFrom(context.Background(), cache, *cfg, srv.Client())
	require.Nil(t, bErr)
	require.EqualValues(t, 1, calls.Load(), "warm token must not re-refresh")
}

func TestBrowserLoginMinterDeadRefreshTokenIsPermanent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":12153,"msg":"refresh token expired"}`))
	}))
	defer srv.Close()

	cfg := &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(srv.URL),
		RefreshToken: schemas.NewSecretVar("dead"),
	}
	_, bErr := ResolveBearerFrom(context.Background(), New[string](Options{}), *cfg, srv.Client())
	require.NotNil(t, bErr)
	require.Equal(t, http.StatusUnauthorized, *bErr.StatusCode)
	require.False(t, *bErr.AllowFallbacks, "a dead credential must not fall back")
	require.Contains(t, bErr.Error.Message, "re-authenticate")
}

func TestBrowserLoginMinterConcurrentCallersRefreshOnce(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-release // hold the first exchange open so the others pile up behind it
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-x","refreshToken":"refresh-x","expiresIn":3600}}`))
	}))
	defer srv.Close()
	cfg := schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(srv.URL),
		RefreshToken: schemas.NewSecretVar("refresh-0"),
	}
	cache := New[string](Options{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = ResolveBearerFrom(context.Background(), cache, cfg, srv.Client())
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	require.EqualValues(t, 1, calls.Load(), "concurrent callers must share one refresh")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd core && go test ./providers/utils/tokencache/ -run 'TestBrowserLoginMinter' -v`
Expected: FAIL — the minter returns an "unsupported grant" error, so `bErr` is non-nil.

- [ ] **Step 3: Implement the minter**

Create `core/providers/utils/tokencache/browserlogin.go`:

```go
// BrowserLoginMinter exchanges a refresh token for an access token. The refresh token rides
// in the X-Refresh-Token header (the endpoint ignores the body), and a successful exchange
// usually returns a rotated refresh token. Rotation is reported through onRotate, which may
// be nil: tokencache.Entry has no metadata channel, and adding one would change a struct
// every provider's cache shares.
func BrowserLoginMinter(cfg *schemas.OAuthKeyConfig, hc *http.Client, onRotate func(accessToken, refreshToken string, expiresAt time.Time)) Minter[string]
```

Behaviour the test pins:
- Send `POST` to `cfg.TokenURL` with body `{}`, headers `Content-Type: application/json`, `Accept: application/json`, `X-Product: SaaS`, `X-Refresh-Token: <refresh>`.
- Parse `{code, msg, data:{accessToken, refreshToken, expiresIn}}`.
- `code != 0` → `*schemas.BifrostError`; `code == 12153` or HTTP 401 → `StatusCode` 401, `AllowFallbacks = &false`, message mentioning "re-authenticate".
- Success → `&Entry[string]{Value: data.accessToken, ExpiresAt: now.Add(expiresIn)}`, with `RefreshAt` set to `ExpiresAt.Add(-60 * time.Second)` (the spec's refresh margin) so the cache mints before upstream expiry rather than after.
- A missing or non-positive `expiresIn` falls back to 2 minutes, so an unreported expiry cannot pin a dead token forever.
- Before returning, call `onRotate(accessToken, rotatedRefreshToken, expiresAt)` when it is non-nil; `rotatedRefreshToken` is the upstream value when present, else the original.

Add the dispatch in `MinterForConfig`:

```go
case schemas.OAuthGrantBrowserLogin:
	return cacheKey, BrowserLoginMinter(cfg, hc, nil), nil
```

Add to `validateConfig` a `browser_login` branch requiring a non-empty resolved refresh token, and to `oauthKeyCacheKey` hash the refresh token (so two keys with different refresh tokens never share a cache slot).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd core && go test ./providers/utils/tokencache/ -run 'TestBrowserLoginMinter' -v`
Expected: PASS, all three tests. Then `cd core && go test ./providers/utils/tokencache/` — the pre-existing OAuth tests must still pass.

- [ ] **Step 5: Commit**

```bash
git add core/providers/utils/tokencache/
git commit -m "feat(tokencache): browser_login grant refreshes codebuddy tokens"
```

---

### Task 3: ConfigHash excludes rotating credential state

**Files:**
- Modify: `framework/configstore/clientconfig.go:1138-1150` (`oauthKeyConfigHashView`)
- Test: `framework/configstore/clientconfig_test.go` (extend the existing file; if `generateKeyHash`/OAuth hashing is tested elsewhere, extend that file)

**Interfaces:**
- Consumes: the three new `OAuthKeyConfig` fields from Task 1.
- Produces: no new API; a behaviour guarantee other tasks rely on.

- [ ] **Step 1: Write the failing test**

```go
func TestOAuthKeyConfigHashIgnoresRotatingTokenState(t *testing.T) {
	base := schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar("https://copilot.tencent.com/v2/plugin/auth/token/refresh"),
		AccessToken:  schemas.NewSecretVar("access-1"),
		RefreshToken: schemas.NewSecretVar("refresh-1"),
		ExpiresAt:    "2026-10-22T12:00:00Z",
	}
	rotated := base
	rotated.AccessToken = schemas.NewSecretVar("access-2")
	rotated.ExpiresAt = "2026-10-22T13:00:00Z"

	keyA := schemas.Key{ID: "k1", Name: "cb", Value: schemas.SecretVar{}, OAuthKeyConfig: &base}
	keyB := schemas.Key{ID: "k1", Name: "cb", Value: schemas.SecretVar{}, OAuthKeyConfig: &rotated}

	h1, err := configstore.GenerateKeyHash(keyA)
	require.NoError(t, err)
	h2, err := configstore.GenerateKeyHash(keyB)
	require.NoError(t, err)
	require.Equal(t, h1, h2, "a refreshed token must not look like a config change")

	// But a genuinely different declared credential must change the hash.
	other := base
	other.RefreshToken = schemas.NewSecretVar("refresh-other-source")
	keyC := schemas.Key{ID: "k1", Name: "cb", Value: schemas.SecretVar{}, OAuthKeyConfig: &other}
	h3, err := configstore.GenerateKeyHash(keyC)
	require.NoError(t, err)
	require.NotEqual(t, h1, h3)
}
```

`configstore.GenerateKeyHash(key schemas.Key) (string, error)` is already exported — no test-only helper and no new export is needed.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd framework && go test ./configstore/ -run TestOAuthKeyConfigHashIgnoresRotatingTokenState -v`
Expected: FAIL — `h1 != h2`, because `AccessToken` and `ExpiresAt` currently feed the hash.

- [ ] **Step 3: Blank the rotating fields in the hash view**

In `oauthKeyConfigHashView`, after the existing `view.TokenURL`/`ClientID`/... lines:

```go
// browser_login credentials rotate at runtime: every refresh replaces the access token and
// its expiry. Those are state, not declared configuration, so they are blanked here. The
// refresh token is reduced to its source marker so a config.json-managed key is not seen as
// changed (and overwritten from file) every time a refresh lands.
view.AccessToken = nil
view.ExpiresAt = ""
if cfg.RefreshToken != nil {
	view.RefreshToken = source(cfg.RefreshToken)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd framework && go test ./configstore/ -run TestOAuthKeyConfigHashIgnoresRotatingTokenState -v`
Expected: PASS. Then `cd framework && go test ./configstore/ -run 'Hash'` — existing hash tests must still pass.

- [ ] **Step 5: Commit**

```bash
git add framework/configstore/clientconfig.go framework/configstore/clientconfig_test.go
git commit -m "fix(configstore): keep rotating oauth tokens out of ConfigHash"
```

---

### Task 4: Provider package — headers, chat, models, errors

**Files:**
- Create: `core/providers/codebuddycn/codebuddycn.go`, `headers.go`, `errors.go`, `models.go`
- Modify: `core/bifrost.go` (provider construction switch)
- Test: `core/providers/codebuddycn/codebuddycn_test.go`

**Interfaces:**
- Consumes: `schemas.CodeBuddyCN`, `OAuthGrantBrowserLogin`, `tokencache.ResolveBearerFrom` (Tasks 1–2).
- Produces: `codebuddycn.NewCodeBuddyCNProvider(config *schemas.ProviderConfig, logger schemas.Logger) (*CodeBuddyCNProvider, error)`; `type CodeBuddyCNProvider struct` satisfying `schemas.Provider`; unexported `func (p *CodeBuddyCNProvider) resolveKey(ctx context.Context, key schemas.Key) (schemas.Key, *schemas.BifrostError)`; `func authHeaderFor(key schemas.Key, accessToken string) map[string]string`; `func editorHeaders() map[string]schemas.SecretVar`.

- [ ] **Step 1: Write the failing test**

```go
func TestEditorHeadersCarryCLIIdentity(t *testing.T) {
	h := editorHeaders()
	require.Equal(t, "SaaS", h["X-Product"].GetValue())
	require.Equal(t, "CLI", h["X-IDE-Type"].GetValue())
	require.Equal(t, "CodeBuddy", h["X-IDE-Name"].GetValue())
	require.Equal(t, "0.0.0", h["X-IDE-Version"].GetValue())
}

func TestAuthHeaderForUsesAPIKeyHeaderForPastedKeys(t *testing.T) {
	// A pasted API key goes in X-API-Key; a bearer there is rejected by the gateway with an
	// HTML 401 from APISIX before credential validation ever runs.
	got := authHeaderFor(schemas.Key{Value: *schemas.NewSecretVar("sk-pasted")}, "")
	require.Equal(t, "sk-pasted", got["X-API-Key"])
	require.NotContains(t, got, "Authorization")
}

func TestAuthHeaderForUsesBearerForOAuthKeys(t *testing.T) {
	got := authHeaderFor(schemas.Key{}, "access-abc")
	require.Equal(t, "Bearer access-abc", got["Authorization"])
	require.NotContains(t, got, "X-API-Key")
}

func TestProviderRejectsUnsupportedOperations(t *testing.T) {
	p, err := codebuddycn.NewCodeBuddyCNProvider(&schemas.ProviderConfig{}, bifrost.NewNoOpLogger())
	require.NoError(t, err)
	require.Equal(t, schemas.CodeBuddyCN, p.GetProviderKey())

	_, bErr := p.Embedding(context.Background(), schemas.Key{}, &schemas.BifrostEmbeddingRequest{})
	require.NotNil(t, bErr)
	require.Contains(t, bErr.Error.Message, "is not supported by")
}

// providerUtils.NewUnsupportedOperationError(requestType schemas.RequestType, providerName
// schemas.ModelProvider) produces "<requestType> is not supported by <providerName> provider"
// with Error.Code == "unsupported_operation". Pass schemas.EmbeddingRequest and
// schemas.CodeBuddyCN; use the matching request-type constant for every other unsupported
// method.

func TestDefaultBaseURL(t *testing.T) {
	cfg := &schemas.ProviderConfig{}
	_, err := codebuddycn.NewCodeBuddyCNProvider(cfg, bifrost.NewNoOpLogger())
	require.NoError(t, err)
	require.Equal(t, "https://copilot.tencent.com", cfg.NetworkConfig.BaseURL)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd core && go test ./providers/codebuddycn/ -v`
Expected: FAIL — the package does not exist.

- [ ] **Step 3: Implement the package**

`headers.go`:

```go
// editorHeaders returns the identity headers CodeBuddy requires. Requests without them are
// treated as generic API clients and refused before inference.
func editorHeaders() map[string]schemas.SecretVar

// authHeaderFor chooses the credential header: a pasted key travels in X-API-Key, an OAuth
// access token in Authorization. Verified against the live gateway: a bogus X-API-Key reaches
// credential validation, while a bogus bearer is rejected by APISIX with an HTML 401.
func authHeaderFor(key schemas.Key, accessToken string) map[string]string
```

`codebuddycn.go` — mirror `groq.go`'s structure exactly:
- Struct fields: `logger`, `client`, `streamingClient`, `networkConfig`, `sendBackRawRequest`, `sendBackRawResponse`, `authHTTPClient *http.Client`, `tokens *tokencache.Cache[string]`, `pendingPersist *schemas.BifrostContext`-free sink (see below).
- Constructor: build the client, `ConfigureProxy`/`ConfigureDialer`/`ConfigureTLS`, `BuildStreamingClient`, default `BaseURL` to `https://copilot.tencent.com`, trim trailing `/`.
- `resolveKey(ctx, key)`: for a `browser_login` bundle, call `tokencache.BrowserLoginMinter(cfg, p.authHTTPClient, onRotate)` through the cache (single-flight, 60s margin), where `onRotate` records `{accessToken, refreshToken, expiresAt}` into a per-request sink read by the transport in Task 6; otherwise use the shared `ResolveBearerFrom`. Returns a key whose `Value` is the access token.
- `GetProviderKey()` returns `schemas.CodeBuddyCN`.
- `ListModels`: `openai.HandleOpenAIListModelsRequest` against `/v2/models`; if upstream 404s, return the static catalog from `models.go` (verified: `/v2/models` 404s, so the catalog path is the expected one).
- `ChatCompletion`: `openai.HandleOpenAIChatCompletionRequest` with URL `BaseURL + "/v2/chat/completions"`, `authHeaderFor(...)`, `editorHeaders()` merged into `extraHeaders`.
- `ChatCompletionStream`: `openai.HandleOpenAIChatCompletionStreaming`, same decoration, using `p.streamingClient`.
- Every other interface method: `providerUtils.NewUnsupportedOperationError(...)`.

The rotation sink is the mechanism the plan commits to: it is a value the transport installs on `schemas.ProviderConfig` before construction (a `func(provider schemas.ModelProvider, keyID string, accessToken, refreshToken string, expiresAt time.Time)` field), or, if `ProviderConfig` must stay untouched, a package-level `atomic.Pointer` setter in `codebuddycn` that the transport wires once at boot. Whoever implements it must not add a field to `tokencache.Entry`.

`errors.go`: parse `{"code":N,"msg":"..."}` and `{"message":"..."}`; map 401/`12153` → 401 non-fallback, everything else → 502 retriable. Include the upstream `code` and `msg` in the Bifrost error body.

`models.go`: a `[]string` catalog (e.g. `hunyuan-chat`, `deepseek-v3`, `glm-5.2`; the exact current ids are read from `GET /v2/plugin/models` with a live credential in Task 11 and pasted here). Unknown ids are passed through rather than rejected.

`codebuddycn_test.go` also gets the two benchmarks the spec's cost section requires:

```go
func BenchmarkAuthHeaderForStaticKey(b *testing.B) {
	key := schemas.Key{Value: *schemas.NewSecretVar("sk-pasted")}
	b.ReportAllocs()
	for b.Loop() {
		_ = authHeaderFor(key, "")
	}
}

func BenchmarkEditorHeaders(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = editorHeaders()
	}
}
```

`core/bifrost.go`: add the import and one case in the provider construction switch, next to `GithubCopilot`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd core && go test ./providers/codebuddycn/ -v`
Expected: PASS. Then `cd core && go build ./...`.

- [ ] **Step 5: Live probe — does upstream accept non-streaming?**

With a real credential exported as `CODEBUDDY_CN_API_KEY`, confirm both shapes:

```bash
curl -sS -X POST https://copilot.tencent.com/v2/chat/completions \
  -H "X-API-Key: $CODEBUDDY_CN_API_KEY" -H 'Content-Type: application/json' \
  -H 'X-Product: SaaS' -H 'X-IDE-Type: CLI' -H 'X-IDE-Name: CodeBuddy' -H 'X-IDE-Version: 0.0.0' \
  -d '{"model":"<catalog-id>","messages":[{"role":"user","content":"hi"}],"stream":false}' | head -c 400
```

Expected: a non-streaming chat completion JSON. If instead it returns an error rejecting non-stream requests, stop and implement the fallback from the spec ("Non-streaming and streaming"): force `stream: true`, drain the stream, fold chunks into a `BifrostChatResponse`, and add a unit test for the fold. Record which outcome held in the PR body.

- [ ] **Step 6: Commit**

```bash
git add core/providers/codebuddycn/ core/bifrost.go
git commit -m "feat(providers): add codebuddy-cn provider"
```

---

### Task 5: Registration in config schema and provider plumbing

**Files:**
- Modify: `transports/config.schema.json` (provider property block near line 745, `ModelProvider` enum near line 12790, **and the `oauth_key_config` block near line 6820**)
- Modify: `docs/openapi/openapi.json` (provider enum **and `oauth_key_config`/`oauth_key_config_response` schema parity** near line 128600)
- Test: `transports/bifrost-http/lib/validator_test.go` (extend)

**Interfaces:**
- Consumes: `schemas.CodeBuddyCN`; the `browser_login` grant and its three fields from Task 1.
- Produces: config.json accepts `codebuddy-cn` as a provider key, and accepts a `browser_login` `oauth_key_config`.

- [ ] **Step 1: Write the failing test**

```go
func TestConfigSchemaAcceptsCodeBuddyCN(t *testing.T) {
	cfg := `{
		"providers": {
			"codebuddy-cn": {
				"keys": [
					{
						"name": "default",
						"value": "env.CODEBUDDY_CN_API_KEY",
						"weight": 1.0,
						"models": ["*"]
					}
				]
			}
		}
	}`
	require.NoError(t, ValidateConfigSchema([]byte(cfg), loadLocalSchema(t)))
}

func TestConfigSchemaAcceptsBrowserLoginGrant(t *testing.T) {
	cfg := `{
		"providers": {
			"codebuddy-cn": {
				"keys": [
					{
						"name": "oauth",
						"weight": 1.0,
						"models": ["*"],
						"oauth_key_config": {
							"grant_type": "browser_login",
							"token_url": "https://copilot.tencent.com/v2/plugin/auth/token/refresh",
							"access_token": "env.CODEBUDDY_ACCESS_TOKEN",
							"refresh_token": "env.CODEBUDDY_REFRESH_TOKEN",
							"expires_at": "2026-10-22T12:00:00Z"
						}
					}
				]
			}
		}
	}`
	require.NoError(t, ValidateConfigSchema([]byte(cfg), loadLocalSchema(t)))
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd transports && go test ./bifrost-http/lib/ -run 'TestConfigSchemaAcceptsCodeBuddyCN|TestConfigSchemaAcceptsBrowserLoginGrant' -v`
Expected: FAIL — `codebuddy-cn` is not in the provider enum, and `browser_login` plus the three fields are rejected by the closed `oauth_key_config` block.

- [ ] **Step 3: Add the schema entries**

In `transports/config.schema.json`:

1. Next to `"github-copilot"`, add `"codebuddy-cn": { "$ref": "#/$defs/provider" }`.
2. Add `"codebuddy-cn"` to the `ModelProvider` enum array in alphabetical position.
3. In the `oauth_key_config` block, add `"browser_login"` to the `grant_type` enum, and add three properties alongside the existing ones:

```json
"access_token": {
  "type": "string",
  "minLength": 1,
  "description": "browser_login: short-lived bearer, refreshed before use"
},
"refresh_token": {
  "type": "string",
  "minLength": 1,
  "description": "browser_login: durable credential that mints access tokens"
},
"expires_at": {
  "type": "string",
  "description": "browser_login: RFC3339 expiry; omit to refresh on first use"
}
```

4. Add a fourth `allOf` entry requiring `refresh_token` when the grant is `browser_login`:

```json
{
  "if": { "properties": { "grant_type": { "const": "browser_login" } } },
  "then": { "required": ["refresh_token"] }
}
```

5. Re-examine `transports/bifrost-http/lib/validator_test.go`'s `TestSchemaOAuthKeyConfig` invalid case named `"unknown field"` at ~line 3775: it currently sends `refresh_token` as an unknown-field probe. That field is now legitimate, so repoint the probe at a field that is still unknown (for example `"not_a_field": "x"`) and say why in a comment.

In `docs/openapi/openapi.json`, mirror all five changes in the request shape and in `oauth_key_config_response` so the published spec matches `config.schema.json`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd transports && go test ./bifrost-http/lib/ -run 'TestConfigSchema|TestSchemaOAuthKeyConfig' -v`
Expected: PASS. Then `cd transports && go test ./bifrost-http/lib/` in full.

- [ ] **Step 5: Commit**

```bash
git add transports/config.schema.json transports/bifrost-http/lib/validator_test.go docs/openapi/openapi.json
git commit -m "feat(config): accept codebuddy-cn and the browser_login oauth grant"
```

---

### Task 6: Persist rotated tokens and preserve masks

**Files:**
- Modify: `transports/bifrost-http/handlers/provider_keys.go:766-800` (mask-preserve loop)
- Create: `transports/bifrost-http/handlers/codebuddycredential.go` — the credential sink
- Test: `transports/bifrost-http/handlers/provider_keys_test.go` (extend)

**Interfaces:**
- Consumes: the rotated refresh token/expiry surfaced by `resolveKey` (Task 4).
- Produces: `func (h *ProviderHandler) persistRotatedCredential(ctx context.Context, provider schemas.ModelProvider, keyID string, accessToken, refreshToken, expiresAt string) error`.

- [ ] **Step 1: Write the failing test**

Two tests, both in `provider_keys_test.go`:

```go
func TestUpdateProviderKeyResolvesMaskedOAuthTokens(t *testing.T) {
	// A GET returns masks; a PUT echoing them must resolve to the stored tokens rather than
	// persisting the mask text as a credential.
	// Arrange a stored key whose OAuthKeyConfig has AccessToken "access-stored" and
	// RefreshToken "refresh-stored". PUT a body carrying AccessToken/RefreshToken masks.
	// Assert the stored values are unchanged after the update.
}

func TestCodeBuddyCNAllowsEmptyValueWithOAuthBundle(t *testing.T) {
	// POST a key with value "" and a complete browser_login OAuthKeyConfig.
	// Expected: 200, not the "value is required" rejection.
}

func TestCodeBuddyCNRejectsBothAuthModes(t *testing.T) {
	// POST a key with both a pasted value and an OAuthKeyConfig.
	// Expected: 400 whose message names the conflict.
}
```

Fill these in against the file's existing fake-store helpers; the assertions above are the contract.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd transports && go test ./bifrost-http/handlers/ -run 'TestUpdateProviderKeyResolvesMaskedOAuthTokens|TestCodeBuddyCNAllowsEmptyValueWithOAuthBundle|TestCodeBuddyCNRejectsBothAuthModes' -v`
Expected: first test FAILS (mask text stored as the token); second may pass already via `CanProviderKeyValueBeEmpty`; third FAILS (no conflict check).

- [ ] **Step 3: Implement**

In `provider_keys.go`, inside the `if mergedKey.OAuthKeyConfig != nil {` block, add two entries to the existing `[]struct{...}` preserve slice:

```go
{mergedKey.OAuthKeyConfig.AccessToken, accessToken, "oauth_key_config.access_token"},
{mergedKey.OAuthKeyConfig.RefreshToken, refreshToken, "oauth_key_config.refresh_token"},
```

where `accessToken`/`refreshToken` are captured from `oldRawKey.OAuthKeyConfig` alongside the existing `tokenURL`/`clientID`/... locals.

Add the conflict rule where the provider's key is validated (same function as the existing GitHub Copilot branch, `case schemas.CodeBuddyCN:`):

```go
case schemas.CodeBuddyCN:
	if key.Value.GetValue() != "" && key.OAuthKeyConfig != nil {
		return fmt.Errorf("a codebuddy-cn key takes either a pasted api key or an oauth login, not both")
	}
	if key.Value.GetValue() == "" {
		if key.OAuthKeyConfig == nil || key.OAuthKeyConfig.GrantType != schemas.OAuthGrantBrowserLogin {
			return fmt.Errorf("codebuddy-cn key requires either value or oauth_key_config with grant_type browser_login")
		}
		if err := key.OAuthKeyConfig.Validate(); err != nil {
			return err
		}
	}
```

Create `codebuddylogin.go`'s companion `codebuddycredential.go` with `persistRotatedCredential`, which:
- Reads the current key via the in-memory store.
- If the stored refresh token already differs from the one being written, returns nil (another request already persisted a newer rotation — last-writer-wins is fine, but a stale write must not overwrite a new one).
- Otherwise calls `Config.UpdateProviderKey` with `BifrostContextKeySkipDBUpdate` absent, so the store is written, and does **not** trigger `Bifrost.UpdateProvider` — the next request re-reads keys via `GetKeysForProvider`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd transports && go test ./bifrost-http/handlers/ -run 'TestUpdateProviderKeyResolvesMaskedOAuthTokens|TestCodeBuddyCN' -v`
Expected: PASS. Then the whole package.

- [ ] **Step 5: Commit**

```bash
git add transports/bifrost-http/handlers/provider_keys.go transports/bifrost-http/handlers/provider_keys_test.go transports/bifrost-http/handlers/codebuddycredential.go
git commit -m "feat(handlers): persist rotated codebuddy tokens and preserve masked oauth fields"
```

---

### Task 7: Login endpoints

**Files:**
- Create: `transports/bifrost-http/handlers/codebuddylogin.go`
- Modify: `transports/bifrost-http/handlers/providers.go:243-266` (`RegisterRoutes`)
- Test: `transports/bifrost-http/handlers/codebuddylogin_test.go`

**Interfaces:**
- Consumes: `KVStore` from `lib.Config`, `isAuthBypassed(ctx)`, provider `network_config.base_url`.
- Produces: `POST /api/providers/{provider}/codebuddy-cn/login` → `{"flow_id":"…","auth_url":"…","expires_at":"…"}`; `GET /api/providers/{provider}/codebuddy-cn/login/{flow_id}` → `{"status":"pending"|"completed"|"failed", "access_token"?:…, "refresh_token"?:…, "expires_at"?:…, "error"?:…}`; `type codeBuddyLoginFlow struct`.

- [ ] **Step 1: Write the failing test**

```go
func TestCodeBuddyLoginStartRequiresAdminSession(t *testing.T) {
	// Auth bypassed → 403 naming the admin-session requirement.
}

func TestCodeBuddyLoginFlowTransitions(t *testing.T) {
	// Fake upstream: auth/state returns {state:"s1", authUrl:"https://x/login?state=s1"}.
	// token poll returns code 11217 twice, then code 0 with tokens.
	// Assert: start → 200 with auth_url; poll 1 → pending; poll 2 → pending; poll 3 →
	// completed with access_token and refresh_token; poll 4 (after completion) → the same
	// completed payload, not a hang and not a fresh upstream call.
}

func TestCodeBuddyLoginEndpointIsNotCallerDialable(t *testing.T) {
	// POST with {"endpoint":"https://evil.example"} in the body.
	// Expected: the upstream call still goes to the provider's base_url; the body field is
	// ignored. Assert the fake provider host received the request and no request reached the
	// attacker host.
}

func TestCodeBuddyLoginExpiredFlowIsGone(t *testing.T) {
	// Insert a flow with an expiry in the past; poll it.
	// Expected: 404 (or a terminal "failed" status), never a pending loop.
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd transports && go test ./bifrost-http/handlers/ -run TestCodeBuddyLogin -v`
Expected: FAIL — routes do not exist (404).

- [ ] **Step 3: Implement the handler**

`codebuddylogin.go`:
- `startLogin`: reject when `isAuthBypassed(ctx)` with 403 `"codebuddy login requires an authenticated admin session; enable dashboard authentication first"`. Resolve the provider base URL from config (never the body). `POST {base}/v2/plugin/auth/state?platform=CLI`. Store a flow in KVStore under `codebuddy:login:{flow_id}` with `{state, provider, expires_at}` and a 15-minute TTL. Return the `authUrl` from upstream plus an opaque `flow_id` (never the upstream `state`).
- `pollLogin`: load the flow; missing → 404. Call `GET {base}/v2/plugin/auth/token?state={state}`. `code 11217` → `{"status":"pending"}`. `code 0` → convert `data.expiresIn` to an RFC3339 absolute time, write `{"status":"completed", tokens…}` back to the flow with the remaining TTL, and return it. Anything else → `{"status":"failed","error":…}`, also written back so a repeat poll is terminal. Never return tokens before `code 0`.
- Use `KVStore.Get`/`SetWithTTL` so the flow survives across replicas.

In `RegisterRoutes`, after the refresh-models routes:

```go
r.POST("/api/providers/{provider}/codebuddy-cn/login", lib.ChainMiddlewares(h.startCodeBuddyLogin, middlewares...))
r.GET("/api/providers/{provider}/codebuddy-cn/login/{flow_id}", lib.ChainMiddlewares(h.pollCodeBuddyLogin, middlewares...))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd transports && go test ./bifrost-http/handlers/ -run TestCodeBuddyLogin -v`
Expected: PASS, all four.

- [ ] **Step 5: Commit**

```bash
git add transports/bifrost-http/handlers/codebuddylogin.go transports/bifrost-http/handlers/codebuddylogin_test.go transports/bifrost-http/handlers/providers.go
git commit -m "feat(handlers): codebuddy browser login endpoints"
```

---

### Task 8: UI — provider presence and form validation

**Files:**
- Modify: `ui/lib/constants/config.ts`, `ui/lib/constants/icons.tsx`, `ui/lib/constants/logs.ts`, `ui/lib/types/schemas.ts`, `ui/lib/schemas/providerForm.ts`
- Test: `ui/lib/schemas/providerForm.codebuddy.test.ts` (create; mirrors `providerForm.copilot.test.ts`)

**Interfaces:**
- Consumes: the API shape from Tasks 6–7.
- Produces: `codebuddyCNOAuthSchema`, `codebuddyCNOAuthComplete(cfg)` exported from `providerForm.ts` for the form fragment.

- [ ] **Step 1: Write the failing test**

```ts
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

  it("accepts an oauth-only key with an empty value", () => {
    expect(parse({ value: "", oauth_key_config: oauth() }).success).toBe(true);
  });

  it("accepts a pasted api key with no oauth config", () => {
    expect(parse({ value: "sk-pasted" }).success).toBe(true);
  });

  it("rejects a key with both auth modes", () => {
    const r = parse({ value: "sk-pasted", oauth_key_config: oauth() });
    expect(r.success).toBe(false);
  });

  it("rejects a key with neither auth mode", () => {
    const r = parse({ value: "", oauth_key_config: undefined });
    expect(r.success).toBe(false);
  });

  it("rejects an incomplete oauth bundle", () => {
    expect(parse({ value: "", oauth_key_config: oauth({ refresh_token: literal("") }) }).success).toBe(false);
  });
});
```

`parse` mirrors the copilot test's helper: `ProviderFormSchema.safeParse({selectedProvider:"codebuddy-cn", isDirty:true, networkConfig:DefaultNetworkConfig, keys:[{id:"k1", name:"cb", models:["*"], weight:1, ...overrides}]})`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ui && npx vitest run lib/schemas/providerForm.codebuddy.test.ts`
Expected: FAIL — `oauth_key_config` is stripped by the schema, so the oauth-only case fails.

- [ ] **Step 3: Implement**

- `ui/lib/constants/config.ts`: add `"codebuddy-cn": { modelPlaceholder: "hunyuan-chat", requiresKey: false }` following the file's existing entry shape.
- `ui/lib/constants/icons.tsx`: add a `codebuddy` icon entry.
- `ui/lib/constants/logs.ts`: add the display name `"CodeBuddy CN"` in both places the file keeps it.
- `ui/lib/types/schemas.ts`: extend the key config type with `oauth_key_config` fields `access_token`, `refresh_token`, `expires_at`.
- `ui/lib/schemas/providerForm.ts`: add `codebuddyCNOAuthSchema` and `codebuddyCNOAuthComplete(cfg)`; declare `oauth_key_config: codebuddyCNOAuthSchema.optional()` on the key object; in `superRefine`, add a `codebuddy-cn` branch enforcing exactly-one-of, mirroring the `github-copilot` branch at line 334.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ui && npx vitest run lib/schemas/providerForm.codebuddy.test.ts`
Expected: PASS, all five. Then `cd ui && npx vitest run lib/schemas/` — the copilot suite must still pass.

- [ ] **Step 5: Commit**

```bash
git add ui/lib/constants/ ui/lib/types/schemas.ts ui/lib/schemas/providerForm.ts ui/lib/schemas/providerForm.codebuddy.test.ts
git commit -m "feat(ui): register codebuddy-cn provider and validate its key auth modes"
```

---

### Task 9: UI — the login modal

**Files:**
- Create: `ui/app/workspace/providers/views/codeBuddyLoginModal.tsx`, `codeBuddyLoginModal.test.tsx`
- Modify: `ui/app/workspace/providers/fragments/apiKeysFormFragment.tsx`
- Modify: the RTK Query provider slice (locate with `grep -rn "useGetProvidersQuery" ui/lib/store/services/`)

**Interfaces:**
- Consumes: the two endpoints from Task 7; `codebuddyCNOAuthComplete` from Task 8.
- Produces: `<CodeBuddyLoginModal open onOpenChange onSuccess={(cfg) => void} />`; `useStartCodeBuddyLoginMutation`, `useGetCodeBuddyLoginStatusQuery`.

- [ ] **Step 1: Write the failing test**

```tsx
it("opens the popup synchronously, polls until completed, then closes and reports tokens", async () => {
  // Stub window.open to return a fake window object with a spy close().
  // Stub the start mutation to resolve {flow_id, auth_url}.
  // Stub the status query: pending, pending, completed.
  // Render the modal open, click "Sign in".
  // Assert: window.open was called before the start mutation resolved (it must be called in
  // the click handler, not after an await); the popup is closed on completion; onSuccess
  // received access_token and refresh_token.
});

it("stops polling and closes the popup when the modal is dismissed mid-flight", async () => {
  // Pending forever; close the modal; assert no further status requests and popup.close() called.
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ui && npx vitest run app/workspace/providers/views/codeBuddyLoginModal.test.tsx`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement**

- `codeBuddyLoginModal.tsx`: a Dialog matching the providers page's existing key-editing dialog. Button click handler calls `window.open("about:blank")` **synchronously** (before any `await`), then fires the start mutation, sets `popup.location = auth_url`, and begins polling the status query with `pollingInterval: 5000`, `skip` once terminal. On `completed`: close the popup, call `onSuccess` with the bundle, close the modal. On `failed`: render the error with a retry button. On dismiss: close the popup and stop polling. Copy the proven popup/polling mechanics from `ui/app/workspace/mcp-registry/views/oauth2Authorizer.tsx`, including its `initialPopup` pattern and `data-testid` conventions — but not its MCP API calls.
- `apiKeysFormFragment.tsx`: a `codebuddy-cn`-gated block offering "API key" and "OAuth login" modes; the OAuth mode shows connected state (expiry only — the login response carries no identity) plus a "Sign in" / "Re-authenticate" button that opens the modal and, on success, writes the tokens into form state via `setValue`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ui && npx vitest run app/workspace/providers/views/codeBuddyLoginModal.test.tsx`
Expected: PASS, both tests.

- [ ] **Step 5: Commit**

```bash
git add ui/app/workspace/providers/views/ ui/app/workspace/providers/fragments/apiKeysFormFragment.tsx ui/lib/store/services/
git commit -m "feat(ui): codebuddy browser login modal in the key form"
```

---

### Task 10: Docs, OpenAPI, and harness case

**Files:**
- Create: `docs/providers/supported-providers/codebuddy-cn.mdx`
- Modify: `docs/docs.json` (navigation), `docs/openapi/openapi.json`
- Modify: `tests/e2e/api/collections/provider-harness.json` (surgical insert)

**Interfaces:**
- Consumes: everything above.
- Produces: documentation and one harness case.

- [ ] **Step 1: Write the harness case first**

Insert (surgically, via a script that splices the object in — never a whole-file reserialize) two cases:
- `codebuddy-cn chat non-streaming` through `/v1/chat/completions` with `model: "codebuddy-cn/<catalog-id>"`, asserting `200` and a non-empty `choices[0].message.content`.
- `codebuddy-cn chat streaming` asserting `200`, `text/event-stream`, and at least one `data:` chunk with a `delta`.

Neither case may guard on status codes; assert the exact expected status and include `pm.response.text()` in failure messages.

- [ ] **Step 2: Validate the harness cases structurally**

```bash
node tests/e2e/api/runners/augment-provider-harness.mjs --source tests/e2e/api/collections/provider-harness.json --out tmp/harness-augmented.json
node tests/e2e/api/runners/filter-collection.mjs --source tmp/harness-augmented.json --out tmp/filtered.json --feature "codebuddy"
```

Expected: both commands exit 0 and the filtered collection contains both new cases. Confirm `git diff --stat` on the collection shows only the inserted lines, not a reformat.

- [ ] **Step 3: Write the provider doc**

`docs/providers/supported-providers/codebuddy-cn.mdx` with Web UI / API / config.json tabs, covering: the two auth modes, that the login is an admin action with one credential set per key shared by all traffic, the static model catalog, that a file-only deployment (`config_store.enabled: false`) cannot persist a rotation and therefore needs a re-login after restart-and-expiry, and how to re-authenticate when the refresh token dies.

- [ ] **Step 4: Update OpenAPI and navigation**

Add `codebuddy-cn` to `docs/openapi/openapi.json`'s provider enum and document the two login endpoints. Add the page to `docs/docs.json` under the supported-providers group.

- [ ] **Step 5: Verify the doc renders and the schema examples validate**

Run: `cd ui && npm run build`
Expected: build succeeds (also catches TypeScript errors from Tasks 8–9).

- [ ] **Step 6: Commit**

```bash
git add docs/ tests/e2e/api/collections/provider-harness.json
git commit -m "docs: codebuddy-cn provider page, openapi, and harness cases"
```

---

### Task 11: End-to-end verification

**Files:**
- Modify: `core/providers/codebuddycn/models.go` (real catalog ids, if live probing reveals different ones)
- Modify: `core/providers/codebuddycn/codebuddycn_test.go` (llmtests wiring)

**Interfaces:**
- Consumes: all prior tasks.
- Produces: a verified provider.

- [ ] **Step 1: Wire the standard llmtests entry point**

Add `TestCodeBuddyCN(t *testing.T)` in `codebuddycn_test.go` following `groq_test.go`: skip when `CODEBUDDY_CN_API_KEY` is empty, `llmtests.SetupTest()`, a `ComprehensiveTestConfig` with `Provider: schemas.CodeBuddyCN`, `ChatModel` set to a real catalog id, and a `Scenarios` block enabling `SimpleChat`, `SimpleChatStream`, `ToolCalls`, and disabling everything CodeBuddy does not support (text completion, embedding, speech, transcription, image, batch, files).

- [ ] **Step 2: Verify the model catalog against the live API**

```bash
curl -sS https://copilot.tencent.com/v2/plugin/models \
  -H "X-API-Key: $CODEBUDDY_CN_API_KEY" -H 'X-Product: SaaS' \
  -H 'X-IDE-Type: CLI' -H 'X-IDE-Name: CodeBuddy' -H 'X-IDE-Version: 0.0.0'
```

Update `models.go` to the ids actually returned. If the endpoint 404s, keep the static list and note in the PR that the catalog is hand-maintained.

- [ ] **Step 3: Run the provider test suite**

Run: `make test-core PROVIDER=codebuddy-cn`
Expected: PASS for chat, chat-stream, and tool calls.

- [ ] **Step 4: Run the broader suites**

Run: `make lint && make test-plugins`
Expected: PASS. Then `cd core && go test ./...` and `cd framework && go test ./configstore/` and `cd transports && go test ./bifrost-http/...`, confirming no other provider regressed.

- [ ] **Step 5: Commit**

```bash
git add core/providers/codebuddycn/
git commit -m "test(providers): codebuddy-cn llmtests wiring and live model catalog"
```

---

## Self-Review

**Spec coverage:** provider identity + registration (Tasks 1, 4, 5); `browser_login` credential shape and its six consequences (Tasks 1, 2, 3, 6); refresh strategy including the dead-token classification and the 60s margin (Tasks 2, 4); token persistence without a provider rebuild (Task 6); login flow, admin guard, non-caller-dialable endpoint, KVStore-backed flows, 15-minute TTL (Task 7); popup/poll/populate modal and expiry-only connected state (Task 9); UI provider presence and exactly-one-auth-mode (Task 8); static catalog with unknown-id passthrough (Task 4); stream pass-through with a live probe and a contained fallback (Task 4 Step 5); docs, OpenAPI, harness cases (Task 10); request-path cost and retained-memory claims (Task 11's benchmarks below).

One gap found and fixed inline: the spec's "Cost on the request path" section requires a `Benchmark*` for request-path code with before/after allocs in the PR body. Task 4 must add `BenchmarkAuthHeaderFor` and `BenchmarkResolveKeyWarm` to `codebuddycn_test.go` and record `-benchmem` output in the PR body; a static-key path must show zero new allocations against the pre-change baseline.

**Primary risk: the rotation sink.** The spec requires a refreshed token to persist without a provider rebuild, but `schemas.ProviderConfig` has no extension point for it and `tokencache.Entry` has no metadata channel. The plan picks one mechanism in Task 4 (a sink field on `ProviderConfig`, or a package-level setter in `codebuddycn` wired at boot) and Task 6 consumes it. The implementer must confirm the choice compiles against `ProviderConfig` before writing Task 6, and must not add a field to `Entry`.

**Step scan:** each step names a file, a signature, or a command with expected output. The places a body is specified (Task 1's `Validate` case, Task 3's hash view, Task 2's header/response contract) are exact copy the spec fixes.

**Type consistency:** `CodeBuddyCN`, `OAuthGrantBrowserLogin`, `AccessToken`/`RefreshToken`/`ExpiresAt`, `NewCodeBuddyCNProvider`, `editorHeaders`, `authHeaderFor`, `resolveKey`, `persistRotatedCredential`, `codebuddyCNOAuthSchema`/`codebuddyCNOAuthComplete`, `CodeBuddyLoginModal` — each is defined once and referenced with the same name and arity in later tasks.

**Review Focus tests mapped:** (1) concurrent refresh → Task 2 `TestBrowserLoginMinterConcurrentCallersRefreshOnce`; (2) reconciliation overwrite → Task 3; (3) both/neither auth mode → Tasks 6 and 8; (4) masked GET/PUT round-trip → Task 6; (5) modal dismissed mid-flight → Task 9.

**Proportion:** the plan is longer than the spec but carries no transcribed bodies beyond the two the spec fixes; most of its length is task boundaries, which the executor needs.
