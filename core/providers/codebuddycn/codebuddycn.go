// Package codebuddycn implements the Tencent CodeBuddy (China) provider.
//
// CodeBuddy exposes an OpenAI-compatible chat completions API at
// https://copilot.tencent.com/v2, so request and response shaping is delegated wholesale to
// the openai package. Three things make it unlike the other OpenAI-compatible providers:
//
//   - Every inference call must carry editor-identity headers. The gateway refuses requests
//     that look like generic API clients, so X-Product and the X-IDE-* trio travel on all of
//     them.
//   - The credential header depends on the auth mode: a pasted API key goes in X-API-Key,
//     while a browser-login access token goes in Authorization. A bearer carrying a pasted
//     key is rejected by the APISIX front end before credential validation ever runs.
//   - Access tokens are short-lived. A browser_login key holds a durable refresh token, and
//     resolveKey refreshes it through the shared token cache before the request is shaped.
//
// There is no published model catalogue: the gateway serves none to an unauthenticated
// caller, so ListModels answers with the pinned catalog in models.go when the live listing
// 404s. Unknown model ids are passed through untouched.
package codebuddycn

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/providers/openai"
	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/providers/utils/tokencache"
	schemas "github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
)

const (
	// defaultBaseURL is the CN gateway. The /v2 API root lives under it, so paths below start
	// with /v2 and a deployment pointing elsewhere points base_url at the host root.
	defaultBaseURL = "https://copilot.tencent.com"
	// chatCompletionsPath is the only inference surface this provider serves.
	chatCompletionsPath = "/v2/chat/completions"
	// modelsPath is the live catalogue. It 404s today, which is why the pinned catalog is the
	// expected answer rather than a fallback of last resort.
	modelsPath = "/v2/models"
	// maxAccessTokenLifetime is the longest access-token life this code will trust from a stored
	// expiry. The endpoint reports 3600s, and its own fallback when it reports none is 2 minutes, so
	// 24 hours leaves a wide margin for a longer-lived future deployment while still bounding the
	// damage a hand-written, copied, or clock-skewed expiry can do: a token with a far-future
	// expiry would otherwise pin a revoked credential until an operator edited the key.
	//
	// It is not a correctness knob. Exceeding it only means one extra mint, which is safe.
	maxAccessTokenLifetime = 24 * time.Hour
)

// CodeBuddyCNProvider implements the Provider interface for Tencent CodeBuddy (China).
type CodeBuddyCNProvider struct {
	logger              schemas.Logger               // Logger for provider operations
	client              *fasthttp.Client             // HTTP client for unary API requests (ReadTimeout bounds overall response)
	streamingClient     *fasthttp.Client             // HTTP client for streaming API requests (no ReadTimeout; idle governed by NewIdleTimeoutReader)
	networkConfig       schemas.NetworkConfig        // Network configuration including extra headers
	sendBackRawRequest  bool                         // Whether to include raw request in BifrostResponse
	sendBackRawResponse bool                         // Whether to include raw response in BifrostResponse
	authHTTPClient      *http.Client                 // Client for browser_login token refreshes, routed through proxy_config
	tokens              *tokencache.Cache[string]    // Access tokens minted from oauth_key_config, one slot per credential
	requestHeaders      map[string]schemas.SecretVar // Editor identity merged over network_config.extra_headers, built once
}

// NewCodeBuddyCNProvider creates a new CodeBuddy CN provider instance.
// It initializes the HTTP client with the provided configuration and sets up response pools.
// The client is configured with timeouts, concurrency limits, and optional proxy settings.
func NewCodeBuddyCNProvider(config *schemas.ProviderConfig, logger schemas.Logger) (*CodeBuddyCNProvider, error) {
	config.CheckAndSetDefaults()

	requestTimeout := time.Second * time.Duration(config.NetworkConfig.DefaultRequestTimeoutInSeconds)
	client := &fasthttp.Client{
		ReadTimeout:         requestTimeout,
		WriteTimeout:        requestTimeout,
		MaxConnsPerHost:     config.NetworkConfig.MaxConnsPerHost,
		MaxIdleConnDuration: time.Second * time.Duration(config.NetworkConfig.KeepAliveTimeoutInSeconds),
		MaxConnWaitTimeout:  requestTimeout,
		MaxConnDuration:     time.Second * time.Duration(schemas.DefaultMaxConnDurationInSeconds),
		ConnPoolStrategy:    fasthttp.FIFO,
	}

	// Configure proxy and retry policy
	client = providerUtils.ConfigureProxy(client, config.ProxyConfig, logger)
	client = providerUtils.ConfigureDialer(client, config.NetworkConfig.AllowPrivateNetwork)
	client = providerUtils.ConfigureTLS(client, config.NetworkConfig, logger)
	streamingClient := providerUtils.BuildStreamingClient(client)
	// Set default BaseURL if not provided
	if config.NetworkConfig.BaseURL == "" {
		config.NetworkConfig.BaseURL = defaultBaseURL
	}
	config.NetworkConfig.BaseURL = strings.TrimRight(config.NetworkConfig.BaseURL, "/")

	return &CodeBuddyCNProvider{
		logger:              logger,
		client:              client,
		streamingClient:     streamingClient,
		networkConfig:       config.NetworkConfig,
		sendBackRawRequest:  config.SendBackRawRequest,
		sendBackRawResponse: config.SendBackRawResponse,
		authHTTPClient:      providerUtils.NewProviderHTTPClient(config.ProxyConfig, config.NetworkConfig, logger),
		tokens:              tokencache.New[string](tokencache.Options{}),
		requestHeaders:      mergeExtraHeaders(config.NetworkConfig.ExtraHeaders),
	}, nil
}

// mergeExtraHeaders layers the editor identity over the operator's network headers. Editor
// values win: a wrong X-IDE-Version or X-Product breaks every request before credential
// validation, so an extra_headers entry must not silently shadow one. The context's per-request
// extra headers still override both, which is the escape hatch when a deployment really does
// need a different value.
//
// The result is built once per provider and shared: NetworkConfig is copied at construction and
// nothing on the request path mutates it, so a request pays no map allocation for its headers.
func mergeExtraHeaders(networkHeaders map[string]schemas.SecretVar) map[string]schemas.SecretVar {
	headers := make(map[string]schemas.SecretVar, len(networkHeaders)+len(editorHeaderValues))
	maps.Copy(headers, networkHeaders)
	for name, value := range editorHeaders() {
		headers[name] = value
	}
	return headers
}

// resolveKey returns key unchanged when it carries a pasted value or no oauth_key_config,
// otherwise a copy whose Value is the access token minted for that config. Every entry point
// resolves at entry, so the rest of the provider — including the shared openai helpers — keeps
// reading key.Value and needs no knowledge of OAuth. A pasted key costs two comparisons and no
// allocation here.
//
// A browser_login key normally carries the access token a previous refresh minted, together with
// its expiry. While that token is still outside the refresh margin it is used as-is: the returned
// key is that token in Value. This is not an optimisation, it is what makes rotation compatible
// with the cache. tokencache keys a credential by a hash that includes the refresh token, so after
// a rotation the next request would miss, mint, and rotate again — one refresh per inference
// request, forever. The stored access token is the one rotation-stable artefact, and the config
// records when it dies (ExpiresAt), so the freshness decision is two string comparisons.
//
// Past the margin, or with no stored token, the exchange is
// tokencache.ResolveBearerFromWithSink: single-flight, the 60s refresh margin, the negative cache
// and the dead-token classification stay the cache's. A rotation it sees is delivered to the
// process-wide sink, which the transport installs to persist it; with no sink installed the
// rotation is discarded, so a Go SDK caller still resolves but cannot keep one. The closure is
// created only on that branch, so the pasted-value path above never pays for it.
//
// A minted key costs the credential's cache-key hash plus one cache lookup on the warm path;
// the minter is built only when the token is actually due.
func (p *CodeBuddyCNProvider) resolveKey(ctx context.Context, key schemas.Key) (schemas.Key, *schemas.BifrostError) {
	// Trimmed, as validateKey and key selection treat a whitespace-only value as no value.
	if key.OAuthKeyConfig == nil || strings.TrimSpace(key.Value.GetValue()) != "" {
		return key, nil
	}
	// iat is read once and shared: the expiry check and the sink's timestamp then agree, and the
	// path takes one clock read instead of three.
	iat := time.Now()
	if token := storedAccessToken(*key.OAuthKeyConfig, iat); token != "" {
		key.Value = schemas.SecretVar{Val: token, SecretType: schemas.SecretTypePlainText}
		return key, nil
	}
	headers, bErr := tokencache.ResolveBearerFromWithSink(ctx, p.tokens, *key.OAuthKeyConfig, p.authHTTPClient, p.rotationCallback(key.ID))
	if bErr != nil {
		return key, bErr
	}
	// Assigned as a plain value rather than through NewSecretVar: the token is not a reference,
	// and parsing it as one would both misread a JSON-shaped token and allocate on a path that
	// otherwise does not.
	key.Value = schemas.SecretVar{Val: strings.TrimPrefix(headers[authorizationHeader], bearerPrefix), SecretType: schemas.SecretTypePlainText}
	return key, nil
}

// storedAccessToken returns the access token recorded on cfg when it may be used as-is, or "" when
// it must be minted instead. The decision is two comparisons and no allocation.
//
// Only browser_login qualifies. That grant is the one whose access token this provider persists,
// and it is the only grant for which Validate permits a stored token to be meaningful. A
// client_credentials or jwt_bearer key may carry an access_token anyway (Validate ignores the field
// for those grants), and honouring it would send an operator's pasted value instead of minting.
//
// Freshness reuses tokencache's margin arithmetic, so a token the cache would consider due is not
// trusted here either — including a token whose lifetime was shorter than the margin, which the
// cache keeps for the rest of its life rather than re-minting per request.
//
// An empty ExpiresAt means "refresh on use" — the field's documented contract — so a token without
// one is not used. An expiry further out than maxAccessTokenLifetime is refused as well.
func storedAccessToken(cfg schemas.OAuthKeyConfig, now time.Time) string {
	if cfg.GrantType != schemas.OAuthGrantBrowserLogin {
		return ""
	}
	token := strings.TrimSpace(cfg.AccessToken.GetValue())
	if token == "" {
		return ""
	}
	expiresAt := strings.TrimSpace(cfg.ExpiresAt)
	if expiresAt == "" {
		return ""
	}
	deadline, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		// An unparseable expiry is a configuration fault the management API refuses; treating it
		// as stale costs one mint and lets the next successful refresh replace it, whereas
		// trusting it would pin a token of unknown age.
		return ""
	}
	// A self-declared expiry is not a trust boundary: a hand-written, copied, or clock-skewed
	// value must not pin a revoked token indefinitely. Beyond the cap the token is ignored and
	// minted, which is always safe — the refresh token is still the credential.
	if deadline.Sub(now) > maxAccessTokenLifetime {
		return ""
	}
	if !tokencache.RefreshAt(deadline, now, tokencache.DefaultRefreshMargin).Before(now) {
		return token
	}
	return ""
}

// rotationCallback builds the sink closure for one key, or nil when no sink is installed. It is
// only called on the OAuth branch, so a non-OAuth request never allocates it.
//
// The provider names itself and the key names itself: the sink is process-wide, and it must know
// which row to write. The expiry is formatted here, once, because that is the shape the config
// stores and the only clock the sink can trust is the one the minter used.
func (p *CodeBuddyCNProvider) rotationCallback(keyID string) func(accessToken, refreshToken string, expiresAt time.Time) {
	if currentCredentialSink() == nil {
		return nil
	}
	return func(accessToken, refreshToken string, expiresAt time.Time) {
		sink := currentCredentialSink()
		if sink == nil {
			// Cleared between this request deciding to persist and the rotation landing. Dropping
			// the rotation is the honest outcome: nothing is installed to receive it.
			return
		}
		sink(p.GetProviderKey(), keyID, accessToken, refreshToken, expiresAt.UTC().Format(time.RFC3339))
	}
}

// extraHeaders returns the editor identity plus the operator's network headers, which the
// shared openai helpers apply with SetExtraHeaders. Editor values sit in that map rather than in
// the authHeader map, so nothing on the auth path can drop them; context extra headers still
// override both, as they do for every provider.
//
// Cost: one map per provider, built at construction, so a request reads a shared map.
func (p *CodeBuddyCNProvider) extraHeaders() map[string]schemas.SecretVar {
	return p.requestHeaders
}

// GetProviderKey returns the provider identifier for CodeBuddy CN.
func (p *CodeBuddyCNProvider) GetProviderKey() schemas.ModelProvider {
	return schemas.CodeBuddyCN
}

// ListModels performs a list models request to CodeBuddy's API, answering with the pinned
// catalog when the live listing is absent. It cannot use HandleOpenAIListModelsRequest: that
// helper builds its own Authorization header from key.Value, whereas a pasted key has to travel
// in X-API-Key and the editor headers must ride along on the listing too.
func (p *CodeBuddyCNProvider) ListModels(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostListModelsRequest) (*schemas.BifrostListModelsResponse, *schemas.BifrostError) {
	unfiltered := request != nil && request.Unfiltered
	// The gateway never reaches this branch: core's getAllSupportedKeys fails a ListModels request
	// before any provider method runs when a keyed provider has no usable keys, and codebuddy-cn is
	// keyed. A direct caller of the Provider interface — a Go SDK integration, or a caller inside
	// core that resolves keys itself — can still pass an empty slice, and for those the pinned
	// catalog is the right answer rather than a "no key" error, so the branch stays.
	if len(keys) == 0 {
		return providerUtils.HandleKeylessListModelsRequest(p.GetProviderKey(), func() (*schemas.BifrostListModelsResponse, *schemas.BifrostError) {
			return catalogListModelsResponse(schemas.WhiteList{"*"}, nil, nil, unfiltered), nil
		})
	}
	return providerUtils.HandleMultipleListModelsRequests(ctx, keys, request, p.listModelsByKey)
}

// listModelsByKey fetches the live catalogue for one key and filters it through the standard
// list-models pipeline so the key's allowlist, blacklist and aliases apply.
//
// The pinned catalog answers whenever the live listing cannot be produced: the gateway serves no
// catalogue today (404), and a 200 whose body the shared converter cannot read carries no model
// information either — an HTML interstitial or a maintenance page is not a decode bug the caller
// can act on. Any other failure is reported, because a 5xx or a rejected credential is a real
// upstream condition the caller should see rather than have masked by a static list.
func (p *CodeBuddyCNProvider) listModelsByKey(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostListModelsRequest) (*schemas.BifrostListModelsResponse, *schemas.BifrostError) {
	resolved, bErr := p.resolveKey(ctx, key)
	if bErr != nil {
		return nil, bErr
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	providerUtils.SetExtraHeaders(ctx, req, p.extraHeaders(), nil)
	req.SetRequestURI(p.networkConfig.BaseURL + providerUtils.GetPathFromContext(ctx, modelsPath))
	req.Header.SetMethod(http.MethodGet)
	req.Header.SetContentType("application/json")
	for name, value := range authHeaderFor(key, resolved.Value.GetValue()) {
		req.Header.Set(name, value)
	}

	latency, bErr, wait := providerUtils.MakeRequestWithContext(ctx, p.client, req, resp)
	defer wait()
	if bErr != nil {
		return nil, providerUtils.SetErrorLatency(bErr, latency)
	}
	ctx.SetValue(schemas.BifrostContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))

	// Read the body before branching on status so the catalog answer can record it exactly as the
	// live-listing path does; a decode failure here is itself a "no listing" answer.
	body, bodyErr := providerUtils.CheckAndDecodeBody(resp)

	if resp.StatusCode() == fasthttp.StatusNotFound {
		return p.catalogResponse(key, request, latency, body), nil
	}
	if resp.StatusCode() != fasthttp.StatusOK {
		return nil, providerUtils.SetErrorLatency(parseError(resp), latency)
	}
	if bodyErr != nil {
		return p.catalogResponse(key, request, latency, body), nil
	}
	listing := &openai.OpenAIListModelsResponse{}
	_, rawResponse, bErr := providerUtils.HandleProviderResponse(
		body, listing, nil, false,
		providerUtils.ShouldSendBackRawResponse(ctx, p.sendBackRawResponse),
	)
	if bErr != nil {
		return p.catalogResponse(key, request, latency, body), nil
	}

	response := listing.ToBifrostListModelsResponse(p.GetProviderKey(), key.Models, key.BlacklistedModels, key.Aliases, request.Unfiltered)
	response.ExtraFields.Latency = latency.Milliseconds()
	response.ExtraFields.RawResponse = rawResponse
	return response, nil
}

// catalogResponse renders the pinned catalog as one key's answer, recording the same latency, raw
// body and response headers a live listing records. Without that the catalog answer would be
// invisible in the logs that show how long the listing took and what the upstream actually sent,
// which is precisely the question asked when a deployment's model picker disagrees with the
// catalog.
func (p *CodeBuddyCNProvider) catalogResponse(key schemas.Key, request *schemas.BifrostListModelsRequest, latency time.Duration, body []byte) *schemas.BifrostListModelsResponse {
	unfiltered := request != nil && request.Unfiltered
	response := catalogListModelsResponse(key.Models, key.BlacklistedModels, key.Aliases, unfiltered)
	response.ExtraFields.Latency = latency.Milliseconds()
	if len(body) > 0 && p.sendBackRawResponse {
		// json.RawMessage, not []byte: a plain byte slice marshals as base64, which would put a
		// different value on the wire than the live-listing path writes for the same field.
		response.ExtraFields.RawResponse = json.RawMessage(body)
	}
	return response
}

// ChatCompletion performs a chat completion request to the CodeBuddy API. The caller's stream
// flag is passed through unchanged: the official CLI constructs both shapes, so the gateway
// accepts both and nothing is forced or aggregated here.
//
// A 401 on a browser_login key is retried once after the credential is invalidated, because the
// upstream can revoke an access token before the expiry it declared. See retryOnUnauthorized.
func (p *CodeBuddyCNProvider) ChatCompletion(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostChatRequest) (*schemas.BifrostChatResponse, *schemas.BifrostError) {
	response, sent, bErr := p.chatCompletion(ctx, key, request)
	if sent && bErr != nil {
		if retriedKey, ok := p.retryOnUnauthorized(key, bErr); ok {
			response, _, bErr = p.chatCompletion(ctx, retriedKey, request)
		}
	}
	return response, bErr
}

// chatCompletion is one unary attempt: resolve the credential, then send. sent reports whether the
// request reached the upstream, which is what makes a 401 retryable — a failure to resolve the
// credential has already been through the mint, and retrying it would hit the token endpoint again
// for an answer that cannot have changed.
func (p *CodeBuddyCNProvider) chatCompletion(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostChatRequest) (*schemas.BifrostChatResponse, bool, *schemas.BifrostError) {
	resolved, bErr := p.resolveKey(ctx, key)
	if bErr != nil {
		return nil, false, bErr
	}
	// authHeaderFor takes the key as configured plus the minted token separately: the resolved copy
	// holds that token in Value, which would then read as a pasted key and be sent in X-API-Key.
	response, bErr := openai.HandleOpenAIChatCompletionRequest(
		ctx,
		p.client,
		p.networkConfig.BaseURL+providerUtils.GetPathFromContext(ctx, chatCompletionsPath),
		request,
		authHeaderFor(key, resolved.Value.GetValue()),
		p.extraHeaders(),
		providerUtils.ShouldSendBackRawRequest(ctx, p.sendBackRawRequest),
		providerUtils.ShouldSendBackRawResponse(ctx, p.sendBackRawResponse),
		p.GetProviderKey(),
		chatResponseHandler,
		parseError,
		nil,
		p.logger,
	)
	return response, true, bErr
}

// retryOnUnauthorized decides whether one failed chat attempt should be re-minted and retried, and
// returns the key the retry must use. It reports false for anything that is not a 401 on a
// browser_login bundle, so the pasted-key path and every other provider failure are untouched.
//
// The fast path in resolveKey is what makes this necessary: it serves the stored access token for
// as long as the expiry says it is fresh, and nothing told that path the upstream had revoked the
// token early. Both places that can keep serving it are cleared — the token cache, and the stored
// access token the config holds — so the retry mints from the refresh token. The stored token is
// cleared through the credential sink rather than a second writer, and before the mint, so the
// mint's own rotation is what ends up persisted.
//
// Exactly one retry is possible: the caller makes this decision once per request, and a second 401
// is returned with AllowFallbacks false, which is the spec's permanent-credential ruling.
func (p *CodeBuddyCNProvider) retryOnUnauthorized(key schemas.Key, bErr *schemas.BifrostError) (schemas.Key, bool) {
	if bErr == nil || bErr.StatusCode == nil || *bErr.StatusCode != http.StatusUnauthorized {
		return key, false
	}
	// 12153 is the durable refresh token being dead, not the access token. A re-mint cannot repair
	// that, and clearing the stored access token would drop a credential that may still be good.
	if bErr.Error != nil && bErr.Error.Code != nil && *bErr.Error.Code == strconv.Itoa(deadRefreshTokenCode) {
		return key, false
	}
	if key.OAuthKeyConfig == nil || key.OAuthKeyConfig.GrantType != schemas.OAuthGrantBrowserLogin {
		return key, false
	}
	// A pasted value wins over the bundle in resolveKey, so a 401 there is about that value, not
	// about a minted token this code owns.
	if strings.TrimSpace(key.Value.GetValue()) != "" {
		return key, false
	}
	p.invalidateBrowserLoginCredential(key)
	// The cache was just invalidated, so the fast path would still read the stored token off this
	// copy of the key. Dropping it from the retry's key makes the mint unconditional, which is the
	// point of the invalidate: the credential that was refused must not be offered again.
	retry := key
	cfg := *key.OAuthKeyConfig
	cfg.AccessToken = nil
	cfg.ExpiresAt = ""
	retry.OAuthKeyConfig = &cfg
	return retry, true
}

// invalidateBrowserLoginCredential drops the cached access token for a browser_login key and asks
// the credential sink to clear the stored one. Both are best-effort: with no sink installed (a Go
// SDK caller) only the cache can be cleared, and the retry still mints because its key copy carries
// no stored token.
//
// The sink is reused rather than a second write path: it is already the one owner of "persist this
// credential", including the store write and the in-memory update that the next request reads.
func (p *CodeBuddyCNProvider) invalidateBrowserLoginCredential(key schemas.Key) {
	tokencache.InvalidateForConfig(p.tokens, key.OAuthKeyConfig)
	if key.OAuthKeyConfig == nil {
		return
	}
	sink := currentCredentialSink()
	if sink == nil {
		return
	}
	// An empty access token and an empty expiry: the refresh token stays, and the empty expiry asks
	// applyProviderKeyTokens to leave the stored value alone. What is being written is the absence
	// of a token, not a token.
	sink(p.GetProviderKey(), key.ID, "", key.OAuthKeyConfig.RefreshToken.GetValue(), "")
}

// ChatCompletionStream performs a streaming chat completion request to the CodeBuddy API.
// It supports real-time streaming of responses using Server-Sent Events (SSE).
// Uses CodeBuddy's OpenAI-compatible streaming format.
// Returns a channel containing BifrostStreamChunk objects representing the stream or an error if the request fails.
//
// A 401 arrives before the first chunk, so the same one-shot re-mint the unary path does applies
// here too: nothing has been sent to the caller yet.
func (p *CodeBuddyCNProvider) ChatCompletionStream(ctx *schemas.BifrostContext, postHookRunner schemas.PostHookRunner, postHookSpanFinalizer func(context.Context), key schemas.Key, request *schemas.BifrostChatRequest) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	stream, sent, bErr := p.chatCompletionStream(ctx, postHookRunner, postHookSpanFinalizer, key, request)
	if sent && bErr != nil {
		if retriedKey, ok := p.retryOnUnauthorized(key, bErr); ok {
			stream, _, bErr = p.chatCompletionStream(ctx, postHookRunner, postHookSpanFinalizer, retriedKey, request)
		}
	}
	return stream, bErr
}

// chatCompletionStream is one streaming attempt: resolve the credential, then send. sent means the
// same thing it does on the unary path.
func (p *CodeBuddyCNProvider) chatCompletionStream(ctx *schemas.BifrostContext, postHookRunner schemas.PostHookRunner, postHookSpanFinalizer func(context.Context), key schemas.Key, request *schemas.BifrostChatRequest) (chan *schemas.BifrostStreamChunk, bool, *schemas.BifrostError) {
	resolved, bErr := p.resolveKey(ctx, key)
	if bErr != nil {
		return nil, false, bErr
	}
	stream, bErr := openai.HandleOpenAIChatCompletionStreaming(
		ctx,
		p.streamingClient,
		p.networkConfig.BaseURL+providerUtils.GetPathFromContext(ctx, chatCompletionsPath),
		request,
		authHeaderFor(key, resolved.Value.GetValue()),
		p.extraHeaders(),
		p.networkConfig.StreamIdleTimeoutInSeconds,
		providerUtils.ShouldSendBackRawRequest(ctx, p.sendBackRawRequest),
		providerUtils.ShouldSendBackRawResponse(ctx, p.sendBackRawResponse),
		p.GetProviderKey(),
		postHookRunner,
		nil,
		chatResponseHandler,
		parseError,
		nil,
		nil,
		nil,
		p.logger,
		postHookSpanFinalizer,
	)
	return stream, true, bErr
}

// ModelRetrieve is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) ModelRetrieve(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostModelRetrieveRequest) (*schemas.BifrostModelRetrieveResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ModelRetrieveRequest, p.GetProviderKey())
}

// TextCompletion is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) TextCompletion(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostTextCompletionRequest) (*schemas.BifrostTextCompletionResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionRequest, p.GetProviderKey())
}

// TextCompletionStream is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) TextCompletionStream(ctx *schemas.BifrostContext, postHookRunner schemas.PostHookRunner, postHookSpanFinalizer func(context.Context), key schemas.Key, request *schemas.BifrostTextCompletionRequest) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionStreamRequest, p.GetProviderKey())
}

// Responses performs a responses request to the CodeBuddy API. The gateway serves only the chat
// completions surface, so this is served through chat and folded back into the Responses shape,
// exactly as the other OpenAI-compatible providers do it — and as
// llmtests.RunSimpleChatTest, which requires both shapes to pass, expects.
func (p *CodeBuddyCNProvider) Responses(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostResponsesRequest) (*schemas.BifrostResponsesResponse, *schemas.BifrostError) {
	chatResponse, bErr := p.ChatCompletion(ctx, key, request.ToChatRequest())
	if bErr != nil {
		return nil, bErr
	}
	return chatResponse.ToBifrostResponsesResponse(), nil
}

// ResponsesStream performs a streaming responses request to the CodeBuddy API. It marks the
// context so the shared streaming helper maps chat deltas into Responses events, then delegates.
func (p *CodeBuddyCNProvider) ResponsesStream(ctx *schemas.BifrostContext, postHookRunner schemas.PostHookRunner, postHookSpanFinalizer func(context.Context), key schemas.Key, request *schemas.BifrostResponsesRequest) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	ctx.SetValue(schemas.BifrostContextKeyIsResponsesToChatCompletionFallback, true)
	return p.ChatCompletionStream(ctx, postHookRunner, postHookSpanFinalizer, key, request.ToChatRequest())
}

// CountTokens is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) CountTokens(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostResponsesRequest) (*schemas.BifrostCountTokensResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.CountTokensRequest, p.GetProviderKey())
}

// Compaction is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) Compaction(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostCompactionRequest) (*schemas.BifrostCompactionResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.CompactionRequest, p.GetProviderKey())
}

// Embedding is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) Embedding(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostEmbeddingRequest) (*schemas.BifrostEmbeddingResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.EmbeddingRequest, p.GetProviderKey())
}

// Rerank is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) Rerank(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostRerankRequest) (*schemas.BifrostRerankResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.RerankRequest, p.GetProviderKey())
}

// Decision is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) Decision(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostDecisionRequest) (*schemas.BifrostDecisionResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.DecisionRequest, p.GetProviderKey())
}

// OCR is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) OCR(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostOCRRequest) (*schemas.BifrostOCRResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.OCRRequest, p.GetProviderKey())
}

// Speech is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) Speech(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostSpeechRequest) (*schemas.BifrostSpeechResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechRequest, p.GetProviderKey())
}

// SpeechStream is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) SpeechStream(ctx *schemas.BifrostContext, postHookRunner schemas.PostHookRunner, postHookSpanFinalizer func(context.Context), key schemas.Key, request *schemas.BifrostSpeechRequest) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechStreamRequest, p.GetProviderKey())
}

// Transcription is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) Transcription(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostTranscriptionRequest) (*schemas.BifrostTranscriptionResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionRequest, p.GetProviderKey())
}

// TranscriptionStream is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) TranscriptionStream(ctx *schemas.BifrostContext, postHookRunner schemas.PostHookRunner, postHookSpanFinalizer func(context.Context), key schemas.Key, request *schemas.BifrostTranscriptionRequest) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionStreamRequest, p.GetProviderKey())
}

// ImageGeneration is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) ImageGeneration(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostImageGenerationRequest) (*schemas.BifrostImageGenerationResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationRequest, p.GetProviderKey())
}

// ImageGenerationStream is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) ImageGenerationStream(ctx *schemas.BifrostContext, postHookRunner schemas.PostHookRunner, postHookSpanFinalizer func(context.Context), key schemas.Key, request *schemas.BifrostImageGenerationRequest) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationStreamRequest, p.GetProviderKey())
}

// ImageEdit is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) ImageEdit(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostImageEditRequest) (*schemas.BifrostImageGenerationResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditRequest, p.GetProviderKey())
}

// ImageEditStream is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) ImageEditStream(ctx *schemas.BifrostContext, postHookRunner schemas.PostHookRunner, postHookSpanFinalizer func(context.Context), key schemas.Key, request *schemas.BifrostImageEditRequest) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditStreamRequest, p.GetProviderKey())
}

// ImageVariation is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) ImageVariation(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostImageVariationRequest) (*schemas.BifrostImageGenerationResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageVariationRequest, p.GetProviderKey())
}

// VideoGeneration is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) VideoGeneration(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostVideoGenerationRequest) (*schemas.BifrostVideoGenerationResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoGenerationRequest, p.GetProviderKey())
}

// VideoEdit is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) VideoEdit(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostVideoEditRequest) (*schemas.BifrostVideoEditResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoEditRequest, p.GetProviderKey())
}

// VideoRetrieve is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) VideoRetrieve(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostVideoRetrieveRequest) (*schemas.BifrostVideoGenerationResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRetrieveRequest, p.GetProviderKey())
}

// VideoDownload is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) VideoDownload(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostVideoDownloadRequest) (*schemas.BifrostVideoDownloadResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDownloadRequest, p.GetProviderKey())
}

// VideoDelete is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) VideoDelete(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostVideoDeleteRequest) (*schemas.BifrostVideoDeleteResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDeleteRequest, p.GetProviderKey())
}

// VideoList is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) VideoList(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostVideoListRequest) (*schemas.BifrostVideoListResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoListRequest, p.GetProviderKey())
}

// VideoRemix is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) VideoRemix(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostVideoRemixRequest) (*schemas.BifrostVideoGenerationResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRemixRequest, p.GetProviderKey())
}

// BatchCreate is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) BatchCreate(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostBatchCreateRequest) (*schemas.BifrostBatchCreateResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCreateRequest, p.GetProviderKey())
}

// BatchList is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) BatchList(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostBatchListRequest) (*schemas.BifrostBatchListResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchListRequest, p.GetProviderKey())
}

// BatchRetrieve is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) BatchRetrieve(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostBatchRetrieveRequest) (*schemas.BifrostBatchRetrieveResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchRetrieveRequest, p.GetProviderKey())
}

// BatchCancel is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) BatchCancel(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostBatchCancelRequest) (*schemas.BifrostBatchCancelResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCancelRequest, p.GetProviderKey())
}

// BatchDelete is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) BatchDelete(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostBatchDeleteRequest) (*schemas.BifrostBatchDeleteResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchDeleteRequest, p.GetProviderKey())
}

// BatchResults is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) BatchResults(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostBatchResultsRequest) (*schemas.BifrostBatchResultsResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchResultsRequest, p.GetProviderKey())
}

// FileUpload is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) FileUpload(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostFileUploadRequest) (*schemas.BifrostFileUploadResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileUploadRequest, p.GetProviderKey())
}

// FileList is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) FileList(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostFileListRequest) (*schemas.BifrostFileListResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileListRequest, p.GetProviderKey())
}

// FileRetrieve is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) FileRetrieve(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostFileRetrieveRequest) (*schemas.BifrostFileRetrieveResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileRetrieveRequest, p.GetProviderKey())
}

// FileDelete is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) FileDelete(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostFileDeleteRequest) (*schemas.BifrostFileDeleteResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileDeleteRequest, p.GetProviderKey())
}

// FileContent is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) FileContent(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostFileContentRequest) (*schemas.BifrostFileContentResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileContentRequest, p.GetProviderKey())
}

// CachedContentCreate is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) CachedContentCreate(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostCachedContentCreateRequest) (*schemas.BifrostCachedContentCreateResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.CachedContentCreateRequest, p.GetProviderKey())
}

// CachedContentList is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) CachedContentList(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostCachedContentListRequest) (*schemas.BifrostCachedContentListResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.CachedContentListRequest, p.GetProviderKey())
}

// CachedContentRetrieve is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) CachedContentRetrieve(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostCachedContentRetrieveRequest) (*schemas.BifrostCachedContentRetrieveResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.CachedContentRetrieveRequest, p.GetProviderKey())
}

// CachedContentUpdate is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) CachedContentUpdate(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostCachedContentUpdateRequest) (*schemas.BifrostCachedContentUpdateResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.CachedContentUpdateRequest, p.GetProviderKey())
}

// CachedContentDelete is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) CachedContentDelete(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostCachedContentDeleteRequest) (*schemas.BifrostCachedContentDeleteResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.CachedContentDeleteRequest, p.GetProviderKey())
}

// ContainerCreate is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) ContainerCreate(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostContainerCreateRequest) (*schemas.BifrostContainerCreateResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerCreateRequest, p.GetProviderKey())
}

// ContainerList is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) ContainerList(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostContainerListRequest) (*schemas.BifrostContainerListResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerListRequest, p.GetProviderKey())
}

// ContainerRetrieve is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) ContainerRetrieve(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostContainerRetrieveRequest) (*schemas.BifrostContainerRetrieveResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerRetrieveRequest, p.GetProviderKey())
}

// ContainerDelete is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) ContainerDelete(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostContainerDeleteRequest) (*schemas.BifrostContainerDeleteResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerDeleteRequest, p.GetProviderKey())
}

// ContainerFileCreate is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) ContainerFileCreate(ctx *schemas.BifrostContext, key schemas.Key, request *schemas.BifrostContainerFileCreateRequest) (*schemas.BifrostContainerFileCreateResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileCreateRequest, p.GetProviderKey())
}

// ContainerFileList is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) ContainerFileList(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostContainerFileListRequest) (*schemas.BifrostContainerFileListResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileListRequest, p.GetProviderKey())
}

// ContainerFileRetrieve is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) ContainerFileRetrieve(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostContainerFileRetrieveRequest) (*schemas.BifrostContainerFileRetrieveResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileRetrieveRequest, p.GetProviderKey())
}

// ContainerFileContent is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) ContainerFileContent(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostContainerFileContentRequest) (*schemas.BifrostContainerFileContentResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileContentRequest, p.GetProviderKey())
}

// ContainerFileDelete is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) ContainerFileDelete(ctx *schemas.BifrostContext, keys []schemas.Key, request *schemas.BifrostContainerFileDeleteRequest) (*schemas.BifrostContainerFileDeleteResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileDeleteRequest, p.GetProviderKey())
}

// Passthrough is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) Passthrough(ctx *schemas.BifrostContext, key schemas.Key, req *schemas.BifrostPassthroughRequest) (*schemas.BifrostPassthroughResponse, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughRequest, p.GetProviderKey())
}

// PassthroughStream is not supported by the CodeBuddy CN provider.
func (p *CodeBuddyCNProvider) PassthroughStream(ctx *schemas.BifrostContext, postHookRunner schemas.PostHookRunner, postHookSpanFinalizer func(context.Context), key schemas.Key, req *schemas.BifrostPassthroughRequest) (chan *schemas.BifrostStreamChunk, *schemas.BifrostError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughStreamRequest, p.GetProviderKey())
}
