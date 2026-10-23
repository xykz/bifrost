package handlers

import (
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/network"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/v2/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

const (
	// codeBuddyLoginDefaultBaseURL is the CN gateway, used when a codebuddy-cn provider has no
	// base_url of its own. The device-flow calls below hang off the host root, like every other
	// CodeBuddy path.
	codeBuddyLoginDefaultBaseURL = "https://copilot.tencent.com"
	// codeBuddyLoginStatePath and codeBuddyLoginTokenPath are the CLI's own device-flow
	// endpoints. platform=CLI is not optional: the start call is rejected without it.
	codeBuddyLoginStatePath = "/v2/plugin/auth/state?platform=CLI"
	codeBuddyLoginTokenPath = "/v2/plugin/auth/token"
	// codeBuddyLoginPendingCode is the upstream's "the browser has not finished yet" answer.
	codeBuddyLoginPendingCode = 11217
	// codeBuddyLoginKeyPrefix namespaces a flow in the shared store. flow_id is the rest of the
	// key and is the only handle a client ever sees; the upstream state stays in the value.
	codeBuddyLoginKeyPrefix = "codebuddy:login:"
	// codeBuddyLoginPendingTTL is how long an unfinished browser sign-in is kept. Fifteen minutes
	// covers a human logging in, including a password plus an MFA prompt, and nothing longer is
	// useful: an abandoned popup should not leave an upstream authorization sitting around.
	codeBuddyLoginPendingTTL = 15 * time.Minute
	// codeBuddyLoginSettledTTL replaces the pending TTL the moment a flow reaches a terminal
	// state. A completed flow holds a live access/refresh pair, so handing it out for the full
	// pending window would widen the exposure of credentials the UI already has; five minutes is
	// several poll cycles of slack. A failed flow carries no secret, but it is kept for the same
	// five minutes so a repeat poll reads the terminal answer instead of starting over.
	codeBuddyLoginSettledTTL = 5 * time.Minute
	// codeBuddyLoginRequestTimeout bounds a single upstream call. The UI polls every couple of
	// seconds, so a hung upstream must surface as an error it can retry, not hold the request.
	codeBuddyLoginRequestTimeout = 10 * time.Second
	// codeBuddyLoginMaxResponseBytes caps an upstream body. Both wire shapes are a few hundred
	// bytes; anything larger is not the device flow answering.
	codeBuddyLoginMaxResponseBytes = 1 << 20
	// codeBuddyLoginAdminRequired is the refusal for a deployment with dashboard auth disabled,
	// where isAuthBypassed is true for every caller on the network.
	codeBuddyLoginAdminRequired = "codebuddy login requires an authenticated admin session; enable dashboard authentication first"
	// codeBuddyLoginWrongProvider refuses a login route scoped to a provider that is not one of
	// the gateway's CodeBuddy implementations.
	codeBuddyLoginWrongProvider = "codebuddy login is only available for the codebuddy-cn provider"
	// codeBuddyLoginFlowNotFound is the answer for an unknown, foreign, expired or already-dropped
	// flow. It deliberately does not distinguish between them.
	codeBuddyLoginFlowNotFound = "codebuddy login flow not found"
	// codeBuddyLoginStoreFailed is the refusal for a terminal answer the store cannot hold. The
	// client is not shown the tokens in that case: the server could not reproduce them.
	codeBuddyLoginStoreFailed = "failed to store the codebuddy login result"
	// codeBuddyLoginLockStripes bounds the poll locks. Striping keeps the set fixed for the life
	// of the process, so per-flow serialization costs no bookkeeping and leaks nothing.
	codeBuddyLoginLockStripes = 64
)

const (
	codeBuddyLoginPending   = "pending"   // The browser has not completed the sign-in yet.
	codeBuddyLoginCompleted = "completed" // The upstream issued a token pair.
	codeBuddyLoginFailed    = "failed"    // The upstream answered with something terminal.
)

// errCodeBuddyLoginWrongProvider marks a provider the login route does not serve, as opposed to
// one that is simply missing from the config.
var errCodeBuddyLoginWrongProvider = errors.New(codeBuddyLoginWrongProvider)

// codeBuddyLoginFlowLocks serializes polls of one flow on this node; see lockCodeBuddyLoginFlow.
var codeBuddyLoginFlowLocks [codeBuddyLoginLockStripes]sync.Mutex

// lockCodeBuddyLoginFlow takes this node's lock for a flow and returns its release.
//
// Two concurrent polls of a pending flow would otherwise both present the same upstream state. The
// upstream answers the second with a terminal code (the state is consumed), and without
// serialization that losing answer could settle over the winning poll's token pair. Holding the
// lock across the upstream call also stops one browser sign-in from being polled twice at once.
// It is per node: a peer replica can still race, which is why finishCodeBuddyLogin re-reads the
// record before writing.
func lockCodeBuddyLoginFlow(flowID string) func() {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(flowID))
	lock := &codeBuddyLoginFlowLocks[hash.Sum32()%codeBuddyLoginLockStripes]
	lock.Lock()
	return lock.Unlock
}

// codeBuddyLoginFlow is a login in progress, as stored in the shared KV store.
//
// The upstream state is a credential in its own right: whoever presents it can finish the flow and
// collect the browser's tokens. It therefore appears outside this record only inside auth_url,
// which is the upstream URL the admin opens. flow_id is the opaque handle handed out instead, and
// it is the store key's suffix rather than a field here.
//
// ExpiresAt and TokenExpiresAt are different clocks and must not be confused: the first is when the
// browser must finish (and, once settled, when this entry stops being pollable), the second is when
// the access token the browser minted will need refreshing.
type codeBuddyLoginFlow struct {
	State          string                `json:"state"`                      // Upstream device-flow state, server-side only
	Provider       schemas.ModelProvider `json:"provider"`                   // Provider the flow was started for
	ExpiresAt      string                `json:"expires_at"`                 // Flow deadline, RFC3339
	Status         string                `json:"status"`                     // pending, completed or failed
	AccessToken    string                `json:"access_token,omitempty"`     // Completed only
	RefreshToken   string                `json:"refresh_token,omitempty"`    // Completed only
	TokenType      string                `json:"token_type,omitempty"`       // Completed only, as the upstream reported it
	TokenExpiresAt string                `json:"token_expires_at,omitempty"` // Completed only, access-token expiry RFC3339
	Error          string                `json:"error,omitempty"`            // Failed only
}

// codeBuddyLoginStartResponse is the start endpoint's wire shape.
//
// flow_expires_at is the deadline for the browser to finish the sign-in. It is deliberately not
// called expires_at: the completed poll uses expires_at for the access token's expiry, which is the
// value oauth_key_config.expires_at stores, and the two must never be written into one field.
type codeBuddyLoginStartResponse struct {
	FlowID        string `json:"flow_id"`         // Opaque handle to poll with
	AuthURL       string `json:"auth_url"`        // Browser URL the admin opens
	FlowExpiresAt string `json:"flow_expires_at"` // When the browser must finish, RFC3339
}

// codeBuddyLoginStatusResponse is the poll endpoint's wire shape, identical for every state.
//
// expires_at here is the access token's expiry, not the flow's: it is what the key form stores.
type codeBuddyLoginStatusResponse struct {
	Status       string `json:"status"`                  // pending, completed or failed
	AccessToken  string `json:"access_token,omitempty"`  // Completed only
	RefreshToken string `json:"refresh_token,omitempty"` // Completed only
	TokenType    string `json:"token_type,omitempty"`    // Completed only
	ExpiresAt    string `json:"expires_at,omitempty"`    // Completed only, access-token expiry RFC3339
	Error        string `json:"error,omitempty"`         // Failed only
}

// codeBuddyDeviceStateResponse is the upstream's answer to the start call.
type codeBuddyDeviceStateResponse struct {
	State   string `json:"state"`   // State to poll with
	AuthURL string `json:"authUrl"` // Browser URL for the admin
}

// codeBuddyDeviceTokenData is the token pair inside a successful poll answer.
type codeBuddyDeviceTokenData struct {
	AccessToken  string `json:"accessToken"`  // Bearer used for inference
	RefreshToken string `json:"refreshToken"` // Durable credential the key keeps
	ExpiresIn    int    `json:"expiresIn"`    // Access-token lifetime in seconds
	TokenType    string `json:"tokenType"`    // Always Bearer today
}

// codeBuddyDeviceTokenResponse is the upstream's answer to a poll.
type codeBuddyDeviceTokenResponse struct {
	Code    int                       `json:"code"`    // 0 success, 11217 pending, anything else failed
	Message string                    `json:"message"` // Upstream explanation, never forwarded
	Data    *codeBuddyDeviceTokenData `json:"data"`    // Present only on success
}

// codeBuddyLoginFallbackClient serves a config built without an HTTPClientFactory, which is what
// a hand-constructed lib.Config (tests, embedded use) looks like. The live factory is preferred
// so the flow honours the deployment's proxy settings.
var codeBuddyLoginFallbackClient = &http.Client{
	Transport:     http.DefaultTransport,
	Timeout:       codeBuddyLoginRequestTimeout,
	CheckRedirect: refuseCodeBuddyLoginRedirect,
}

// refuseCodeBuddyLoginRedirect stops the login client following a redirect. The poll URL carries
// the upstream state in its query, and both calls expect a JSON body, so a redirect is not part of
// the contract: following one would hand that state to whatever host the response named.
func refuseCodeBuddyLoginRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// startCodeBuddyLogin handles POST /api/providers/{provider}/codebuddy-cn/login.
//
// It opens a device flow at the provider's own base URL and hands back an opaque flow handle.
// The request body is never read: the only dial target is the one in the provider config, so a
// caller cannot turn this endpoint into a request forwarder.
func (h *ProviderHandler) startCodeBuddyLogin(ctx *fasthttp.RequestCtx) {
	if isAuthBypassed(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, codeBuddyLoginAdminRequired)
		return
	}
	provider, err := getProviderFromCtx(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("invalid provider: %v", err))
		return
	}
	// Provider validation comes before the store check: a bogus provider must be a 404 on every
	// deployment, including one whose store failed to initialise, rather than a misleading 500.
	baseURL, err := h.codeBuddyLoginBaseURL(provider)
	if err != nil {
		sendCodeBuddyLoginTargetError(ctx, err)
		return
	}
	kv, err := h.codeBuddyLoginStore()
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}

	upstreamURL := baseURL + codeBuddyLoginStatePath
	body, err := h.codeBuddyLoginCall(ctx, http.MethodPost, upstreamURL)
	if err != nil {
		logger.Warn("codebuddy login start failed for provider %s: %v", provider, err)
		SendError(ctx, fasthttp.StatusBadGateway, "codebuddy login could not reach the provider")
		return
	}
	var state codeBuddyDeviceStateResponse
	if err := sonic.Unmarshal(body, &state); err != nil || state.State == "" || state.AuthURL == "" {
		SendError(ctx, fasthttp.StatusBadGateway, "codebuddy login received an unexpected answer from the provider")
		return
	}

	flowID := uuid.NewString()
	flowExpiresAt := time.Now().Add(codeBuddyLoginPendingTTL).UTC()
	flow := &codeBuddyLoginFlow{
		State:     state.State,
		Provider:  provider,
		ExpiresAt: flowExpiresAt.Format(time.RFC3339),
		Status:    codeBuddyLoginPending,
	}
	if err := kv.SetWithTTL(codeBuddyLoginKey(flowID), flow, codeBuddyLoginPendingTTL); err != nil {
		logger.Warn("failed to store codebuddy login flow for provider %s: %v", provider, err)
		SendError(ctx, fasthttp.StatusInternalServerError, "failed to start codebuddy login")
		return
	}

	SendJSON(ctx, codeBuddyLoginStartResponse{
		FlowID:        flowID,
		AuthURL:       state.AuthURL,
		FlowExpiresAt: flow.ExpiresAt,
	})
}

// pollCodeBuddyLogin handles GET /api/providers/{provider}/codebuddy-cn/login/{flow_id}.
//
// A flow is polled until it settles. Once completed or failed, the stored answer is returned
// verbatim and the upstream is not contacted again: the UI polls every couple of seconds and a
// settled flow must be free to re-read.
func (h *ProviderHandler) pollCodeBuddyLogin(ctx *fasthttp.RequestCtx) {
	if isAuthBypassed(ctx) {
		SendError(ctx, fasthttp.StatusForbidden, codeBuddyLoginAdminRequired)
		return
	}
	provider, err := getProviderFromCtx(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("invalid provider: %v", err))
		return
	}
	flowID, _ := ctx.UserValue("flow_id").(string)
	if flowID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "missing flow id")
		return
	}
	// Resolve the provider before the store, for the same reason start does: a bogus provider is a
	// 404 on every deployment, not a 500 blaming the store. The result is reused for the upstream
	// call below, so this costs nothing extra.
	baseURL, err := h.codeBuddyLoginBaseURL(provider)
	if err != nil {
		sendCodeBuddyLoginTargetError(ctx, err)
		return
	}
	kv, err := h.codeBuddyLoginStore()
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}

	release := lockCodeBuddyLoginFlow(flowID)
	defer release()

	flow, err := loadCodeBuddyLoginFlow(kv, flowID)
	if err != nil || flow.Provider != provider {
		// A flow belonging to another provider is indistinguishable from a missing one: the
		// provider segment of the path is not an authorization boundary a caller may probe.
		SendError(ctx, fasthttp.StatusNotFound, codeBuddyLoginFlowNotFound)
		return
	}
	if flowDeadline, parseErr := time.Parse(time.RFC3339, flow.ExpiresAt); parseErr != nil || time.Now().After(flowDeadline) {
		// The browser waited too long. Drop the entry rather than leave something an eventual
		// poll could pick up again; the flow_id is dead from here on.
		if _, deleteErr := kv.Delete(codeBuddyLoginKey(flowID)); deleteErr != nil {
			logger.Warn("failed to drop expired codebuddy login flow: %v", deleteErr)
		}
		SendError(ctx, fasthttp.StatusNotFound, codeBuddyLoginFlowNotFound)
		return
	}
	if codeBuddyLoginTerminal(flow.Status) {
		SendJSON(ctx, codeBuddyLoginStatusOf(flow))
		return
	}

	upstreamURL := baseURL + codeBuddyLoginTokenPath + "?" + url.Values{"state": {flow.State}}.Encode()
	body, err := h.codeBuddyLoginCall(ctx, http.MethodGet, upstreamURL)
	if err != nil {
		// A transport failure says nothing about the flow: the browser may still be signing in.
		// Report it as retryable and leave the flow pending, so a blip does not force a re-login.
		logger.Warn("codebuddy login poll failed for provider %s: %v", provider, err)
		SendError(ctx, fasthttp.StatusBadGateway, "codebuddy login could not reach the provider")
		return
	}
	var polled codeBuddyDeviceTokenResponse
	if err := sonic.Unmarshal(body, &polled); err != nil {
		h.finishCodeBuddyLogin(ctx, kv, flowID, failedCodeBuddyLogin(flow, "codebuddy login received an unexpected answer from the provider"))
		return
	}

	switch polled.Code {
	case codeBuddyLoginPendingCode:
		SendJSON(ctx, codeBuddyLoginStatusResponse{Status: codeBuddyLoginPending})
	case 0:
		if polled.Data == nil || polled.Data.AccessToken == "" || polled.Data.RefreshToken == "" {
			h.finishCodeBuddyLogin(ctx, kv, flowID, failedCodeBuddyLogin(flow, "codebuddy login succeeded without a token pair"))
			return
		}
		settled := *flow
		settled.Status = codeBuddyLoginCompleted
		settled.AccessToken = polled.Data.AccessToken
		settled.RefreshToken = polled.Data.RefreshToken
		settled.TokenType = polled.Data.TokenType
		if polled.Data.ExpiresIn > 0 {
			settled.TokenExpiresAt = time.Now().Add(time.Duration(polled.Data.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
		}
		// The state finished the flow; nothing past this point may call upstream with it again, so
		// it does not outlive the poll that consumed it, not even in a gossip payload to a peer.
		settled.State = ""
		// The browser deadline is spent; what bounds this entry now is the settled TTL. Moving the
		// deadline with it keeps the stored lifetime and the expiry check telling the same story,
		// so a sign-in that completes at minute 14 is still readable for its five minutes.
		settled.ExpiresAt = time.Now().Add(codeBuddyLoginSettledTTL).UTC().Format(time.RFC3339)
		h.finishCodeBuddyLogin(ctx, kv, flowID, &settled)
	default:
		// The upstream said no in its own words. Its message is not forwarded: it is upstream
		// text, and the state it was asked about must not travel back to a client in any form.
		h.finishCodeBuddyLogin(ctx, kv, flowID, failedCodeBuddyLogin(flow,
			fmt.Sprintf("codebuddy login was refused by the provider (code %d)", polled.Code)))
	}
}

// failedCodeBuddyLogin projects a flow onto its terminal failure record. The token fields and the
// state are cleared: a failed flow can never complete, so neither has any further use.
func failedCodeBuddyLogin(flow *codeBuddyLoginFlow, message string) *codeBuddyLoginFlow {
	settled := *flow
	settled.Status = codeBuddyLoginFailed
	settled.Error = message
	settled.AccessToken = ""
	settled.RefreshToken = ""
	settled.TokenType = ""
	settled.TokenExpiresAt = ""
	settled.State = ""
	settled.ExpiresAt = time.Now().Add(codeBuddyLoginSettledTTL).UTC().Format(time.RFC3339)
	return &settled
}

// finishCodeBuddyLogin persists a terminal flow and answers with the outcome that actually won.
//
// The store has no compare-and-set, so a write cannot be made atomic with the earlier read. Two
// things narrow the gap. Polls of one flow are serialized on this node (lockCodeBuddyLoginFlow), so
// the local interleaving cannot happen at all. After that, a peer replica may still have settled
// the same flow, so this re-reads before writing and refuses to overwrite a terminal record: the
// first settlement wins, and this poll returns the winner's payload rather than its own losing one.
//
// If that re-read fails the write is skipped — overwriting blind is exactly how a token pair would
// be destroyed — and the request answers 500 instead of handing out credentials the store may not
// hold. A failed write gets the same treatment for the same reason.
func (h *ProviderHandler) finishCodeBuddyLogin(ctx *fasthttp.RequestCtx, kv schemas.KVStore, flowID string, settled *codeBuddyLoginFlow) {
	current, err := loadCodeBuddyLoginFlow(kv, flowID)
	if err != nil {
		logger.Warn("failed to re-read codebuddy login flow before settling: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, codeBuddyLoginStoreFailed)
		return
	}
	if codeBuddyLoginTerminal(current.Status) {
		// Another poll settled first. Its record is the truth the client must see; writing this
		// poll's answer over it would erase the tokens the browser just minted.
		SendJSON(ctx, codeBuddyLoginStatusOf(current))
		return
	}
	if err := kv.SetWithTTL(codeBuddyLoginKey(flowID), settled, codeBuddyLoginSettledTTL); err != nil {
		logger.Warn("failed to settle codebuddy login flow: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, codeBuddyLoginStoreFailed)
		return
	}
	SendJSON(ctx, codeBuddyLoginStatusOf(settled))
}

// codeBuddyLoginTerminal reports whether a status is final.
func codeBuddyLoginTerminal(status string) bool {
	return status == codeBuddyLoginCompleted || status == codeBuddyLoginFailed
}

// codeBuddyLoginStatusOf projects a stored flow onto the poll response. Fields the flow does not
// carry are omitted rather than serialized empty, and expires_at is the access token's expiry —
// the flow's own deadline is reported once, by the start response.
func codeBuddyLoginStatusOf(flow *codeBuddyLoginFlow) codeBuddyLoginStatusResponse {
	return codeBuddyLoginStatusResponse{
		Status:       flow.Status,
		AccessToken:  flow.AccessToken,
		RefreshToken: flow.RefreshToken,
		TokenType:    flow.TokenType,
		ExpiresAt:    flow.TokenExpiresAt,
		Error:        flow.Error,
	}
}

// codeBuddyLoginKey is the store key for a flow handle.
func codeBuddyLoginKey(flowID string) string {
	return codeBuddyLoginKeyPrefix + flowID
}

// loadCodeBuddyLoginFlow reads a flow and accepts both shapes a shared store can return it in:
// the local pointer this node wrote, and the JSON bytes a peer decodes without a registered
// decoder. Callers never mutate the result; they copy it before settling.
func loadCodeBuddyLoginFlow(kv schemas.KVStore, flowID string) (*codeBuddyLoginFlow, error) {
	value, err := kv.Get(codeBuddyLoginKey(flowID))
	if err != nil {
		return nil, err
	}
	switch stored := value.(type) {
	case *codeBuddyLoginFlow:
		if stored == nil {
			return nil, errors.New("empty login flow")
		}
		return stored, nil
	case codeBuddyLoginFlow:
		return &stored, nil
	case []byte:
		var flow codeBuddyLoginFlow
		if err := sonic.Unmarshal(stored, &flow); err != nil {
			return nil, err
		}
		return &flow, nil
	default:
		return nil, errors.New("unexpected login flow type")
	}
}

// codeBuddyLoginBaseURL resolves the only host a login may dial: the provider's configured
// base_url, else the CN gateway. Nothing else — no request field, no header — contributes.
//
// A codebuddy-cn provider that has not been saved yet is allowed: the operator may be logging
// in while filling out the add-provider form. Any other provider must exist and must resolve to
// a codebuddy-cn implementation, whether directly or through its custom base provider.
func (h *ProviderHandler) codeBuddyLoginBaseURL(provider schemas.ModelProvider) (string, error) {
	if h.inMemoryStore == nil {
		return "", errors.New("config is not available")
	}
	config, err := h.inMemoryStore.GetProviderConfigRaw(provider)
	if err != nil {
		if provider == schemas.CodeBuddyCN {
			return codeBuddyLoginDefaultBaseURL, nil
		}
		return "", err
	}
	baseProvider := provider
	if config.CustomProviderConfig != nil && config.CustomProviderConfig.BaseProviderType != "" {
		baseProvider = config.CustomProviderConfig.BaseProviderType
	}
	if baseProvider != schemas.CodeBuddyCN {
		return "", errCodeBuddyLoginWrongProvider
	}
	if config.NetworkConfig != nil {
		if base := strings.TrimSpace(config.NetworkConfig.BaseURL); base != "" {
			return strings.TrimRight(base, "/"), nil
		}
	}
	return codeBuddyLoginDefaultBaseURL, nil
}

// codeBuddyLoginStore returns the shared store, so a flow survives across replicas.
func (h *ProviderHandler) codeBuddyLoginStore() (schemas.KVStore, error) {
	if h.inMemoryStore == nil || h.inMemoryStore.GetKVStore() == nil {
		return nil, errors.New("codebuddy login is unavailable: kv store is not configured")
	}
	return h.inMemoryStore.GetKVStore(), nil
}

// codeBuddyLoginCall performs one upstream device-flow request and returns the body. The URL is
// always assembled from codeBuddyLoginBaseURL, never from the inbound request.
func (h *ProviderHandler) codeBuddyLoginCall(ctx *fasthttp.RequestCtx, method, upstreamURL string) ([]byte, error) {
	reqCtx, cancel := RequestWorkContext(ctx, codeBuddyLoginRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, upstreamURL, nil)
	if err != nil {
		// NewRequestWithContext wraps its error in a *url.Error carrying the URL, and the poll
		// URL's query is the upstream state. A malformed configured base_url must not put that
		// into a log line or a shipped log store.
		return nil, unwrapCodeBuddyLoginURLError(err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := h.codeBuddyLoginHTTPClient().Do(req)
	if err != nil {
		return nil, unwrapCodeBuddyLoginURLError(err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream returned http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, codeBuddyLoginMaxResponseBytes))
	if err != nil {
		return nil, err
	}
	return body, nil
}

// unwrapCodeBuddyLoginURLError drops the *url.Error wrapper, which quotes the request URL.
func unwrapCodeBuddyLoginURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}

// codeBuddyLoginHTTPClient builds the client for one upstream call. It borrows the config's live
// transport when there is one, so the flow follows the deployment's proxy settings, and falls
// back to the standard transport for a hand-built lib.Config (tests, embedded use). A fresh
// client per call is what allows the redirect policy below: the factory's client is shared and
// must not be mutated, and the request path here is one call per UI poll.
func (h *ProviderHandler) codeBuddyLoginHTTPClient() *http.Client {
	transport := codeBuddyLoginFallbackClient.Transport
	if h.inMemoryStore != nil && h.inMemoryStore.HTTPClientFactory != nil {
		if live := h.inMemoryStore.HTTPClientFactory.GetHTTPClient(network.ClientPurposeAPI); live != nil && live.Transport != nil {
			transport = live.Transport
		}
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       codeBuddyLoginRequestTimeout,
		CheckRedirect: refuseCodeBuddyLoginRedirect,
	}
}

// sendCodeBuddyLoginTargetError maps a base-URL resolution failure onto its status code.
func sendCodeBuddyLoginTargetError(ctx *fasthttp.RequestCtx, err error) {
	switch {
	case errors.Is(err, errCodeBuddyLoginWrongProvider):
		SendError(ctx, fasthttp.StatusBadRequest, codeBuddyLoginWrongProvider)
	case errors.Is(err, lib.ErrNotFound):
		SendError(ctx, fasthttp.StatusNotFound, "provider not found")
	default:
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
	}
}
