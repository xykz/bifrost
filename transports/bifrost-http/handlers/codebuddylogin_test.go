package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fasthttp/router"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/kvstore"
	"github.com/maximhq/bifrost/transports/v2/bifrost-http/lib"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

// codeBuddyLoginStartBody mirrors the start response the UI consumes. It is declared here
// rather than reusing the handler's type so these tests also compile before the handler exists,
// which is what makes the first run fail on routing instead of on a build error.
//
// flow_expires_at is the browser's deadline. There is deliberately no expires_at field: that name
// belongs to the completed poll, where it is the access token's expiry.
type codeBuddyLoginStartBody struct {
	FlowID        string `json:"flow_id"`
	AuthURL       string `json:"auth_url"`
	FlowExpiresAt string `json:"flow_expires_at"`
}

// codeBuddyLoginStatusBody mirrors the poll response. expires_at is the access token's expiry.
type codeBuddyLoginStatusBody struct {
	Status       string `json:"status"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresAt    string `json:"expires_at"`
	Error        string `json:"error"`
}

// codeBuddyLoginFixture serves the provider routes over an in-memory listener, so a test
// exercises the real router, the real path parameters and the real JSON encoding.
type codeBuddyLoginFixture struct {
	kv      *kvstore.Store
	client  *fasthttp.Client
	config  *lib.Config
	handler *ProviderHandler
}

func newCodeBuddyLoginFixture(t *testing.T, upstreamBaseURL string, middlewares ...schemas.BifrostHTTPMiddleware) *codeBuddyLoginFixture {
	t.Helper()
	// The logger is a package global; leaving the mock installed would leak into every later test
	// in this package.
	previousLogger := logger
	SetLogger(&mockLogger{})
	t.Cleanup(func() { SetLogger(previousLogger) })

	store, err := kvstore.New(kvstore.Config{})
	if err != nil {
		t.Fatalf("create kv store: %v", err)
	}

	config := &lib.Config{
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {
				NetworkConfig: &schemas.NetworkConfig{
					BaseURL:                        upstreamBaseURL,
					DefaultRequestTimeoutInSeconds: 5,
				},
			},
		},
		KVStore: store,
	}

	handler := &ProviderHandler{inMemoryStore: config}
	r := router.New()
	handler.RegisterRoutes(r, middlewares...)

	server := &fasthttp.Server{Handler: r.Handler}
	listener := fasthttputil.NewInmemoryListener()
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Shutdown()
		_ = listener.Close()
		_ = store.Close()
	})

	return &codeBuddyLoginFixture{
		kv:      store,
		config:  config,
		handler: handler,
		client: &fasthttp.Client{
			Dial:         func(string) (net.Conn, error) { return listener.Dial() },
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
	}
}

func (f *codeBuddyLoginFixture) do(t *testing.T, method, path, body string) (int, string) {
	t.Helper()
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethod(method)
	req.SetRequestURI("http://bifrost.test" + path)
	if body != "" {
		req.Header.SetContentType("application/json")
		req.SetBodyString(body)
	}
	if err := f.client.Do(req, resp); err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp.StatusCode(), string(resp.Body())
}

// fakeCodeBuddyUpstream is the official device-flow shape: state, then a poll that answers
// 11217 until the browser completes, then the token pair.
type fakeCodeBuddyUpstream struct {
	server               *httptest.Server
	mu                   sync.Mutex
	stateCalls           int
	tokenCalls           int
	pendingBeforeSuccess int
	failureCode          int
	// failAfterFirstSuccess makes the second and later token polls answer terminal, which models
	// what a real upstream does once the state has been consumed by the winning poll.
	failAfterFirstSuccess bool
	// holdFirstToken blocks the first token poll until gate is closed or drained.
	holdFirstToken chan struct{}
	// activeTokens and maxActiveTokens record how many token polls the upstream saw at once.
	activeTokens    int
	maxActiveTokens int
	tokenState      string
}

func newFakeCodeBuddyUpstream(t *testing.T, pendingPolls int) *fakeCodeBuddyUpstream {
	t.Helper()
	return newFakeCodeBuddyUpstreamWithFailure(t, pendingPolls, 0)
}

// newFakeCodeBuddyUpstreamWithFailure answers every token poll with failureCode when it is
// non-zero, which is how the upstream refuses a sign-in outright.
func newFakeCodeBuddyUpstreamWithFailure(t *testing.T, pendingPolls, failureCode int) *fakeCodeBuddyUpstream {
	t.Helper()
	f := &fakeCodeBuddyUpstream{pendingBeforeSuccess: pendingPolls, failureCode: failureCode}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/plugin/auth/state":
			f.mu.Lock()
			f.stateCalls++
			f.mu.Unlock()
			if r.URL.Query().Get("platform") != "CLI" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"code":400,"message":"platform required"}`))
				return
			}
			_, _ = w.Write([]byte(`{"state":"s1","authUrl":"https://copilot.tencent.com/login?platform=CLI&state=s1"}`))
		case "/v2/plugin/auth/token":
			f.answerTokenPoll(w, r)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":404}`))
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

// answerTokenPoll serves one token poll, recording concurrency so a test can prove the endpoints
// never present one state to the upstream twice at once.
func (f *fakeCodeBuddyUpstream) answerTokenPoll(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.tokenCalls++
	callNumber := f.tokenCalls
	f.tokenState = r.URL.Query().Get("state")
	pending := f.pendingBeforeSuccess
	if pending > 0 {
		f.pendingBeforeSuccess--
	}
	failure := f.failureCode
	failLater := f.failAfterFirstSuccess && callNumber > 1
	gate := f.holdFirstToken
	f.activeTokens++
	if f.activeTokens > f.maxActiveTokens {
		f.maxActiveTokens = f.activeTokens
	}
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.activeTokens--
		f.mu.Unlock()
	}()

	if gate != nil && callNumber == 1 {
		<-gate
	}
	if failure != 0 || failLater {
		code := failure
		if code == 0 {
			code = 40901
		}
		_, _ = w.Write([]byte(fmt.Sprintf(`{"code":%d,"message":"refused"}`, code)))
		return
	}
	if pending > 0 {
		_, _ = w.Write([]byte(`{"code":11217}`))
		return
	}
	_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-1","refreshToken":"refresh-1","expiresIn":3600,"tokenType":"Bearer"}}`))
}

func (f *fakeCodeBuddyUpstream) counts() (state, token int, stateParam string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stateCalls, f.tokenCalls, f.tokenState
}

func decodeCodeBuddyLoginStart(t *testing.T, body string) codeBuddyLoginStartBody {
	t.Helper()
	var decoded codeBuddyLoginStartBody
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("decode start body %q: %v", body, err)
	}
	return decoded
}

func decodeCodeBuddyLoginStatus(t *testing.T, body string) codeBuddyLoginStatusBody {
	t.Helper()
	var decoded codeBuddyLoginStatusBody
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("decode status body %q: %v", body, err)
	}
	return decoded
}

func mustParseCodeBuddyTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("%q is not RFC3339: %v", value, err)
	}
	return parsed
}

// startCodeBuddyLoginOn drives the start endpoint and returns the decoded body.
func startCodeBuddyLoginOn(t *testing.T, fixture *codeBuddyLoginFixture, provider string) codeBuddyLoginStartBody {
	t.Helper()
	status, body := fixture.do(t, fasthttp.MethodPost, "/api/providers/"+provider+"/codebuddy-cn/login", "{}")
	if status != fasthttp.StatusOK {
		t.Fatalf("start status = %d, want 200; body=%s", status, body)
	}
	return decodeCodeBuddyLoginStart(t, body)
}

// TestCodeBuddyLoginStartRequiresAdminSession pins requirement 3: a deployment with dashboard
// auth disabled must not offer an unauthenticated path to mint a credential.
func TestCodeBuddyLoginStartRequiresAdminSession(t *testing.T) {
	upstream := newFakeCodeBuddyUpstream(t, 0)
	bypassed := func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			ctx.SetUserValue(schemas.BifrostContextKeyAuthBypassed, true)
			next(ctx)
		}
	}
	fixture := newCodeBuddyLoginFixture(t, upstream.server.URL, bypassed)

	status, body := fixture.do(t, fasthttp.MethodPost, "/api/providers/codebuddy-cn/codebuddy-cn/login", "{}")
	if status != fasthttp.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", status, body)
	}
	const want = "codebuddy login requires an authenticated admin session; enable dashboard authentication first"
	if !strings.Contains(body, want) {
		t.Fatalf("body = %q, want it to carry %q", body, want)
	}
	if stateCalls, _, _ := upstream.counts(); stateCalls != 0 {
		t.Fatalf("upstream state called %d times, want 0: a refused login must not dial out", stateCalls)
	}
}

// TestCodeBuddyLoginPollRequiresAdminSession pins the poll route's own gate. It is a second
// handler, so passing the start test says nothing about it.
func TestCodeBuddyLoginPollRequiresAdminSession(t *testing.T) {
	upstream := newFakeCodeBuddyUpstream(t, 0)
	bypassed := func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			ctx.SetUserValue(schemas.BifrostContextKeyAuthBypassed, true)
			next(ctx)
		}
	}
	fixture := newCodeBuddyLoginFixture(t, upstream.server.URL, bypassed)

	status, body := fixture.do(t, fasthttp.MethodGet, "/api/providers/codebuddy-cn/codebuddy-cn/login/any-flow", "")
	if status != fasthttp.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", status, body)
	}
	const want = "codebuddy login requires an authenticated admin session; enable dashboard authentication first"
	if !strings.Contains(body, want) {
		t.Fatalf("body = %q, want it to carry %q", body, want)
	}
	if _, tokenCalls, _ := upstream.counts(); tokenCalls != 0 {
		t.Fatalf("upstream token polled %d times, want 0: a refused poll must not dial out", tokenCalls)
	}
}

// TestCodeBuddyLoginFlowTransitions drives the UI's poll loop end to end: pending twice, then the
// token pair, then the same stored answer without another upstream call.
func TestCodeBuddyLoginFlowTransitions(t *testing.T) {
	upstream := newFakeCodeBuddyUpstream(t, 2)
	fixture := newCodeBuddyLoginFixture(t, upstream.server.URL)

	status, body := fixture.do(t, fasthttp.MethodPost, "/api/providers/codebuddy-cn/codebuddy-cn/login", "{}")
	if status != fasthttp.StatusOK {
		t.Fatalf("start status = %d, want 200; body=%s", status, body)
	}
	started := decodeCodeBuddyLoginStart(t, body)
	if started.FlowID == "" {
		t.Fatalf("start body %q carried no flow_id", body)
	}
	if started.FlowID == "s1" {
		t.Fatalf("flow_id = %q leaked the upstream state", started.FlowID)
	}
	if started.AuthURL != "https://copilot.tencent.com/login?platform=CLI&state=s1" {
		t.Fatalf("auth_url = %q, want the upstream authUrl", started.AuthURL)
	}
	if strings.Contains(body, `"state":`) {
		t.Fatalf("start body %q exposed a state field", body)
	}
	// The start deadline must not be called expires_at: that key is the token expiry on the poll,
	// and a UI writing it into oauth_key_config.expires_at would store a 15-minute key.
	if strings.Contains(body, `"expires_at"`) {
		t.Fatalf("start body %q reused expires_at for the flow deadline", body)
	}
	if _, err := time.Parse(time.RFC3339, started.FlowExpiresAt); err != nil {
		t.Fatalf("flow_expires_at = %q is not RFC3339: %v", started.FlowExpiresAt, err)
	}
	if flowDelta := time.Until(mustParseCodeBuddyTime(t, started.FlowExpiresAt)); flowDelta < 14*time.Minute || flowDelta > 16*time.Minute {
		t.Fatalf("pending flow expires in %v, want the 15 minute window", flowDelta)
	}
	if stateCalls, _, _ := upstream.counts(); stateCalls != 1 {
		t.Fatalf("upstream state calls = %d, want 1", stateCalls)
	}

	pollPath := "/api/providers/codebuddy-cn/codebuddy-cn/login/" + started.FlowID
	for i := 0; i < 2; i++ {
		status, body = fixture.do(t, fasthttp.MethodGet, pollPath, "")
		if status != fasthttp.StatusOK {
			t.Fatalf("poll %d status = %d, want 200; body=%s", i+1, status, body)
		}
		pending := decodeCodeBuddyLoginStatus(t, body)
		if pending.Status != "pending" {
			t.Fatalf("poll %d status = %q, want pending; body=%s", i+1, pending.Status, body)
		}
		if pending.AccessToken != "" || pending.RefreshToken != "" {
			t.Fatalf("poll %d returned tokens before the browser completed: %s", i+1, body)
		}
		if strings.Contains(body, `"expires_at"`) {
			t.Fatalf("pending poll %q carried an expires_at, which the UI would read as a token expiry", body)
		}
	}

	status, body = fixture.do(t, fasthttp.MethodGet, pollPath, "")
	if status != fasthttp.StatusOK {
		t.Fatalf("completion poll status = %d, want 200; body=%s", status, body)
	}
	completed := decodeCodeBuddyLoginStatus(t, body)
	if completed.Status != "completed" {
		t.Fatalf("status = %q, want completed; body=%s", completed.Status, body)
	}
	if completed.AccessToken != "access-1" || completed.RefreshToken != "refresh-1" {
		t.Fatalf("tokens = %q/%q, want access-1/refresh-1", completed.AccessToken, completed.RefreshToken)
	}
	if completed.TokenType != "Bearer" {
		t.Fatalf("token_type = %q, want the upstream's Bearer", completed.TokenType)
	}
	if strings.Contains(body, `"flow_expires_at"`) {
		t.Fatalf("completed poll %q carried the flow deadline; that key belongs to the start response", body)
	}
	tokenExpiry, err := time.Parse(time.RFC3339, completed.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at = %q is not RFC3339: %v", completed.ExpiresAt, err)
	}
	if delta := time.Until(tokenExpiry); delta < 50*time.Minute || delta > 62*time.Minute {
		t.Fatalf("expires_at is %v away, want roughly the 3600s expiresIn", delta)
	}
	// The settled entry is pollable for its own shorter window, and the answer says so rather
	// than keeping the pending flow's deadline.
	stored, err := fixture.kv.Get("codebuddy:login:" + started.FlowID)
	if err != nil {
		t.Fatalf("completed flow vanished from the store: %v", err)
	}
	settledFlow, ok := stored.(*codeBuddyLoginFlow)
	if !ok {
		t.Fatalf("stored flow has type %T, want *codeBuddyLoginFlow", stored)
	}
	if settledFlow.State != "" {
		t.Fatalf("settled flow still carries the upstream state %q", settledFlow.State)
	}
	if remaining := time.Until(mustParseCodeBuddyTime(t, settledFlow.ExpiresAt)); remaining > 5*time.Minute || remaining < 4*time.Minute {
		t.Fatalf("settled flow keeps a %v window, want the shortened 5 minute one", remaining)
	}

	// A fourth poll after completion must answer from the stored flow. Another upstream call
	// would mean the flow was never settled, and a hang would leave the popup spinning.
	status, body = fixture.do(t, fasthttp.MethodGet, pollPath, "")
	if status != fasthttp.StatusOK {
		t.Fatalf("repeat poll status = %d, want 200; body=%s", status, body)
	}
	if repeated := decodeCodeBuddyLoginStatus(t, body); repeated != completed {
		t.Fatalf("repeat poll = %+v, want the same payload %+v", repeated, completed)
	}
	if stateCalls, tokenCalls, stateParam := upstream.counts(); stateCalls != 1 || tokenCalls != 3 {
		t.Fatalf("upstream calls state=%d token=%d, want 1/3: a settled flow must not be polled again", stateCalls, tokenCalls)
	} else if stateParam != "s1" {
		t.Fatalf("token poll state param = %q, want s1", stateParam)
	}
}

// TestCodeBuddyLoginEndpointIsNotCallerDialable pins requirement 1: the base URL comes from the
// provider config, so a body field naming another host must be inert.
func TestCodeBuddyLoginEndpointIsNotCallerDialable(t *testing.T) {
	upstream := newFakeCodeBuddyUpstream(t, 0)

	var attackerMu sync.Mutex
	attackerHits := 0
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attackerMu.Lock()
		attackerHits++
		attackerMu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"state":"attacker","authUrl":"https://evil.example/login"}`))
	}))
	t.Cleanup(attacker.Close)

	fixture := newCodeBuddyLoginFixture(t, upstream.server.URL)
	body := `{"endpoint":"` + attacker.URL + `"}`
	status, responseBody := fixture.do(t, fasthttp.MethodPost, "/api/providers/codebuddy-cn/codebuddy-cn/login", body)
	if status != fasthttp.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", status, responseBody)
	}
	started := decodeCodeBuddyLoginStart(t, responseBody)
	if started.AuthURL != "https://copilot.tencent.com/login?platform=CLI&state=s1" {
		t.Fatalf("auth_url = %q, want the configured provider's answer", started.AuthURL)
	}

	if stateCalls, _, _ := upstream.counts(); stateCalls != 1 {
		t.Fatalf("configured provider saw %d start calls, want 1", stateCalls)
	}
	attackerMu.Lock()
	hits := attackerHits
	attackerMu.Unlock()
	if hits != 0 {
		t.Fatalf("attacker host received %d requests; a caller-supplied endpoint was dialed", hits)
	}
}

// TestCodeBuddyLoginFlowIsBoundToItsProvider pins that a flow started for codebuddy-cn cannot be
// finished (or read) through another provider's path segment.
func TestCodeBuddyLoginFlowIsBoundToItsProvider(t *testing.T) {
	upstream := newFakeCodeBuddyUpstream(t, 0)
	fixture := newCodeBuddyLoginFixture(t, upstream.server.URL)
	// A second provider that is also a CodeBuddy implementation, so the path is refused by the
	// flow's own binding rather than by the provider-type check.
	fixture.config.Mu.Lock()
	fixture.config.Providers["codebuddy-cn-other"] = configstore.ProviderConfig{
		CustomProviderConfig: &schemas.CustomProviderConfig{BaseProviderType: schemas.CodeBuddyCN},
		NetworkConfig:        &schemas.NetworkConfig{BaseURL: upstream.server.URL},
	}
	fixture.config.Mu.Unlock()

	started := startCodeBuddyLoginOn(t, fixture, "codebuddy-cn")
	status, body := fixture.do(t, fasthttp.MethodGet, "/api/providers/codebuddy-cn-other/codebuddy-cn/login/"+started.FlowID, "")
	if status != fasthttp.StatusNotFound {
		t.Fatalf("cross-provider poll status = %d, want 404; body=%s", status, body)
	}
	if _, tokenCalls, _ := upstream.counts(); tokenCalls != 0 {
		t.Fatalf("upstream token polled %d times, want 0: a foreign provider must not finish the flow", tokenCalls)
	}
	stored, err := fixture.kv.Get("codebuddy:login:" + started.FlowID)
	if err != nil {
		t.Fatalf("flow vanished after a refused cross-provider poll: %v", err)
	}
	if flow, ok := stored.(*codeBuddyLoginFlow); !ok || flow.Status != codeBuddyLoginPending {
		t.Fatalf("a refused cross-provider poll changed the flow: %#v", stored)
	}

	// The flow is still usable through the provider that started it.
	status, body = fixture.do(t, fasthttp.MethodGet, "/api/providers/codebuddy-cn/codebuddy-cn/login/"+started.FlowID, "")
	if status != fasthttp.StatusOK {
		t.Fatalf("own-provider poll status = %d, want 200; body=%s", status, body)
	}
	if got := decodeCodeBuddyLoginStatus(t, body); got.Status != "completed" {
		t.Fatalf("own-provider poll status = %q, want completed", got.Status)
	}
}

// TestCodeBuddyLoginRefusedFlowIsTerminal covers the third state: an upstream refusal settles the
// flow as failed, carries no tokens, and is not retried upstream by later polls.
func TestCodeBuddyLoginRefusedFlowIsTerminal(t *testing.T) {
	const refusal = 40001
	upstream := newFakeCodeBuddyUpstreamWithFailure(t, 0, refusal)
	fixture := newCodeBuddyLoginFixture(t, upstream.server.URL)

	status, body := fixture.do(t, fasthttp.MethodPost, "/api/providers/codebuddy-cn/codebuddy-cn/login", "{}")
	if status != fasthttp.StatusOK {
		t.Fatalf("start status = %d, want 200; body=%s", status, body)
	}
	started := decodeCodeBuddyLoginStart(t, body)
	pollPath := "/api/providers/codebuddy-cn/codebuddy-cn/login/" + started.FlowID

	status, body = fixture.do(t, fasthttp.MethodGet, pollPath, "")
	if status != fasthttp.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", status, body)
	}
	failed := decodeCodeBuddyLoginStatus(t, body)
	if failed.Status != "failed" {
		t.Fatalf("status = %q, want failed; body=%s", failed.Status, body)
	}
	if failed.Error == "" {
		t.Fatalf("a failed flow carries no explanation: %s", body)
	}
	if strings.Contains(failed.Error, "s1") {
		t.Fatalf("error %q leaked the upstream state", failed.Error)
	}
	if failed.AccessToken != "" || failed.RefreshToken != "" {
		t.Fatalf("a failed flow returned tokens: %s", body)
	}

	status, body = fixture.do(t, fasthttp.MethodGet, pollPath, "")
	if status != fasthttp.StatusOK {
		t.Fatalf("repeat poll status = %d, want 200; body=%s", status, body)
	}
	if repeated := decodeCodeBuddyLoginStatus(t, body); repeated != failed {
		t.Fatalf("repeat poll = %+v, want the same terminal payload %+v", repeated, failed)
	}
	if _, tokenCalls, _ := upstream.counts(); tokenCalls != 1 {
		t.Fatalf("upstream token polled %d times, want 1: a failed flow must stay settled", tokenCalls)
	}
	stored, err := fixture.kv.Get("codebuddy:login:" + started.FlowID)
	if err != nil {
		t.Fatalf("failed flow vanished from the store: %v", err)
	}
	failedFlow, ok := stored.(*codeBuddyLoginFlow)
	if !ok {
		t.Fatalf("stored flow has type %T, want *codeBuddyLoginFlow", stored)
	}
	if remaining := time.Until(mustParseCodeBuddyTime(t, failedFlow.ExpiresAt)); remaining > 5*time.Minute || remaining < 4*time.Minute {
		t.Fatalf("failed flow keeps a %v window, want the shortened 5 minute one", remaining)
	}
	if failedFlow.State != "" {
		t.Fatalf("failed flow still carries the upstream state %q", failedFlow.State)
	}
}

// TestCodeBuddyLoginLosingSettleKeepsCompletedTokens forces the interleaving directly: a poll has
// already read a pending flow, a second poll completes it, and only then does the first try to
// settle as failed. Most of the way there is the local per-flow lock, but a peer replica is outside
// it, so the finished writer's answer must not be overwritten.
func TestCodeBuddyLoginLosingSettleKeepsCompletedTokens(t *testing.T) {
	upstream := newFakeCodeBuddyUpstream(t, 0)
	fixture := newCodeBuddyLoginFixture(t, upstream.server.URL)
	started := startCodeBuddyLoginOn(t, fixture, "codebuddy-cn")

	// The stale copy a racing poll would be holding: read while the flow was still pending.
	stale, err := loadCodeBuddyLoginFlow(fixture.kv, started.FlowID)
	if err != nil {
		t.Fatalf("load pending flow: %v", err)
	}
	if stale.Status != codeBuddyLoginPending {
		t.Fatalf("setup: flow status is %q, want pending", stale.Status)
	}

	// The winning poll completes through the real endpoint, so the stored record is exactly what
	// a browser sign-in produces.
	status, body := fixture.do(t, fasthttp.MethodGet, "/api/providers/codebuddy-cn/codebuddy-cn/login/"+started.FlowID, "")
	if status != fasthttp.StatusOK {
		t.Fatalf("winning poll status = %d, want 200; body=%s", status, body)
	}
	winner := decodeCodeBuddyLoginStatus(t, body)
	if winner.Status != "completed" || winner.AccessToken != "access-1" {
		t.Fatalf("winning poll = %+v, want the completed token pair", winner)
	}

	// The losing poll settles its stale copy as failed. It must observe the winner and answer with
	// the winner's payload instead of blanking the tokens.
	losingCtx := &fasthttp.RequestCtx{}
	fixture.handler.finishCodeBuddyLogin(losingCtx, fixture.kv, started.FlowID,
		failedCodeBuddyLogin(stale, "codebuddy login was refused by the provider (code 40901)"))
	if got := losingCtx.Response.StatusCode(); got != fasthttp.StatusOK {
		t.Fatalf("losing settle status = %d, want 200 with the winner's payload; body=%s", got, losingCtx.Response.Body())
	}
	losing := decodeCodeBuddyLoginStatus(t, string(losingCtx.Response.Body()))
	if losing != winner {
		t.Fatalf("losing settle returned %+v, want the winner's payload %+v", losing, winner)
	}

	stored, err := loadCodeBuddyLoginFlow(fixture.kv, started.FlowID)
	if err != nil {
		t.Fatalf("reload flow: %v", err)
	}
	if stored.Status != codeBuddyLoginCompleted {
		t.Fatalf("stored status = %q, want completed: a losing write overwrote the tokens", stored.Status)
	}
	if stored.AccessToken != "access-1" || stored.RefreshToken != "refresh-1" {
		t.Fatalf("stored tokens = %q/%q, want the completed pair", stored.AccessToken, stored.RefreshToken)
	}
}

// TestCodeBuddyLoginConcurrentPollsShareOneUpstreamCall is the end-to-end form of the same race:
// two polls of one pending flow arrive together, and the upstream (which answers terminal on every
// poll after the first) must be reached once. Both clients must see the completed payload.
func TestCodeBuddyLoginConcurrentPollsShareOneUpstreamCall(t *testing.T) {
	upstream := newFakeCodeBuddyUpstream(t, 0)
	upstream.failAfterFirstSuccess = true
	upstream.holdFirstToken = make(chan struct{})
	released := false
	release := func() {
		if !released {
			released = true
			close(upstream.holdFirstToken)
		}
	}
	defer release()

	fixture := newCodeBuddyLoginFixture(t, upstream.server.URL)
	started := startCodeBuddyLoginOn(t, fixture, "codebuddy-cn")
	pollPath := "/api/providers/codebuddy-cn/codebuddy-cn/login/" + started.FlowID

	type result struct {
		status int
		body   string
	}
	results := make(chan result, 2)
	poll := func() {
		status, body := fixture.do(t, fasthttp.MethodGet, pollPath, "")
		results <- result{status: status, body: body}
	}

	go poll()
	// Wait until one poll is parked inside the upstream call, then start the second.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, tokenCalls, _ := upstream.counts(); tokenCalls >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first poll never reached the upstream")
		}
		time.Sleep(time.Millisecond)
	}
	go poll()
	// Give the second poll time to arrive and block, then let the first finish.
	time.Sleep(50 * time.Millisecond)
	release()

	for i := 0; i < 2; i++ {
		select {
		case got := <-results:
			if got.status != fasthttp.StatusOK {
				t.Fatalf("poll %d status = %d, want 200; body=%s", i+1, got.status, got.body)
			}
			decoded := decodeCodeBuddyLoginStatus(t, got.body)
			if decoded.Status != "completed" || decoded.AccessToken != "access-1" || decoded.RefreshToken != "refresh-1" {
				t.Fatalf("poll %d = %+v, want the completed token pair", i+1, decoded)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a concurrent poll never answered")
		}
	}
	if _, tokenCalls, _ := upstream.counts(); tokenCalls != 1 {
		t.Fatalf("upstream token polled %d times, want 1: the second poll must read the settled flow", tokenCalls)
	}
	upstream.mu.Lock()
	maxActive := upstream.maxActiveTokens
	upstream.mu.Unlock()
	if maxActive != 1 {
		t.Fatalf("upstream saw %d token polls at once, want 1: one flow's state must not be presented twice", maxActive)
	}
}

// failingKVStore wraps a real store and refuses writes, which is how a full or broken store
// behaves from the handler's point of view.
type failingKVStore struct {
	schemas.KVStore
	err error
}

func (s failingKVStore) SetWithTTL(string, any, time.Duration) error { return s.err }
func (s failingKVStore) SetNXWithTTL(string, any, time.Duration) (bool, error) {
	return false, s.err
}

// TestCodeBuddyLoginUnsavedResultIsNotHandedOut pins that a terminal answer the store refuses is
// reported as an error rather than returned as success. Handing the tokens out anyway would leave
// the client holding credentials the server still calls pending, and the next poll would re-dial a
// state the upstream has already consumed.
func TestCodeBuddyLoginUnsavedResultIsNotHandedOut(t *testing.T) {
	upstream := newFakeCodeBuddyUpstream(t, 0)
	fixture := newCodeBuddyLoginFixture(t, upstream.server.URL)
	started := startCodeBuddyLoginOn(t, fixture, "codebuddy-cn")

	completed := &codeBuddyLoginFlow{
		Provider:     schemas.CodeBuddyCN,
		Status:       codeBuddyLoginCompleted,
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		ExpiresAt:    time.Now().Add(codeBuddyLoginSettledTTL).UTC().Format(time.RFC3339),
	}

	// A store that reads the real flow but refuses every write is what a full or broken store looks
	// like to the handler.
	ctx := &fasthttp.RequestCtx{}
	fixture.handler.finishCodeBuddyLogin(ctx, failingKVStore{KVStore: fixture.kv, err: errors.New("store is full")}, started.FlowID, completed)
	if got := ctx.Response.StatusCode(); got != fasthttp.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", got, ctx.Response.Body())
	}
	if body := string(ctx.Response.Body()); strings.Contains(body, "access-1") || strings.Contains(body, "refresh-1") {
		t.Fatalf("body %q handed out credentials the store never held", body)
	}

	// The flow really is still pending, so the client was told the truth: there is no stored
	// outcome to contradict.
	stored, err := loadCodeBuddyLoginFlow(fixture.kv, started.FlowID)
	if err != nil {
		t.Fatalf("reload flow: %v", err)
	}
	if stored.Status != codeBuddyLoginPending {
		t.Fatalf("stored status = %q, want pending: a failed write must not settle the record", stored.Status)
	}
}

// failingReadKVStore fails every read, standing in for a store that is down while a poll tries to
// settle. The safer choice is to refuse the write: overwriting blind is how a token pair dies.
type failingReadKVStore struct {
	schemas.KVStore
}

func (failingReadKVStore) Get(string) (any, error) { return nil, errors.New("store is down") }

func TestCodeBuddyLoginUnreadableStoreIsNotOverwritten(t *testing.T) {
	upstream := newFakeCodeBuddyUpstream(t, 0)
	fixture := newCodeBuddyLoginFixture(t, upstream.server.URL)
	started := startCodeBuddyLoginOn(t, fixture, "codebuddy-cn")

	ctx := &fasthttp.RequestCtx{}
	fixture.handler.finishCodeBuddyLogin(ctx, failingReadKVStore{KVStore: fixture.kv}, started.FlowID,
		failedCodeBuddyLogin(&codeBuddyLoginFlow{Provider: schemas.CodeBuddyCN}, "codebuddy login was refused by the provider (code 40901)"))
	if got := ctx.Response.StatusCode(); got != fasthttp.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", got, ctx.Response.Body())
	}
	stored, err := loadCodeBuddyLoginFlow(fixture.kv, started.FlowID)
	if err != nil {
		t.Fatalf("reload flow: %v", err)
	}
	if stored.Status != codeBuddyLoginPending {
		t.Fatalf("stored status = %q, want pending: an unreadable store must not be written blind", stored.Status)
	}
}

// TestCodeBuddyLoginUnknownProviderBeatsMissingStore pins the ordering at start: a provider the
// gateway does not know is a 404 even on a deployment whose store failed to initialise, rather than
// a 500 blaming the store for a request that was never going to work.
func TestCodeBuddyLoginUnknownProviderBeatsMissingStore(t *testing.T) {
	SetLogger(&mockLogger{})
	handler := &ProviderHandler{inMemoryStore: &lib.Config{}}

	var ctx fasthttp.RequestCtx
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/api/providers/no-such-provider/codebuddy-cn/login")
	ctx.SetUserValue("provider", "no-such-provider")

	handler.startCodeBuddyLogin(&ctx)

	if got := ctx.Response.StatusCode(); got != fasthttp.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", got, ctx.Response.Body())
	}
	if body := string(ctx.Response.Body()); strings.Contains(body, "kv store") {
		t.Fatalf("body %q blamed the store for an unknown provider", body)
	}
}

// TestCodeBuddyLoginPollRejectsUnknownProviderBeforeStore pins the same ordering on the poll route.
func TestCodeBuddyLoginPollRejectsUnknownProviderBeforeStore(t *testing.T) {
	SetLogger(&mockLogger{})
	handler := &ProviderHandler{inMemoryStore: &lib.Config{}}

	var ctx fasthttp.RequestCtx
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI("/api/providers/no-such-provider/codebuddy-cn/login/flow-1")
	ctx.SetUserValue("provider", "no-such-provider")
	ctx.SetUserValue("flow_id", "flow-1")

	handler.pollCodeBuddyLogin(&ctx)

	if got := ctx.Response.StatusCode(); got != fasthttp.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", got, ctx.Response.Body())
	}
	if body := string(ctx.Response.Body()); strings.Contains(body, "kv store") {
		t.Fatalf("body %q blamed the store for an unknown provider", body)
	}
}

// TestCodeBuddyLoginURLErrorDropsTheState pins that a malformed configured base_url cannot leak the
// upstream state through the *url.Error NewRequestWithContext wraps around its failure.
func TestCodeBuddyLoginURLErrorDropsTheState(t *testing.T) {
	SetLogger(&mockLogger{})
	handler := &ProviderHandler{inMemoryStore: &lib.Config{}}
	var ctx fasthttp.RequestCtx

	// An unparseable URL makes NewRequestWithContext fail before any dial.
	_, err := handler.codeBuddyLoginCall(&ctx, http.MethodGet, "https://exa mple.test/v2/plugin/auth/token?state=s1")
	if err == nil {
		t.Fatal("expected the malformed URL to be refused")
	}
	if strings.Contains(err.Error(), "state=s1") {
		t.Fatalf("error %q carried the upstream state", err.Error())
	}
}

// TestCodeBuddyLoginExpiredFlowIsGone pins that a flow past its deadline is terminal: the poll
// answers 404 and drops the entry rather than reporting pending forever.
func TestCodeBuddyLoginExpiredFlowIsGone(t *testing.T) {
	upstream := newFakeCodeBuddyUpstream(t, 0)
	fixture := newCodeBuddyLoginFixture(t, upstream.server.URL)

	const flowID = "expired-flow"
	// Stored as the JSON bytes a peer without a registered decoder would hand back, which is
	// also the shape the expiry check has to survive.
	stale := []byte(`{"state":"s1","provider":"codebuddy-cn","expires_at":"2020-01-01T00:00:00Z"}`)
	key := "codebuddy:login:" + flowID
	if err := fixture.kv.SetWithTTL(key, stale, 15*time.Minute); err != nil {
		t.Fatalf("seed expired flow: %v", err)
	}

	status, body := fixture.do(t, fasthttp.MethodGet, "/api/providers/codebuddy-cn/codebuddy-cn/login/"+flowID, "")
	if status != fasthttp.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", status, body)
	}
	if _, err := fixture.kv.Get(key); err == nil {
		t.Fatal("expired flow still in the store; a repeat poll could keep finding it")
	}
	if _, tokenCalls, _ := upstream.counts(); tokenCalls != 0 {
		t.Fatalf("upstream token polled %d times for an expired flow, want 0", tokenCalls)
	}
}
