package handlers

import (
	"encoding/json"
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
type codeBuddyLoginStartBody struct {
	FlowID    string `json:"flow_id"`
	AuthURL   string `json:"auth_url"`
	ExpiresAt string `json:"expires_at"`
}

// codeBuddyLoginStatusBody mirrors the poll response.
type codeBuddyLoginStatusBody struct {
	Status       string `json:"status"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    string `json:"expires_at"`
	Error        string `json:"error"`
}

// codeBuddyLoginFixture serves the provider routes over an in-memory listener, so a test
// exercises the real router, the real path parameters and the real JSON encoding.
type codeBuddyLoginFixture struct {
	kv     *kvstore.Store
	client *fasthttp.Client
}

func newCodeBuddyLoginFixture(t *testing.T, upstreamBaseURL string, middlewares ...schemas.BifrostHTTPMiddleware) *codeBuddyLoginFixture {
	t.Helper()
	SetLogger(&mockLogger{})

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

	r := router.New()
	(&ProviderHandler{inMemoryStore: config}).RegisterRoutes(r, middlewares...)

	server := &fasthttp.Server{Handler: r.Handler}
	listener := fasthttputil.NewInmemoryListener()
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Shutdown()
		_ = listener.Close()
		_ = store.Close()
	})

	return &codeBuddyLoginFixture{
		kv: store,
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
	tokenState           string
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
			f.mu.Lock()
			f.tokenCalls++
			f.tokenState = r.URL.Query().Get("state")
			pending := f.pendingBeforeSuccess
			if pending > 0 {
				f.pendingBeforeSuccess--
			}
			failure := f.failureCode
			f.mu.Unlock()
			if failure != 0 {
				_, _ = w.Write([]byte(fmt.Sprintf(`{"code":%d,"message":"refused"}`, failure)))
				return
			}
			if pending > 0 {
				_, _ = w.Write([]byte(`{"code":11217}`))
				return
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-1","refreshToken":"refresh-1","expiresIn":3600,"tokenType":"Bearer"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":404}`))
		}
	}))
	t.Cleanup(f.server.Close)
	return f
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
	if _, err := time.Parse(time.RFC3339, started.ExpiresAt); err != nil {
		t.Fatalf("expires_at = %q is not RFC3339: %v", started.ExpiresAt, err)
	}
	if flowDelta := time.Until(mustParseCodeBuddyTime(t, started.ExpiresAt)); flowDelta < 14*time.Minute || flowDelta > 16*time.Minute {
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
