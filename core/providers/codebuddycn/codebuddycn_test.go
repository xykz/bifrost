package codebuddycn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

// Compile-time check that CodeBuddyCNProvider satisfies the full Provider interface.
var _ schemas.Provider = (*CodeBuddyCNProvider)(nil)

// testLogger is a minimal logger; the package's tests never assert on log output.
type testLogger struct{}

func (l *testLogger) Debug(string, ...any)                   {}
func (l *testLogger) Info(string, ...any)                    {}
func (l *testLogger) Warn(string, ...any)                    {}
func (l *testLogger) Error(string, ...any)                   {}
func (l *testLogger) Fatal(string, ...any)                   {}
func (l *testLogger) SetLevel(schemas.LogLevel)              {}
func (l *testLogger) SetOutputType(schemas.LoggerOutputType) {}
func (l *testLogger) LogHTTPRequest(schemas.LogLevel, string) schemas.LogEventBuilder {
	return schemas.NoopLogEvent
}

func newTestProvider(t *testing.T, serverURL string) *CodeBuddyCNProvider {
	t.Helper()
	// The test file lives in-package to reach editorHeaders and authHeaderFor, so it cannot import
	// the root bifrost package for NewNoOpLogger: bifrost imports this package, and Go rejects the
	// test-only cycle. testLogger is the same stand-in.
	config := &schemas.ProviderConfig{
		NetworkConfig: schemas.NetworkConfig{DefaultRequestTimeoutInSeconds: 30},
	}
	if serverURL != "" {
		config.NetworkConfig.BaseURL = serverURL
	}
	provider, err := NewCodeBuddyCNProvider(config, &testLogger{})
	require.NoError(t, err)
	return provider
}

func TestEditorHeadersCarryCLIIdentity(t *testing.T) {
	h := editorHeaders()
	// GetValue has a pointer receiver and a map index is not addressable, so each entry is read
	// through a local first.
	product := h["X-Product"]
	ideType := h["X-IDE-Type"]
	ideName := h["X-IDE-Name"]
	ideVersion := h["X-IDE-Version"]
	require.Equal(t, "SaaS", product.GetValue())
	require.Equal(t, "CLI", ideType.GetValue())
	require.Equal(t, "CodeBuddy", ideName.GetValue())
	require.Equal(t, "0.0.0", ideVersion.GetValue())
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

func TestAuthHeaderForCarriesNoCredentialWithoutOne(t *testing.T) {
	got := authHeaderFor(schemas.Key{}, "")
	require.Empty(t, got)
	require.NotContains(t, got, "X-API-Key")
	require.NotContains(t, got, "Authorization")
}

func TestProviderRejectsUnsupportedOperations(t *testing.T) {
	p := newTestProvider(t, "")
	require.Equal(t, schemas.CodeBuddyCN, p.GetProviderKey())

	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	_, bErr := p.Embedding(ctx, schemas.Key{}, &schemas.BifrostEmbeddingRequest{})
	require.NotNil(t, bErr)
	require.Contains(t, bErr.Error.Message, "is not supported by")
}

// Every operation the provider does not serve returns the shared unsupported-operation error with
// the request type it was called for, so a copy-pasted constant cannot silently report the wrong
// operation to clients.
func TestEveryUnsupportedOperationReportsItsRequestType(t *testing.T) {
	p := newTestProvider(t, "")
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{}

	cases := []struct {
		name        string
		requestType schemas.RequestType
		invoke      func() *schemas.BifrostError
	}{
		{"ModelRetrieve", schemas.ModelRetrieveRequest, func() *schemas.BifrostError {
			_, bErr := p.ModelRetrieve(ctx, key, &schemas.BifrostModelRetrieveRequest{})
			return bErr
		}},
		{"TextCompletion", schemas.TextCompletionRequest, func() *schemas.BifrostError {
			_, bErr := p.TextCompletion(ctx, key, &schemas.BifrostTextCompletionRequest{})
			return bErr
		}},
		{"TextCompletionStream", schemas.TextCompletionStreamRequest, func() *schemas.BifrostError {
			_, bErr := p.TextCompletionStream(ctx, nil, nil, key, &schemas.BifrostTextCompletionRequest{})
			return bErr
		}},
		{"Responses", schemas.ResponsesRequest, func() *schemas.BifrostError {
			_, bErr := p.Responses(ctx, key, &schemas.BifrostResponsesRequest{})
			return bErr
		}},
		{"ResponsesStream", schemas.ResponsesStreamRequest, func() *schemas.BifrostError {
			_, bErr := p.ResponsesStream(ctx, nil, nil, key, &schemas.BifrostResponsesRequest{})
			return bErr
		}},
		{"CountTokens", schemas.CountTokensRequest, func() *schemas.BifrostError {
			_, bErr := p.CountTokens(ctx, key, &schemas.BifrostResponsesRequest{})
			return bErr
		}},
		{"Compaction", schemas.CompactionRequest, func() *schemas.BifrostError {
			_, bErr := p.Compaction(ctx, key, &schemas.BifrostCompactionRequest{})
			return bErr
		}},
		{"Embedding", schemas.EmbeddingRequest, func() *schemas.BifrostError {
			_, bErr := p.Embedding(ctx, key, &schemas.BifrostEmbeddingRequest{})
			return bErr
		}},
		{"Rerank", schemas.RerankRequest, func() *schemas.BifrostError {
			_, bErr := p.Rerank(ctx, key, &schemas.BifrostRerankRequest{})
			return bErr
		}},
		{"Decision", schemas.DecisionRequest, func() *schemas.BifrostError {
			_, bErr := p.Decision(ctx, key, &schemas.BifrostDecisionRequest{})
			return bErr
		}},
		{"OCR", schemas.OCRRequest, func() *schemas.BifrostError {
			_, bErr := p.OCR(ctx, key, &schemas.BifrostOCRRequest{})
			return bErr
		}},
		{"Speech", schemas.SpeechRequest, func() *schemas.BifrostError {
			_, bErr := p.Speech(ctx, key, &schemas.BifrostSpeechRequest{})
			return bErr
		}},
		{"SpeechStream", schemas.SpeechStreamRequest, func() *schemas.BifrostError {
			_, bErr := p.SpeechStream(ctx, nil, nil, key, &schemas.BifrostSpeechRequest{})
			return bErr
		}},
		{"Transcription", schemas.TranscriptionRequest, func() *schemas.BifrostError {
			_, bErr := p.Transcription(ctx, key, &schemas.BifrostTranscriptionRequest{})
			return bErr
		}},
		{"TranscriptionStream", schemas.TranscriptionStreamRequest, func() *schemas.BifrostError {
			_, bErr := p.TranscriptionStream(ctx, nil, nil, key, &schemas.BifrostTranscriptionRequest{})
			return bErr
		}},
		{"ImageGeneration", schemas.ImageGenerationRequest, func() *schemas.BifrostError {
			_, bErr := p.ImageGeneration(ctx, key, &schemas.BifrostImageGenerationRequest{})
			return bErr
		}},
		{"ImageGenerationStream", schemas.ImageGenerationStreamRequest, func() *schemas.BifrostError {
			_, bErr := p.ImageGenerationStream(ctx, nil, nil, key, &schemas.BifrostImageGenerationRequest{})
			return bErr
		}},
		{"ImageEdit", schemas.ImageEditRequest, func() *schemas.BifrostError {
			_, bErr := p.ImageEdit(ctx, key, &schemas.BifrostImageEditRequest{})
			return bErr
		}},
		{"ImageEditStream", schemas.ImageEditStreamRequest, func() *schemas.BifrostError {
			_, bErr := p.ImageEditStream(ctx, nil, nil, key, &schemas.BifrostImageEditRequest{})
			return bErr
		}},
		{"ImageVariation", schemas.ImageVariationRequest, func() *schemas.BifrostError {
			_, bErr := p.ImageVariation(ctx, key, &schemas.BifrostImageVariationRequest{})
			return bErr
		}},
		{"VideoGeneration", schemas.VideoGenerationRequest, func() *schemas.BifrostError {
			_, bErr := p.VideoGeneration(ctx, key, &schemas.BifrostVideoGenerationRequest{})
			return bErr
		}},
		{"VideoEdit", schemas.VideoEditRequest, func() *schemas.BifrostError {
			_, bErr := p.VideoEdit(ctx, key, &schemas.BifrostVideoEditRequest{})
			return bErr
		}},
		{"VideoRetrieve", schemas.VideoRetrieveRequest, func() *schemas.BifrostError {
			_, bErr := p.VideoRetrieve(ctx, key, &schemas.BifrostVideoRetrieveRequest{})
			return bErr
		}},
		{"VideoDownload", schemas.VideoDownloadRequest, func() *schemas.BifrostError {
			_, bErr := p.VideoDownload(ctx, key, &schemas.BifrostVideoDownloadRequest{})
			return bErr
		}},
		{"VideoDelete", schemas.VideoDeleteRequest, func() *schemas.BifrostError {
			_, bErr := p.VideoDelete(ctx, key, &schemas.BifrostVideoDeleteRequest{})
			return bErr
		}},
		{"VideoList", schemas.VideoListRequest, func() *schemas.BifrostError {
			_, bErr := p.VideoList(ctx, key, &schemas.BifrostVideoListRequest{})
			return bErr
		}},
		{"VideoRemix", schemas.VideoRemixRequest, func() *schemas.BifrostError {
			_, bErr := p.VideoRemix(ctx, key, &schemas.BifrostVideoRemixRequest{})
			return bErr
		}},
		{"BatchCreate", schemas.BatchCreateRequest, func() *schemas.BifrostError {
			_, bErr := p.BatchCreate(ctx, key, &schemas.BifrostBatchCreateRequest{})
			return bErr
		}},
		{"BatchList", schemas.BatchListRequest, func() *schemas.BifrostError {
			_, bErr := p.BatchList(ctx, nil, &schemas.BifrostBatchListRequest{})
			return bErr
		}},
		{"BatchRetrieve", schemas.BatchRetrieveRequest, func() *schemas.BifrostError {
			_, bErr := p.BatchRetrieve(ctx, nil, &schemas.BifrostBatchRetrieveRequest{})
			return bErr
		}},
		{"BatchCancel", schemas.BatchCancelRequest, func() *schemas.BifrostError {
			_, bErr := p.BatchCancel(ctx, nil, &schemas.BifrostBatchCancelRequest{})
			return bErr
		}},
		{"BatchDelete", schemas.BatchDeleteRequest, func() *schemas.BifrostError {
			_, bErr := p.BatchDelete(ctx, nil, &schemas.BifrostBatchDeleteRequest{})
			return bErr
		}},
		{"BatchResults", schemas.BatchResultsRequest, func() *schemas.BifrostError {
			_, bErr := p.BatchResults(ctx, nil, &schemas.BifrostBatchResultsRequest{})
			return bErr
		}},
		{"FileUpload", schemas.FileUploadRequest, func() *schemas.BifrostError {
			_, bErr := p.FileUpload(ctx, key, &schemas.BifrostFileUploadRequest{})
			return bErr
		}},
		{"FileList", schemas.FileListRequest, func() *schemas.BifrostError {
			_, bErr := p.FileList(ctx, nil, &schemas.BifrostFileListRequest{})
			return bErr
		}},
		{"FileRetrieve", schemas.FileRetrieveRequest, func() *schemas.BifrostError {
			_, bErr := p.FileRetrieve(ctx, nil, &schemas.BifrostFileRetrieveRequest{})
			return bErr
		}},
		{"FileDelete", schemas.FileDeleteRequest, func() *schemas.BifrostError {
			_, bErr := p.FileDelete(ctx, nil, &schemas.BifrostFileDeleteRequest{})
			return bErr
		}},
		{"FileContent", schemas.FileContentRequest, func() *schemas.BifrostError {
			_, bErr := p.FileContent(ctx, nil, &schemas.BifrostFileContentRequest{})
			return bErr
		}},
		{"CachedContentCreate", schemas.CachedContentCreateRequest, func() *schemas.BifrostError {
			_, bErr := p.CachedContentCreate(ctx, key, &schemas.BifrostCachedContentCreateRequest{})
			return bErr
		}},
		{"CachedContentList", schemas.CachedContentListRequest, func() *schemas.BifrostError {
			_, bErr := p.CachedContentList(ctx, nil, &schemas.BifrostCachedContentListRequest{})
			return bErr
		}},
		{"CachedContentRetrieve", schemas.CachedContentRetrieveRequest, func() *schemas.BifrostError {
			_, bErr := p.CachedContentRetrieve(ctx, nil, &schemas.BifrostCachedContentRetrieveRequest{})
			return bErr
		}},
		{"CachedContentUpdate", schemas.CachedContentUpdateRequest, func() *schemas.BifrostError {
			_, bErr := p.CachedContentUpdate(ctx, nil, &schemas.BifrostCachedContentUpdateRequest{})
			return bErr
		}},
		{"CachedContentDelete", schemas.CachedContentDeleteRequest, func() *schemas.BifrostError {
			_, bErr := p.CachedContentDelete(ctx, nil, &schemas.BifrostCachedContentDeleteRequest{})
			return bErr
		}},
		{"ContainerCreate", schemas.ContainerCreateRequest, func() *schemas.BifrostError {
			_, bErr := p.ContainerCreate(ctx, key, &schemas.BifrostContainerCreateRequest{})
			return bErr
		}},
		{"ContainerList", schemas.ContainerListRequest, func() *schemas.BifrostError {
			_, bErr := p.ContainerList(ctx, nil, &schemas.BifrostContainerListRequest{})
			return bErr
		}},
		{"ContainerRetrieve", schemas.ContainerRetrieveRequest, func() *schemas.BifrostError {
			_, bErr := p.ContainerRetrieve(ctx, nil, &schemas.BifrostContainerRetrieveRequest{})
			return bErr
		}},
		{"ContainerDelete", schemas.ContainerDeleteRequest, func() *schemas.BifrostError {
			_, bErr := p.ContainerDelete(ctx, nil, &schemas.BifrostContainerDeleteRequest{})
			return bErr
		}},
		{"ContainerFileCreate", schemas.ContainerFileCreateRequest, func() *schemas.BifrostError {
			_, bErr := p.ContainerFileCreate(ctx, key, &schemas.BifrostContainerFileCreateRequest{})
			return bErr
		}},
		{"ContainerFileList", schemas.ContainerFileListRequest, func() *schemas.BifrostError {
			_, bErr := p.ContainerFileList(ctx, nil, &schemas.BifrostContainerFileListRequest{})
			return bErr
		}},
		{"ContainerFileRetrieve", schemas.ContainerFileRetrieveRequest, func() *schemas.BifrostError {
			_, bErr := p.ContainerFileRetrieve(ctx, nil, &schemas.BifrostContainerFileRetrieveRequest{})
			return bErr
		}},
		{"ContainerFileContent", schemas.ContainerFileContentRequest, func() *schemas.BifrostError {
			_, bErr := p.ContainerFileContent(ctx, nil, &schemas.BifrostContainerFileContentRequest{})
			return bErr
		}},
		{"ContainerFileDelete", schemas.ContainerFileDeleteRequest, func() *schemas.BifrostError {
			_, bErr := p.ContainerFileDelete(ctx, nil, &schemas.BifrostContainerFileDeleteRequest{})
			return bErr
		}},
		{"Passthrough", schemas.PassthroughRequest, func() *schemas.BifrostError {
			_, bErr := p.Passthrough(ctx, key, &schemas.BifrostPassthroughRequest{})
			return bErr
		}},
		{"PassthroughStream", schemas.PassthroughStreamRequest, func() *schemas.BifrostError {
			_, bErr := p.PassthroughStream(ctx, nil, nil, key, &schemas.BifrostPassthroughRequest{})
			return bErr
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bErr := tc.invoke()
			require.NotNil(t, bErr)
			require.NotNil(t, bErr.Error)
			require.Equal(t, schemas.Ptr("unsupported_operation"), bErr.Error.Code)
			require.Equal(t,
				providerUtils.NewUnsupportedOperationError(tc.requestType, schemas.CodeBuddyCN).Error.Message,
				bErr.Error.Message)
		})
	}
}

func TestDefaultBaseURL(t *testing.T) {
	cfg := &schemas.ProviderConfig{}
	_, err := NewCodeBuddyCNProvider(cfg, &testLogger{})
	require.NoError(t, err)
	require.Equal(t, "https://copilot.tencent.com", cfg.NetworkConfig.BaseURL)
}

func TestConfiguredBaseURLKeepsTrailingSlashTrimmed(t *testing.T) {
	cfg := &schemas.ProviderConfig{NetworkConfig: schemas.NetworkConfig{BaseURL: "https://example.test/v2/"}}
	p, err := NewCodeBuddyCNProvider(cfg, &testLogger{})
	require.NoError(t, err)
	require.Equal(t, "https://example.test/v2", p.networkConfig.BaseURL)
}

// A pasted key must reach the gateway as X-API-Key on /v2/chat/completions, alongside the editor
// identity headers the gateway validates before it looks at the credential.
func TestChatCompletionSendsAPIKeyAndEditorHeaders(t *testing.T) {
	var mu sync.Mutex
	var gotPath, gotMethod, gotAPIKey, gotAuth, gotProduct, gotIDEType, gotIDEName, gotIDEVersion string
	var dispatched int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		dispatched++
		gotPath, gotMethod = r.URL.Path, r.Method
		gotAPIKey, gotAuth = r.Header.Get("X-API-Key"), r.Header.Get("Authorization")
		gotProduct = r.Header.Get("X-Product")
		gotIDEType = r.Header.Get("X-IDE-Type")
		gotIDEName = r.Header.Get("X-IDE-Name")
		gotIDEVersion = r.Header.Get("X-IDE-Version")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"hunyuan-chat","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{Value: *schemas.NewSecretVar("sk-pasted")}

	response, bErr := p.ChatCompletion(ctx, key, chatRequest())
	require.Nil(t, bErr)
	require.NotNil(t, response)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, dispatched)
	require.Equal(t, "/v2/chat/completions", gotPath)
	require.Equal(t, http.MethodPost, gotMethod)
	require.Equal(t, "sk-pasted", gotAPIKey)
	require.Empty(t, gotAuth, "a pasted key must not travel in Authorization")
	require.Equal(t, "SaaS", gotProduct)
	require.Equal(t, "CLI", gotIDEType)
	require.Equal(t, "CodeBuddy", gotIDEName)
	require.Equal(t, "0.0.0", gotIDEVersion)
}

// The streaming path is decorated exactly like the unary one, and the shared streaming helper
// asks upstream for a stream. Nothing is aggregated here: the caller's shape decides which of the
// two paths runs, and both are legal upstream because the official CLI builds both.
func TestChatCompletionStreamDecoratesTheRequest(t *testing.T) {
	var mu sync.Mutex
	var gotStream bool
	var gotAPIKey, gotProduct, gotAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Stream *bool `json:"stream"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)

		mu.Lock()
		gotStream = payload.Stream != nil && *payload.Stream
		gotAPIKey = r.Header.Get("X-API-Key")
		gotProduct = r.Header.Get("X-Product")
		gotAccept = r.Header.Get("Accept")
		mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"hunyuan-chat\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hi\"},\"finish_reason\":null}]}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{Value: *schemas.NewSecretVar("sk-pasted")}
	request := chatRequest()

	postHookRunner := func(_ *schemas.BifrostContext, result *schemas.BifrostResponse, _ *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError) {
		return result, nil
	}
	stream, bErr := p.ChatCompletionStream(ctx, postHookRunner, nil, key, request)
	require.Nil(t, bErr)

	chunks := 0
	for chunk := range stream {
		if chunk != nil {
			chunks++
		}
	}
	require.Positive(t, chunks, "the stream must emit at least one chunk")

	mu.Lock()
	defer mu.Unlock()
	require.True(t, gotStream, "the streaming path must ask upstream for a stream")
	require.Equal(t, "sk-pasted", gotAPIKey)
	require.Equal(t, "SaaS", gotProduct)
	require.Contains(t, gotAccept, "text/event-stream")
}

// An oauth key mints an access token from the refresh endpoint and sends it as a bearer, never as
// X-API-Key. The second call must reuse the cached token instead of refreshing again.
func TestChatCompletionRefreshesOAuthKeyAndReusesTheToken(t *testing.T) {
	var mu sync.Mutex
	var refreshes int
	var gotAuth, gotAPIKey, gotRefreshToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v2/plugin/auth/token/refresh":
			refreshes++
			gotRefreshToken = r.Header.Get("X-Refresh-Token")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-1","refreshToken":"refresh-2","expiresIn":3600}}`))
		case "/v2/chat/completions":
			gotAuth, gotAPIKey = r.Header.Get("Authorization"), r.Header.Get("X-API-Key")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"hunyuan-chat","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{OAuthKeyConfig: &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(server.URL + "/v2/plugin/auth/token/refresh"),
		RefreshToken: schemas.NewSecretVar("refresh-1"),
	}}

	for range 2 {
		response, bErr := p.ChatCompletion(ctx, key, chatRequest())
		require.Nil(t, bErr)
		require.NotNil(t, response)
	}

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, refreshes, "the minted token must be reused until it nears expiry")
	require.Equal(t, "refresh-1", gotRefreshToken)
	require.Equal(t, "Bearer access-1", gotAuth)
	require.Empty(t, gotAPIKey, "an oauth access token must not travel in X-API-Key")
}

// The gateway serves no model catalogue, so a 404 on the live listing answers with the pinned one.
func TestListModelsFallsBackToThePinnedCatalog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	keys := []schemas.Key{{Value: *schemas.NewSecretVar("sk-pasted"), Models: schemas.WhiteList{"*"}}}

	response, bErr := p.ListModels(ctx, keys, &schemas.BifrostListModelsRequest{})
	require.Nil(t, bErr)
	require.NotEmpty(t, response.Data)
	for _, model := range response.Data {
		require.Contains(t, model.ID, string(schemas.CodeBuddyCN)+"/")
	}
}

// A live listing that fails for any other reason is reported rather than masked by the catalog.
func TestListModelsReportsNonMissingCatalogueErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":500,"msg":"boom"}`))
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	keys := []schemas.Key{{Value: *schemas.NewSecretVar("sk-pasted"), Models: schemas.WhiteList{"*"}}}

	_, bErr := p.ListModels(ctx, keys, &schemas.BifrostListModelsRequest{})
	require.NotNil(t, bErr)
	require.Equal(t, schemas.Ptr(http.StatusBadGateway), bErr.StatusCode)
}

func TestParseErrorClassifiesDeadCredentials(t *testing.T) {
	tests := []struct {
		name               string
		status             int
		body               string
		wantStatus         int
		wantCode           *string
		wantAllowFallbacks *bool
		wantMessage        string
	}{
		{
			name:               "html 401 from the fronting gateway",
			status:             http.StatusUnauthorized,
			body:               "<html><body>401 Authorization Required</body></html>",
			wantStatus:         http.StatusUnauthorized,
			wantAllowFallbacks: schemas.Ptr(false),
			wantMessage:        "codebuddy-cn: the credential was rejected",
		},
		{
			name:               "dead refresh token code in a 200 body",
			status:             http.StatusOK,
			body:               `{"code":12153,"msg":"refresh token invalid"}`,
			wantStatus:         http.StatusUnauthorized,
			wantCode:           schemas.Ptr("12153"),
			wantAllowFallbacks: schemas.Ptr(false),
			wantMessage:        "codebuddy-cn: refresh token invalid (code 12153)",
		},
		{
			name:        "unknown code is retriable",
			status:      http.StatusOK,
			body:        `{"code":40001,"msg":"model not available"}`,
			wantStatus:  http.StatusBadGateway,
			wantCode:    schemas.Ptr("40001"),
			wantMessage: "codebuddy-cn: model not available (code 40001)",
		},
		{
			name:        "bare message envelope",
			status:      http.StatusBadRequest,
			body:        `{"message":"invalid_format"}`,
			wantStatus:  http.StatusBadGateway,
			wantMessage: "codebuddy-cn: invalid_format",
		},
		{
			name:        "empty body keeps the status in the message",
			status:      http.StatusInternalServerError,
			body:        "",
			wantStatus:  http.StatusBadGateway,
			wantMessage: "codebuddy-cn: the provider returned status 500 without a message",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseError(fasthttpResponse(tc.status, tc.body))
			require.NotNil(t, got.Error)
			require.NotNil(t, got.StatusCode)
			require.Equal(t, tc.wantStatus, *got.StatusCode)

			if tc.wantCode == nil {
				require.Nil(t, got.Error.Code)
			} else {
				require.NotNil(t, got.Error.Code)
				require.Equal(t, *tc.wantCode, *got.Error.Code)
			}

			if tc.wantAllowFallbacks == nil {
				require.Nil(t, got.AllowFallbacks, "a retriable failure leaves fallbacks allowed")
			} else {
				require.NotNil(t, got.AllowFallbacks)
				require.Equal(t, *tc.wantAllowFallbacks, *got.AllowFallbacks)
			}

			require.Contains(t, got.Error.Message, tc.wantMessage)
		})
	}
}

// A pasted value is served as-is and never reaches the token endpoint.
func TestResolveKeyLeavesPastedValuesAlone(t *testing.T) {
	p := newTestProvider(t, "")
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)

	resolved, bErr := p.resolveKey(ctx, schemas.Key{Value: *schemas.NewSecretVar("sk-pasted")})
	require.Nil(t, bErr)
	require.Equal(t, "sk-pasted", resolved.Value.GetValue())
}

// fasthttpResponse builds the response shape the error parser reads.
func fasthttpResponse(status int, body string) *fasthttp.Response {
	resp := fasthttp.AcquireResponse()
	resp.SetStatusCode(status)
	resp.SetBodyString(body)
	return resp
}

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

// BenchmarkResolveKeyWarm is the per-request cost of a browser_login key once its access token is
// cached: deriving the credential's cache key and the cache lookup. A pasted key never reaches
// this path — BenchmarkAuthHeaderForStaticKey covers that one.
func BenchmarkResolveKeyWarm(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-1","refreshToken":"refresh-2","expiresIn":3600}}`))
	}))
	defer server.Close()

	provider, err := NewCodeBuddyCNProvider(&schemas.ProviderConfig{
		NetworkConfig: schemas.NetworkConfig{DefaultRequestTimeoutInSeconds: 10, AllowPrivateNetwork: true},
	}, &testLogger{})
	if err != nil {
		b.Fatal(err)
	}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{ID: "key-1", OAuthKeyConfig: &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(server.URL + "/v2/plugin/auth/token/refresh"),
		RefreshToken: schemas.NewSecretVar("refresh-1"),
	}}
	if _, bErr := provider.resolveKey(ctx, key); bErr != nil {
		b.Fatal(bErr)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, bErr := provider.resolveKey(ctx, key); bErr != nil {
			b.Fatal(bErr)
		}
	}
}

// chatRequest is the smallest request the shared OpenAI converter accepts.
func chatRequest() *schemas.BifrostChatRequest {
	return &schemas.BifrostChatRequest{
		Provider: schemas.CodeBuddyCN,
		Model:    "hunyuan-chat",
		Input: []schemas.ChatMessage{{
			Role:    schemas.ChatMessageRoleUser,
			Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("hi")},
		}},
	}
}
