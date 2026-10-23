package codebuddycn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/providers/openai"
	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
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

func newTestProvider(t testing.TB, serverURL string) *CodeBuddyCNProvider {
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

// CodeBuddy reports most inference failures as an HTTP 200 whose body carries the gateway's own
// {"code":N,"msg":"..."} envelope. Nothing in the shared OpenAI path looks for a top-level code,
// so without the provider's own response handler these reach the caller as a success with no
// choices and no usage. Each case below is a real server answering 200.
//
// The bare {"message":"..."} shape is not covered here: the front end sends it with a non-200
// status, so it reaches parseError. TestParseErrorClassifiesDeadCredentials pins that path.
func TestChatCompletionDetectsInBandErrorEnvelopes(t *testing.T) {
	tests := []struct {
		name               string
		body               string
		wantStatus         int
		wantCode           string
		wantAllowFallbacks *bool
		wantMessage        string
	}{
		{
			name:        "retriable failure",
			body:        `{"code":40001,"msg":"model not available"}`,
			wantStatus:  http.StatusBadGateway,
			wantCode:    "40001",
			wantMessage: "model not available",
		},
		{
			name:               "dead refresh token is permanent",
			body:               `{"code":12153,"msg":"refresh token invalid"}`,
			wantStatus:         http.StatusUnauthorized,
			wantCode:           "12153",
			wantAllowFallbacks: schemas.Ptr(false),
			wantMessage:        "refresh token invalid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			p := newTestProvider(t, server.URL)
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			key := schemas.Key{Value: *schemas.NewSecretVar("sk-pasted")}

			response, bErr := p.ChatCompletion(ctx, key, chatRequest())
			require.Nil(t, response, "an in-band failure must not return a response")
			require.NotNil(t, bErr, "a 200 carrying a code envelope is a failure, not a success")
			require.NotNil(t, bErr.StatusCode)
			require.Equal(t, tc.wantStatus, *bErr.StatusCode)
			require.NotNil(t, bErr.Error)
			require.Contains(t, bErr.Error.Message, tc.wantMessage)

			if tc.wantCode == "" {
				require.Nil(t, bErr.Error.Code)
			} else {
				require.NotNil(t, bErr.Error.Code)
				require.Equal(t, tc.wantCode, *bErr.Error.Code)
			}
			if tc.wantAllowFallbacks == nil {
				require.Nil(t, bErr.AllowFallbacks, "a retriable failure leaves fallbacks allowed")
			} else {
				require.NotNil(t, bErr.AllowFallbacks)
				require.Equal(t, *tc.wantAllowFallbacks, *bErr.AllowFallbacks)
			}
		})
	}
}

// The handler must not disturb the happy path: a normal completion body still decodes into a
// response with its content intact.
func TestChatCompletionSucceedsOnANormalBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	require.Len(t, response.Choices, 1)
	require.NotNil(t, response.Choices[0].ChatNonStreamResponseChoice)
	message := response.Choices[0].ChatNonStreamResponseChoice.Message
	require.NotNil(t, message)
	require.NotNil(t, message.Content)
	require.NotNil(t, message.Content.ContentStr)
	require.Equal(t, "hello", *message.Content.ContentStr)
	require.NotNil(t, response.Usage)
}

// A code envelope inside an SSE frame must become an error chunk, not a payload-less chunk the
// caller silently discards.
func TestChatCompletionStreamSurfacesInBandErrorFrames(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"code\":12153,\"msg\":\"refresh token invalid\"}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{Value: *schemas.NewSecretVar("sk-pasted")}

	postHookRunner := func(_ *schemas.BifrostContext, result *schemas.BifrostResponse, bErr *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError) {
		return result, bErr
	}
	stream, bErr := p.ChatCompletionStream(ctx, postHookRunner, nil, key, chatRequest())
	require.Nil(t, bErr)

	var streamErr *schemas.BifrostError
	chunks := 0
	for chunk := range stream {
		if chunk == nil {
			continue
		}
		chunks++
		if chunk.BifrostError != nil {
			streamErr = chunk.BifrostError
		}
	}

	require.NotNil(t, streamErr, "the code envelope must surface as an error chunk")
	require.NotNil(t, streamErr.StatusCode)
	require.Equal(t, http.StatusUnauthorized, *streamErr.StatusCode)
	require.Contains(t, streamErr.Error.Message, "refresh token invalid")
	require.Equal(t, 1, chunks, "only the error chunk should be emitted")
}

// The Responses API is not on CodeBuddy's wire, so it is served through chat exactly as the other
// OpenAI-compatible providers serve it. llmtests.RunSimpleChatTest requires both shapes to work.
func TestResponsesDelegatesThroughChat(t *testing.T) {
	var mu sync.Mutex
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.Path
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"hunyuan-chat","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{Value: *schemas.NewSecretVar("sk-pasted")}

	response, bErr := p.Responses(ctx, key, responsesRequest())
	require.Nil(t, bErr)
	require.NotNil(t, response)
	require.NotNil(t, response.ID)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, "/v2/chat/completions", gotPath, "Responses must be served by the chat surface")
}

func TestResponsesStreamDelegatesThroughChat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"hunyuan-chat\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hi\"},\"finish_reason\":null}]}\n\n"))
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"hunyuan-chat\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{Value: *schemas.NewSecretVar("sk-pasted")}

	postHookRunner := func(_ *schemas.BifrostContext, result *schemas.BifrostResponse, _ *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError) {
		return result, nil
	}
	stream, bErr := p.ResponsesStream(ctx, postHookRunner, nil, key, responsesRequest())
	require.Nil(t, bErr)

	chunks := 0
	for chunk := range stream {
		if chunk != nil {
			chunks++
		}
	}
	require.Positive(t, chunks, "the delegated stream must emit at least one chunk")
}

// A whitespace-only pasted value is no credential, so it must not stop the OAuth mint — and the
// minted token must then be the credential that travels.
func TestWhitespaceOnlyValueStillMintsAndSendsTheBearer(t *testing.T) {
	var mu sync.Mutex
	var gotAuth, gotAPIKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/v2/plugin/auth/token/refresh" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-1","refreshToken":"refresh-2","expiresIn":3600}}`))
			return
		}
		gotAuth, gotAPIKey = r.Header.Get("Authorization"), r.Header.Get("X-API-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"hunyuan-chat","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}`))
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{
		Value: *schemas.NewSecretVar("   "),
		OAuthKeyConfig: &schemas.OAuthKeyConfig{
			GrantType:    schemas.OAuthGrantBrowserLogin,
			TokenURL:     *schemas.NewSecretVar(server.URL + "/v2/plugin/auth/token/refresh"),
			RefreshToken: schemas.NewSecretVar("refresh-1"),
		},
	}

	_, bErr := p.ChatCompletion(ctx, key, chatRequest())
	require.Nil(t, bErr)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, "Bearer access-1", gotAuth)
	require.Empty(t, gotAPIKey, "a whitespace-only value must not become an X-API-Key")
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

// A 200 carrying something the shared converter cannot read is not a decode error the caller can
// act on: the body says nothing about the models this deployment serves, and the pinned catalog is
// still a true answer. This used to surface as a decode error, which turned a reachable provider
// into a broken model picker.
func TestListModelsFallsBackToThePinnedCatalogOnAnUnreadableBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>maintenance</body></html>`))
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	keys := []schemas.Key{{Value: *schemas.NewSecretVar("sk-pasted"), Models: schemas.WhiteList{"*"}}}

	response, bErr := p.ListModels(ctx, keys, &schemas.BifrostListModelsRequest{})
	require.Nil(t, bErr)
	require.NotEmpty(t, response.Data, "the pinned catalog must answer instead of a decode error")
	for _, model := range response.Data {
		require.Contains(t, model.ID, string(schemas.CodeBuddyCN)+"/")
	}
}

// The catalog answer must be indistinguishable from a live listing in the logs: the latency field,
// the captured raw body and the recorded response headers all have to be filled in. Without that the
// one branch that answers from a static list is the one branch an operator cannot see.
func TestCatalogAnswerRecordsTheSameTelemetryAsALiveListing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow enough that a recorded latency cannot be mistaken for the zero value.
		time.Sleep(15 * time.Millisecond)
		w.Header().Set("X-Upstream-Trace", "trace-1")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	}))
	defer server.Close()

	config := &schemas.ProviderConfig{
		NetworkConfig:       schemas.NetworkConfig{DefaultRequestTimeoutInSeconds: 30, BaseURL: server.URL},
		SendBackRawResponse: true,
	}
	p, err := NewCodeBuddyCNProvider(config, &testLogger{})
	require.NoError(t, err)

	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	keys := []schemas.Key{{Value: *schemas.NewSecretVar("sk-pasted"), Models: schemas.WhiteList{"*"}}}

	response, bErr := p.ListModels(ctx, keys, &schemas.BifrostListModelsRequest{})
	require.Nil(t, bErr)
	require.NotEmpty(t, response.Data)
	require.GreaterOrEqual(t, response.ExtraFields.Latency, int64(10), "the catalog branch must record the upstream latency")

	headers, ok := ctx.Value(schemas.BifrostContextKeyProviderResponseHeaders).(map[string]string)
	require.True(t, ok, "the upstream response headers must be recorded on the catalog branch too")
	require.Equal(t, "trace-1", headers["X-Upstream-Trace"])
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
			wantMessage: "codebuddy-cn: model not available (code 40001); transient, retrying",
		},
		{
			// The same shape on a real non-200: the 502 must still say it is being retried, so an
			// operator can tell a refused model from an outage.
			name:        "a 400 with a transient code says it is retried",
			status:      http.StatusBadRequest,
			body:        `{"code":40002,"msg":"model not available"}`,
			wantStatus:  http.StatusBadGateway,
			wantCode:    schemas.Ptr("40002"),
			wantMessage: "codebuddy-cn: model not available (code 40002); transient, retrying",
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

// TestChatCompletionRetriesOnceAfterARevokedAccessToken is Important 5's reproduction. The fast path
// in resolveKey serves the stored access token until the expiry it declared, so a token the upstream
// revoked early fails every request for up to 24h. A 401 on a browser_login key must invalidate the
// credential and re-mint exactly once, and the retry must succeed.
func TestChatCompletionRetriesOnceAfterARevokedAccessToken(t *testing.T) {
	var mu sync.Mutex
	refreshes := 0
	chatCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v2/plugin/auth/token/refresh":
			refreshes++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-2","refreshToken":"refresh-2","expiresIn":3600}}`))
		case "/v2/chat/completions":
			chatCalls++
			// The first token was revoked upstream: the first call is refused, the minted one works.
			if r.Header.Get("Authorization") != "Bearer access-2" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"token revoked"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"hunyuan-chat","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	// The stored token claims to be fresh, which is exactly the case the fast path trusts and the
	// upstream has already revoked.
	key := schemas.Key{ID: "key-1", OAuthKeyConfig: &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(server.URL + "/v2/plugin/auth/token/refresh"),
		AccessToken:  schemas.NewSecretVar("access-revoked"),
		RefreshToken: schemas.NewSecretVar("refresh-1"),
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}}

	response, bErr := p.ChatCompletion(ctx, key, chatRequest())
	require.Nil(t, bErr)
	require.NotNil(t, response)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, refreshes, "a 401 must mint exactly once, not once per request")
	require.Equal(t, 2, chatCalls, "the request must be retried exactly once")
}

// TestChatCompletionDoesNotLoopWhenTheRetryIsAlsoRefused pins the bound: a 401 that persists after
// the re-mint is surfaced with fallbacks blocked, and no second retry happens.
func TestChatCompletionDoesNotLoopWhenTheRetryIsAlsoRefused(t *testing.T) {
	var mu sync.Mutex
	refreshes := 0
	chatCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v2/plugin/auth/token/refresh":
			refreshes++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-2","refreshToken":"refresh-2","expiresIn":3600}}`))
		case "/v2/chat/completions":
			chatCalls++
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"still refused"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{ID: "key-1", OAuthKeyConfig: &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(server.URL + "/v2/plugin/auth/token/refresh"),
		AccessToken:  schemas.NewSecretVar("access-revoked"),
		RefreshToken: schemas.NewSecretVar("refresh-1"),
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}}

	_, bErr := p.ChatCompletion(ctx, key, chatRequest())
	require.NotNil(t, bErr)
	require.NotNil(t, bErr.StatusCode)
	require.Equal(t, http.StatusUnauthorized, *bErr.StatusCode)
	require.NotNil(t, bErr.AllowFallbacks)
	require.False(t, *bErr.AllowFallbacks, "a 401 that survives the re-mint is still permanent")

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, refreshes)
	require.Equal(t, 2, chatCalls, "exactly one retry: a loop would keep calling")
}

// TestChatCompletionDoesNotRetryADeadRefreshToken: code 12153 means the durable credential is gone.
// A re-mint cannot repair it, and clearing the stored access token would drop one that may still be
// good, so the permanent 401 must be surfaced as-is.
func TestChatCompletionDoesNotRetryADeadRefreshToken(t *testing.T) {
	var mu sync.Mutex
	chatCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		chatCalls++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":12153,"msg":"refresh token invalid"}`))
	}))
	defer server.Close()

	sink := &rotationSink{}
	SetCredentialSink(sink.install())
	t.Cleanup(func() { SetCredentialSink(nil) })

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{ID: "key-1", OAuthKeyConfig: &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(server.URL + "/v2/plugin/auth/token/refresh"),
		AccessToken:  schemas.NewSecretVar("access-1"),
		RefreshToken: schemas.NewSecretVar("refresh-1"),
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}}

	_, bErr := p.ChatCompletion(ctx, key, chatRequest())
	require.NotNil(t, bErr)
	require.Equal(t, http.StatusUnauthorized, *bErr.StatusCode)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, chatCalls, "a dead refresh token must not be retried")
	calls, _, _, _, _, _, _ := sink.snapshot()
	require.Equal(t, 0, calls, "a dead refresh token must not clear the stored access token")
}

// A 401 on a pasted key is about that value, not about a minted token, so it must not re-mint or
// touch the credential sink.
func TestChatCompletionDoesNotRetryAPastedKey401(t *testing.T) {
	var mu sync.Mutex
	chatCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		chatCalls++
		mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"bad key"}`))
	}))
	defer server.Close()

	sink := &rotationSink{}
	SetCredentialSink(sink.install())
	t.Cleanup(func() { SetCredentialSink(nil) })

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{Value: *schemas.NewSecretVar("sk-pasted")}

	_, bErr := p.ChatCompletion(ctx, key, chatRequest())
	require.NotNil(t, bErr)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, chatCalls)
	calls, _, _, _, _, _, _ := sink.snapshot()
	require.Equal(t, 0, calls, "a pasted key must not invalidate a browser_login credential")
}

// The streaming path is the same wire and the same 401: a refused token before the first chunk
// must be re-minted once, not surfaced to the caller.
func TestChatCompletionStreamRetriesOnceAfterARevokedAccessToken(t *testing.T) {
	var mu sync.Mutex
	refreshes := 0
	chatCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v2/plugin/auth/token/refresh":
			refreshes++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-2","refreshToken":"refresh-2","expiresIn":3600}}`))
		case "/v2/chat/completions":
			chatCalls++
			if r.Header.Get("Authorization") != "Bearer access-2" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"token revoked"}`))
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n"))
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{ID: "key-1", OAuthKeyConfig: &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(server.URL + "/v2/plugin/auth/token/refresh"),
		AccessToken:  schemas.NewSecretVar("access-revoked"),
		RefreshToken: schemas.NewSecretVar("refresh-1"),
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}}

	stream, bErr := p.ChatCompletionStream(ctx, func(ctx *schemas.BifrostContext, result *schemas.BifrostResponse, err *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError) {
		return result, err
	}, nil, key, chatRequest())
	require.Nil(t, bErr)
	require.NotNil(t, stream)
	for range stream {
	}

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, refreshes)
	require.Equal(t, 2, chatCalls)
}

// A 401 on a browser_login key must also clear the stored access token, or the next request reads
// it off the key row and the fast path serves the revoked credential again until its expiry.
func TestUnauthorizedInvalidationClearsTheStoredAccessToken(t *testing.T) {
	var mu sync.Mutex
	chatCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v2/plugin/auth/token/refresh":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-2","refreshToken":"refresh-2","expiresIn":3600}}`))
		case "/v2/chat/completions":
			chatCalls++
			if r.Header.Get("Authorization") != "Bearer access-2" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"token revoked"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"hunyuan-chat","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}`))
		}
	}))
	defer server.Close()

	var sinkMu sync.Mutex
	type write struct{ access, refresh, expiresAt string }
	var writes []write
	SetCredentialSink(func(provider schemas.ModelProvider, keyID, accessToken, refreshToken, expiresAt string) {
		sinkMu.Lock()
		defer sinkMu.Unlock()
		writes = append(writes, write{accessToken, refreshToken, expiresAt})
	})
	t.Cleanup(func() { SetCredentialSink(nil) })

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{ID: "key-1", OAuthKeyConfig: &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(server.URL + "/v2/plugin/auth/token/refresh"),
		AccessToken:  schemas.NewSecretVar("access-revoked"),
		RefreshToken: schemas.NewSecretVar("refresh-1"),
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}}

	_, bErr := p.ChatCompletion(ctx, key, chatRequest())
	require.Nil(t, bErr)

	mu.Lock()
	require.Equal(t, 2, chatCalls)
	mu.Unlock()

	sinkMu.Lock()
	defer sinkMu.Unlock()
	require.Len(t, writes, 2, "the refused token must be cleared through the sink, then the rotation written")
	require.Equal(t, "", writes[0].access, "the first write clears the token the upstream refused")
	require.Equal(t, "refresh-1", writes[0].refresh, "the durable credential must survive the clear")
	require.Equal(t, "access-2", writes[1].access, "the minted rotation is then written")
	require.Equal(t, "refresh-2", writes[1].refresh)
}

// A pasted key is served as-is and never reaches the token endpoint.
func TestResolveKeyLeavesPastedValuesAlone(t *testing.T) {
	p := newTestProvider(t, "")
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)

	resolved, bErr := p.resolveKey(ctx, schemas.Key{Value: *schemas.NewSecretVar("sk-pasted")})
	require.Nil(t, bErr)
	require.Equal(t, "sk-pasted", resolved.Value.GetValue())
}

// The pre-filter must not swallow a bare {"message":"..."} body on the error path: that shape has
// no code key at all, and the front end sends it with a real non-200 status.
func TestParseErrorReadsABareMessageBody(t *testing.T) {
	got := parseError(fasthttpResponse(http.StatusBadRequest, `{"message":"invalid_format"}`))
	require.NotNil(t, got.Error)
	require.NotNil(t, got.StatusCode)
	require.Equal(t, http.StatusBadGateway, *got.StatusCode)
	require.Contains(t, got.Error.Message, "invalid_format")
}

// A body that merely mentions the word "code" without carrying the field is still a payload, not
// an envelope. The byte pre-filter can only save work; it must never change the answer.
func TestEnvelopeErrorIgnoresCodeInsideContent(t *testing.T) {
	body := []byte(`{"id":"c1","choices":[{"index":0,"message":{"role":"assistant","content":"here is the code: 42"}}]}`)
	require.Nil(t, envelopeError(body))
}

// A sentinel body that decodes to code 0 is a payload too, so the success path must not treat it
// as an error.
func TestEnvelopeErrorIgnoresZeroCode(t *testing.T) {
	require.Nil(t, envelopeError([]byte(`{"code":0,"data":{"accessToken":"a"}}`)))
}

// BenchmarkEnvelopeError measures the in-band check the provider added, over realistic completion
// body sizes. It is the half of the happy-path cost this provider owns; the other half is the
// shared helper's full-body gjson.ValidBytes, which BenchmarkInBandValidationPath isolates below.
func BenchmarkEnvelopeError(b *testing.B) {
	for _, size := range []int{2 << 10, 16 << 10} {
		body := syntheticCompletionBody(size)
		b.Run(fmt.Sprintf("%dKB", size>>10), func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				_ = envelopeError(body)
			}
		})
	}
}

// BenchmarkInBandValidationPath records what supplying a customResponseHandler costs the shared
// helper on top of the provider's own pre-filter: with a handler the helper validates the entire
// body before scanning it, so the happy path pays a full-body scan it did not pay before.
//
// It is deliberately not a micro-benchmark of a single function: the "before" arm is the cheap
// top-level lookup the shared helper performed on its no-handler path, and the "after" arm is the
// whole ErrorInSuccessfulChatBody call it now makes. The difference is the added cost this
// provider introduced.
func BenchmarkInBandValidationPath(b *testing.B) {
	for _, size := range []int{2 << 10, 16 << 10} {
		body := syntheticCompletionBody(size)
		name := fmt.Sprintf("%dKB", size>>10)

		b.Run("before/top-level-error-lookup/"+name, func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				benchGJSONSink = gjson.GetBytes(body, "error")
			}
		})
		b.Run("after/ErrorInSuccessfulChatBody/"+name, func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				benchErrorSink = openai.ErrorInSuccessfulChatBody(body)
			}
		})
	}
}

// syntheticCompletionBody builds a valid OpenAI chat completion body of roughly n bytes: real
// envelope fields, with the content padded to reach the requested size.
func syntheticCompletionBody(n int) []byte {
	const head = `{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"hunyuan-chat","choices":[{"index":0,"message":{"role":"assistant","content":"`
	const tail = `"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
	padding := max(n-len(head)-len(tail), 0)
	return []byte(head + strings.Repeat("a", padding) + tail)
}

// Documented streaming semantics change from supplying a customResponseHandler: a frame that fails
// to decode now terminates the stream with an error chunk. The no-handler path logged the parse
// failure and continued, which let a mid-stream HTML/APISIX body vanish as an empty completion.
func TestChatCompletionStreamSurfacesUndecodableFrames(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n"))
		// A truncated frame: valid JSON prefix, no closing brace, no gateway envelope.
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-2\",\"choices\":[{\"index\":\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{Value: *schemas.NewSecretVar("sk-pasted")}

	postHookRunner := func(_ *schemas.BifrostContext, result *schemas.BifrostResponse, bErr *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError) {
		return result, bErr
	}
	stream, bErr := p.ChatCompletionStream(ctx, postHookRunner, nil, key, chatRequest())
	require.Nil(t, bErr)

	var streamErr *schemas.BifrostError
	for chunk := range stream {
		if chunk != nil && chunk.BifrostError != nil {
			streamErr = chunk.BifrostError
		}
	}
	require.NotNil(t, streamErr, "an undecodable frame must terminate the stream with an error, not be skipped")
	require.NotNil(t, streamErr.Error)
	require.NotEmpty(t, streamErr.Error.Message)
}

// fasthttpResponse builds the response shape the error parser reads.
func fasthttpResponse(status int, body string) *fasthttp.Response {
	resp := fasthttp.AcquireResponse()
	resp.SetStatusCode(status)
	resp.SetBodyString(body)
	return resp
}

// benchHeaderSink keeps the benchmarked maps reachable. Without it the compiler sees the result
// is unused and eliminates the call entirely, which is how BenchmarkAuthHeaderForStaticKey and
// BenchmarkEditorHeaders both came to report 0 allocs for functions that do allocate.
var benchHeaderSink map[string]string

// benchSecretVarSink does the same for editorHeaders, whose return type is not a map[string]string.
var benchSecretVarSink map[string]schemas.SecretVar

// benchGJSONSink and benchErrorSink do it for the validation-path benchmark.
var (
	benchGJSONSink gjson.Result
	benchErrorSink *schemas.BifrostError
)

func BenchmarkAuthHeaderForStaticKey(b *testing.B) {
	key := schemas.Key{Value: *schemas.NewSecretVar("sk-pasted")}
	b.ReportAllocs()
	for b.Loop() {
		benchHeaderSink = authHeaderFor(key, "")
	}
}

func BenchmarkAuthHeaderForOAuthKey(b *testing.B) {
	key := schemas.Key{}
	b.ReportAllocs()
	for b.Loop() {
		benchHeaderSink = authHeaderFor(key, "access-abc")
	}
}

func BenchmarkEditorHeaders(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchSecretVarSink = editorHeaders()
	}
}

// BenchmarkResolveKeyWarm is the per-request cost of a browser_login key whose token lives only in
// tokencache: deriving the credential's cache key and the cache lookup. The key here carries no
// stored access token, so it takes the mint path's warm branch rather than the stored-token fast
// path. BenchmarkResolveKeyOAuthStoredToken covers the path a settled deployment actually pays; a
// pasted key never reaches either — BenchmarkAuthHeaderForStaticKey covers that one.
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
		// Sunk, not discarded: an unread result lets the compiler elide the call and report a
		// fake cost.
		benchResolvedKeySink, benchResolveKeyErrSink = provider.resolveKey(ctx, key)
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

// responsesRequest is the Responses-shaped equivalent of chatRequest, used to drive the
// chat-delegation path.
func responsesRequest() *schemas.BifrostResponsesRequest {
	return &schemas.BifrostResponsesRequest{
		Provider: schemas.CodeBuddyCN,
		Model:    "hunyuan-chat",
		Input: []schemas.ResponsesMessage{{
			Role:    schemas.Ptr(schemas.ResponsesInputMessageRoleUser),
			Content: &schemas.ResponsesMessageContent{ContentStr: schemas.Ptr("hi")},
		}},
	}
}

// rotationSink is the shape the transport installs: the provider names itself so one process-wide
// callback can serve every provider, and the expiry travels as the RFC3339 string the config
// stores.
type rotationSink struct {
	mu        sync.Mutex
	calls     int
	provider  schemas.ModelProvider
	keyID     string
	access    string
	refresh   string
	expiresAt time.Time
	lastErr   error
}

func (s *rotationSink) install() func(schemas.ModelProvider, string, string, string, string) {
	return func(provider schemas.ModelProvider, keyID, accessToken, refreshToken, expiresAt string) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.calls++
		s.provider, s.keyID, s.access, s.refresh = provider, keyID, accessToken, refreshToken
		parsed, err := time.Parse(time.RFC3339, expiresAt)
		s.expiresAt, s.lastErr = parsed, err
	}
}

func (s *rotationSink) snapshot() (int, schemas.ModelProvider, string, string, string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.provider, s.keyID, s.access, s.refresh, s.expiresAt, s.lastErr
}

// TestResolveKeyDeliversRotationToSink pins that a browser_login rotation reaches the persistence
// callback with the key's identity attached. Without it the rotated refresh token is discarded,
// and a key whose upstream invalidates the old one dies at the next mint.
func TestResolveKeyDeliversRotationToSink(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-2","refreshToken":"refresh-2","expiresIn":3600}}`))
	}))
	defer server.Close()

	sink := &rotationSink{}
	SetCredentialSink(sink.install())
	t.Cleanup(func() { SetCredentialSink(nil) })

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{ID: "key-1", OAuthKeyConfig: &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(server.URL + "/v2/plugin/auth/token/refresh"),
		RefreshToken: schemas.NewSecretVar("refresh-1"),
	}}

	resolved, bErr := p.resolveKey(ctx, key)
	require.Nil(t, bErr)
	require.Equal(t, "access-2", resolved.Value.GetValue())

	calls, provider, keyID, access, refresh, expiresAt, parseErr := sink.snapshot()
	require.NoError(t, parseErr, "the sink's expiry must be RFC3339")
	require.Equal(t, 1, calls)
	require.Equal(t, schemas.CodeBuddyCN, provider)
	require.Equal(t, "key-1", keyID)
	require.Equal(t, "access-2", access)
	require.Equal(t, "refresh-2", refresh)
	require.WithinDuration(t, time.Now().Add(time.Hour), expiresAt, 10*time.Second)
}

// TestResolveKeyWithoutSinkStillResolves pins that persistence is optional: a process that never
// installs a sink (the Go SDK, say) still mints and returns the access token.
func TestResolveKeyWithoutSinkStillResolves(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-2","refreshToken":"refresh-2","expiresIn":3600}}`))
	}))
	defer server.Close()

	SetCredentialSink(nil)
	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{ID: "key-1", OAuthKeyConfig: &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(server.URL + "/v2/plugin/auth/token/refresh"),
		RefreshToken: schemas.NewSecretVar("refresh-1"),
	}}

	resolved, bErr := p.resolveKey(ctx, key)
	require.Nil(t, bErr)
	require.Equal(t, "access-2", resolved.Value.GetValue())
}

// TestResolveKeyReusesThePersistedAccessToken pins the interaction between persistence and the
// token cache. The cache is keyed by the refresh token, so a rotation changes the cache key and
// the next request would miss, mint, and rotate again — one refresh per request forever. The
// stored access token is the rotation-stable answer: while it is still outside the refresh
// margin it is used as-is, and the cache is untouched.
func TestResolveKeyReusesThePersistedAccessToken(t *testing.T) {
	var mu sync.Mutex
	refreshes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		refreshes++
		n := refreshes
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"code":0,"data":{"accessToken":"access-%d","refreshToken":"refresh-%d","expiresIn":3600}}`, n+1, n+1)))
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{ID: "key-1", OAuthKeyConfig: &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(server.URL + "/v2/plugin/auth/token/refresh"),
		RefreshToken: schemas.NewSecretVar("refresh-1"),
	}}

	// First request mints from refresh-1 and reports the rotation.
	resolved, bErr := p.resolveKey(ctx, key)
	require.Nil(t, bErr)
	require.Equal(t, "access-2", resolved.Value.GetValue())

	// The transport persists access-2 / refresh-2; the next request reads that stored key.
	stored := key
	cfg := *key.OAuthKeyConfig
	cfg.AccessToken = schemas.NewSecretVar("access-2")
	cfg.RefreshToken = schemas.NewSecretVar("refresh-2")
	cfg.ExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	stored.OAuthKeyConfig = &cfg

	resolved, bErr = p.resolveKey(ctx, stored)
	require.Nil(t, bErr)
	require.Equal(t, "access-2", resolved.Value.GetValue())

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, refreshes, "a persisted access token must be reused, not re-minted through a rotated cache key")
}

// TestResolveKeyRefreshesWhenTheStoredAccessTokenIsStale pins the other half: the fast path is a
// freshness check, not a cache of its own. An expired token is minted again even though it is
// present on the key.
func TestResolveKeyRefreshesWhenTheStoredAccessTokenIsStale(t *testing.T) {
	var mu sync.Mutex
	refreshes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		refreshes++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-new","refreshToken":"refresh-2","expiresIn":3600}}`))
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{ID: "key-1", OAuthKeyConfig: &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar(server.URL + "/v2/plugin/auth/token/refresh"),
		AccessToken:  schemas.NewSecretVar("access-stale"),
		RefreshToken: schemas.NewSecretVar("refresh-1"),
		ExpiresAt:    time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
	}}

	resolved, bErr := p.resolveKey(ctx, key)
	require.Nil(t, bErr)
	require.Equal(t, "access-new", resolved.Value.GetValue(), "an expired stored token must be renewed")
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, refreshes)
}

// BenchmarkResolveKeyPastedValue isolates the no-OAuth fast path: the check the provider adds to
// every non-browser_login request. It must stay allocation-free.
func BenchmarkResolveKeyPastedValue(b *testing.B) {
	p := newTestProvider(b, "")
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{Value: *schemas.NewSecretVar("sk-pasted")}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchResolvedKeySink, benchResolveKeyErrSink = p.resolveKey(ctx, key)
	}
}

// BenchmarkResolveKeyOAuthStoredToken measures the per-request cost of a browser_login key whose
// access token is stored and still fresh: the grant check, the two expiry comparisons and the
// margin arithmetic, with no cache lookup. It is the cost a settled deployment pays, and it is
// deliberately separate from BenchmarkResolveKeyWarm so the primed-cache cost stays named.
func BenchmarkResolveKeyOAuthStoredToken(b *testing.B) {
	p := newTestProvider(b, "")
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{ID: "key-1", OAuthKeyConfig: &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar("https://copilot.tencent.com/v2/plugin/auth/token/refresh"),
		AccessToken:  schemas.NewSecretVar("access-warm"),
		RefreshToken: schemas.NewSecretVar("refresh-1"),
		ExpiresAt:    time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchResolvedKeySink, benchResolveKeyErrSink = p.resolveKey(ctx, key)
	}
}

// benchResolvedKeySink and benchResolveKeyErrSink keep the benchmarked result reachable so the
// compiler cannot eliminate the call and report a fake cost.
var (
	benchResolvedKeySink   schemas.Key
	benchResolveKeyErrSink *schemas.BifrostError
)

// TestStoredAccessTokenIsOnlyUsedWhenItsExpirySaysSo pins the three rejection cases of the
// rotation-stable fast path. An empty expiry means "refresh on use" in the config contract, so a
// token without one must not be trusted; an unparseable one is likewise treated as stale rather
// than pinning a token of unknown age.
func TestStoredAccessTokenIsOnlyUsedWhenItsExpirySaysSo(t *testing.T) {
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)

	// browserLogin is the grant a stored token is meaningful for. The grant gate itself is
	// covered separately below.
	at := func(expiresAt string) schemas.OAuthKeyConfig {
		return schemas.OAuthKeyConfig{
			GrantType:   schemas.OAuthGrantBrowserLogin,
			AccessToken: schemas.NewSecretVar("a"),
			ExpiresAt:   expiresAt,
		}
	}
	now := time.Now()

	cases := []struct {
		name string
		cfg  schemas.OAuthKeyConfig
		want string
	}{
		{"fresh token", at(future), "a"},
		{"no access token", schemas.OAuthKeyConfig{GrantType: schemas.OAuthGrantBrowserLogin, ExpiresAt: future}, ""},
		{"no expiry means refresh on use", at(""), ""},
		{"expired", at(past), ""},
		// A token already inside the margin is trusted for half of what is left, matching the
		// cache's clamp (tokencache.RefreshAt). Treating it as due here would re-mint per request
		// for every key whose lifetime is shorter than the margin.
		{"inside the refresh margin still serves", at(now.Add(30 * time.Second).UTC().Format(time.RFC3339)), "a"},
		{"unparseable expiry", at("tomorrow"), ""},
		{"whitespace-only token", schemas.OAuthKeyConfig{GrantType: schemas.OAuthGrantBrowserLogin, AccessToken: schemas.NewSecretVar("  "), ExpiresAt: future}, ""},
		// A self-declared expiry is not a trust boundary. Beyond the cap the token is ignored and
		// minted, which is always safe: the refresh token is still the credential.
		{"a far-future expiry is not trusted", at(now.Add(48 * time.Hour).UTC().Format(time.RFC3339)), ""},
		{"a token just inside the lifetime cap is trusted", at(now.Add(maxAccessTokenLifetime - time.Minute).UTC().Format(time.RFC3339)), "a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, storedAccessToken(tc.cfg, now))
		})
	}
}

// TestStoredAccessTokenIsOnlyForBrowserLogin pins the grant gate. Validate ignores access_token for
// client_credentials and jwt_bearer, so an operator can leave one on such a key by hand; honouring
// it would send that value as the bearer instead of minting.
func TestStoredAccessTokenIsOnlyForBrowserLogin(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour).UTC().Format(time.RFC3339)
	for _, grant := range []schemas.OAuthGrantType{schemas.OAuthGrantClientCredentials, schemas.OAuthGrantJWTBearer, ""} {
		t.Run(string(grant), func(t *testing.T) {
			cfg := schemas.OAuthKeyConfig{
				GrantType:   grant,
				AccessToken: schemas.NewSecretVar("operator-pasted"),
				ExpiresAt:   future,
			}
			require.Empty(t, storedAccessToken(cfg, now), "a stored access token must not be used for %q", grant)
		})
	}
}

// TestResolveKeyMintsForANonBrowserLoginGrantCarryingAnAccessToken is the same gate seen from the
// request path: the key must still be minted, not served from the inert field.
func TestResolveKeyMintsForANonBrowserLoginGrantCarryingAnAccessToken(t *testing.T) {
	var mu sync.Mutex
	refreshes := 0
	access := "minted-access"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		mu.Lock()
		refreshes++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + access + `","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()

	p := newTestProvider(t, server.URL)
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	key := schemas.Key{ID: "key-1", OAuthKeyConfig: &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantClientCredentials,
		TokenURL:     *schemas.NewSecretVar(server.URL + "/token"),
		ClientID:     schemas.NewSecretVar("id"),
		ClientSecret: schemas.NewSecretVar("secret"),
		AccessToken:  schemas.NewSecretVar("operator-pasted"),
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}}

	resolved, bErr := p.resolveKey(ctx, key)
	require.Nil(t, bErr)
	require.Equal(t, access, resolved.Value.GetValue(), "a client_credentials key must mint, not use its inert access_token")
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, refreshes)
}
