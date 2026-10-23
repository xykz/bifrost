package codebuddycn_test

import (
	"os"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/internal/llmtests"
	"github.com/maximhq/bifrost/core/schemas"
)

// TestCodebuddycn is the entry point `make test-core PROVIDER=codebuddycn` runs. The name carries a
// lowercase "b" because the Makefile derives it from the directory name with
// `toupper(substr(1,1)) tolower(substr(2))`, and it has no mapping entry for this provider's
// registry string (`codebuddy-cn`). The subtest is named CodebuddycnTests for the same reason.
//
// It lives in the external test package, like every other provider's live suite: llmtests imports
// the root bifrost package, which imports this provider, so an in-package test that imported
// llmtests would close a cycle. The provider's internal tests stay in codebuddycn_test.go; this
// file only wires the shared scenario suite.
func TestCodebuddycn(t *testing.T) {
	t.Parallel()
	if strings.TrimSpace(os.Getenv("CODEBUDDY_CN_API_KEY")) == "" {
		t.Skip("Skipping CodeBuddy CN tests because CODEBUDDY_CN_API_KEY is not set")
	}

	client, ctx, cancel, err := llmtests.SetupTest()
	if err != nil {
		t.Fatalf("Error initializing test setup: %v", err)
	}
	defer cancel()
	defer client.Shutdown()

	// The gateway serves chat and Responses (delegated through chat) only. Text completions,
	// embeddings, images, speech, transcription, batch, files and containers all answer
	// unsupported_operation, so every flag below but the chat-shaped ones and ListModels is
	// false.
	//
	// ListModels is enabled because model listing is one of the four operations the provider
	// implements: it answers with the pinned catalog when the gateway serves none. ToolCalls
	// stays on because the request path is the shared OpenAI converter, which already carries
	// function schemas — and enabling ToolCalls also exercises the streaming tool-call paths,
	// since those suites gate on ToolCalls rather than on ToolCallsStreaming. The remaining
	// variants are off: they are not part of what this task can verify here, and a flag left on
	// without a credential to run it is a claim, not a test.
	testConfig := llmtests.ComprehensiveTestConfig{
		Provider:       schemas.CodeBuddyCN,
		ChatModel:      "hunyuan-chat",
		TextModel:      "",
		EmbeddingModel: "",
		Scenarios: llmtests.TestScenarios{
			SimpleChat:           true,
			CompletionStream:     true,
			ToolCalls:            true,
			ListModels:           true,
			TextCompletion:       false,
			TextCompletionStream: false,
			// Multi-turn is plain chat with history and the gateway serves it, but the brief
			// scopes this wiring to SimpleChat, the stream, ToolCalls and model listing. Left off
			// because no live run here can confirm it.
			MultiTurnConversation: false,
			// Tool calling beyond a single call is enabled by CodeBuddy's own client, but no
			// live run has pinned it for this gateway yet; a green suite would be a guess.
			ToolCallsStreaming:           false,
			MultipleToolCalls:            false,
			MultipleToolCallsStreaming:   false,
			End2EndToolCalling:           false,
			AutomaticFunctionCall:        false,
			ImageURL:                     false,
			ImageBase64:                  false,
			MultipleImages:               false,
			FileBase64:                   false,
			FileURL:                      false,
			CompleteEnd2End:              false,
			SpeechSynthesis:              false,
			SpeechSynthesisStream:        false,
			Transcription:                false,
			TranscriptionStream:          false,
			Embedding:                    false,
			MultimodalEmbedding:          false,
			Reasoning:                    false,
			PromptCaching:                false,
			ImageGeneration:              false,
			ImageGenerationStream:        false,
			ImageEdit:                    false,
			ImageEditStream:              false,
			ImageVariation:               false,
			ImageVariationStream:         false,
			VideoGeneration:              false,
			VideoRetrieve:                false,
			VideoRemix:                   false,
			VideoDownload:                false,
			VideoList:                    false,
			VideoDelete:                  false,
			BatchCreate:                  false,
			BatchList:                    false,
			BatchRetrieve:                false,
			BatchCancel:                  false,
			BatchResults:                 false,
			FileUpload:                   false,
			FileList:                     false,
			FileRetrieve:                 false,
			FileDelete:                   false,
			FileContent:                  false,
			FileBatchInput:               false,
			CountTokens:                  false,
			ChatAudio:                    false,
			StructuredOutputs:            false,
			WebSearchTool:                false,
			ContainerCreate:              false,
			ContainerList:                false,
			ContainerRetrieve:            false,
			ContainerDelete:              false,
			ContainerFileCreate:          false,
			ContainerFileList:            false,
			ContainerFileRetrieve:        false,
			ContainerFileContent:         false,
			ContainerFileDelete:          false,
			PassThroughExtraParams:       false,
			Rerank:                       false,
			Decision:                     false,
			DecisionEmulation:            false,
			PassthroughAPI:               false,
			WebSocketResponses:           false,
			Realtime:                     false,
			Compaction:                   false,
			ToolSearch:                   false,
			ExternalCompaction:           false,
			InterleavedThinking:          false,
			FastMode:                     false,
			EagerInputStreaming:          false,
			ServerToolsViaOpenAIEndpoint: false,
			ResponsesLifecycle:           false,
		},
	}

	t.Run("CodebuddycnTests", func(t *testing.T) {
		llmtests.RunAllComprehensiveTests(t, client, ctx, testConfig)
	})
}
