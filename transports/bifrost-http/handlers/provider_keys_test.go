package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/providers/codebuddycn"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/transports/v2/bifrost-http/lib"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

func TestProviderKeyReadRedactsNestedSecrets(t *testing.T) {
	const canary = "synthetic-provider-key-secret-canary-0123456789"
	const ref = "env.BIFROST_PROVIDER_KEY_REDACTION_TEST"
	t.Setenv("BIFROST_PROVIDER_KEY_REDACTION_TEST", canary)
	secret := func() *schemas.SecretVar { return schemas.NewSecretVar(ref) }
	for _, provider := range []schemas.ModelProvider{schemas.Bedrock, schemas.BedrockMantle} {
		t.Run(string(provider), func(t *testing.T) {
			key := schemas.Key{
				ID: "redaction-key", Name: "redaction-key", Value: *secret(),
				Aliases: schemas.KeyAliases{"test": {ModelID: "model", Region: secret(), ProjectID: secret()}},
			}
			if provider == schemas.Bedrock {
				key.BedrockKeyConfig = &schemas.BedrockKeyConfig{
					ProjectID: secret(), Endpoints: &schemas.BedrockEndpoints{Runtime: secret()},
				}
			} else {
				key.BedrockMantleKeyConfig = &schemas.BedrockMantleKeyConfig{
					ProjectID: secret(), Endpoints: &schemas.BedrockEndpoints{Runtime: secret()},
				}
			}
			h := &ProviderHandler{inMemoryStore: &lib.Config{
				Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
					provider: {Keys: []schemas.Key{key}},
				},
			}}
			for name, handler := range map[string]func(*fasthttp.RequestCtx){
				"get": h.getProviderKey, "list": h.listProviderKeys,
			} {
				t.Run(name, func(t *testing.T) {
					ctx := newTestRequestCtx("")
					ctx.SetUserValue("provider", string(provider))
					ctx.SetUserValue("key_id", key.ID)
					handler(ctx)
					body := string(ctx.Response.Body())
					if ctx.Response.StatusCode() != fasthttp.StatusOK {
						t.Fatalf("expected 200, got %d: %s", ctx.Response.StatusCode(), body)
					}
					if strings.Contains(body, canary) {
						t.Fatalf("resolved secret leaked: %s", body)
					}
					// All five populated fields (including the credential control)
					// must be present, resolved, masked, and retain their references.
					if strings.Count(body, ref) != 5 || strings.Count(body, secret().Redacted().GetValue()) != 5 {
						t.Fatalf("missing masked values or references: %s", body)
					}
					if key.Aliases["test"].Region.GetValue() != canary {
						t.Fatal("reading a key modified the live secret")
					}
				})
			}
		})
	}
}

// TestMergeUpdatedKey_Value locks in the invariant that a masked key preview can
// never be persisted as the real key value. The provider keys API renders keys
// redacted on GET; when a client echoes that placeholder back on update, the
// stored credential must be preserved. This is the write-side guard for
// issue #4353 (a masked "*"-laden preview leaking into the config store and
// later breaking JSON re-parsing on governance reload).
func TestMergeUpdatedKey_Value(t *testing.T) {
	h := &ProviderHandler{}
	merge := func(oldRaw, update schemas.Key) schemas.Key {
		t.Helper()
		merged, err := h.mergeUpdatedKey(oldRaw, update)
		if err != nil {
			t.Fatalf("mergeUpdatedKey returned error: %v", err)
		}
		return merged
	}

	const rawValue = "sk-realkey1234567890abcdefghij"

	newRaw := func() schemas.Key {
		return schemas.Key{ID: "key-1", Value: *schemas.NewSecretVar(rawValue)}
	}
	redactedOf := func(raw schemas.Key) schemas.Key {
		return schemas.Key{ID: "key-1", Value: *raw.Value.Redacted()}
	}

	t.Run("echoed current redaction preserves stored value", func(t *testing.T) {
		oldRaw := newRaw()
		oldRedacted := redactedOf(oldRaw)
		// Client sends back exactly what GET rendered.
		update := schemas.Key{ID: "key-1", Value: oldRedacted.Value}

		merged := merge(oldRaw, update)
		if merged.Value.GetValue() != rawValue {
			t.Fatalf("expected stored raw value preserved, got %q", merged.Value.GetValue())
		}
	})

	t.Run("mismatched mask still preserves stored value", func(t *testing.T) {
		// A redacted preview whose bytes differ from the server's current
		// redaction (e.g. a stale render, a different asterisk count, or a
		// preview from another replica). The old exact-match guard let this
		// through and persisted the mask; the fix must still preserve.
		oldRaw := newRaw()
		oldRedacted := redactedOf(oldRaw)
		mismatched := "diff" + strings.Repeat("*", 24) + "XYZW" // redacted-shaped, != oldRedacted
		if !schemas.NewSecretVar(mismatched).IsRedacted() {
			t.Fatalf("test setup: %q is not recognized as redacted", mismatched)
		}
		if mismatched == oldRedacted.Value.GetValue() {
			t.Fatalf("test setup: mismatched mask unexpectedly equals current redaction")
		}
		update := schemas.Key{ID: "key-1", Value: *schemas.NewSecretVar(mismatched)}

		merged := merge(oldRaw, update)
		if merged.Value.GetValue() != rawValue {
			t.Fatalf("masked preview must not be persisted; expected %q, got %q", rawValue, merged.Value.GetValue())
		}
		if strings.Contains(merged.Value.GetValue(), "*") {
			t.Fatalf("merged value still contains mask characters: %q", merged.Value.GetValue())
		}
	})

	t.Run("genuine new plaintext value is applied", func(t *testing.T) {
		oldRaw := newRaw()
		const newValue = "sk-brandnewkey0987654321zyxwvu"
		update := schemas.Key{ID: "key-1", Value: *schemas.NewSecretVar(newValue)}

		merged := merge(oldRaw, update)
		if merged.Value.GetValue() != newValue {
			t.Fatalf("expected new plaintext value applied, got %q", merged.Value.GetValue())
		}
	})

	t.Run("genuine env ref is applied not preserved", func(t *testing.T) {
		oldRaw := newRaw()
		// env refs report IsRedacted() but are an intentional change.
		update := schemas.Key{ID: "key-1", Value: *schemas.NewSecretVar("env.SOME_NEW_KEY")}

		merged := merge(oldRaw, update)
		if !merged.Value.IsFromEnv() || merged.Value.GetRawRef() != "env.SOME_NEW_KEY" {
			t.Fatalf("expected env ref applied, got ref=%q fromEnv=%v", merged.Value.GetRawRef(), merged.Value.IsFromEnv())
		}
		if merged.Value.GetValue() == rawValue {
			t.Fatalf("stored raw value leaked into an env-ref update")
		}
	})

	t.Run("empty value is not treated as redacted", func(t *testing.T) {
		// Empty non-secret values must stay empty so the downstream
		// "must not be empty" validation still fires. The merge must not
		// silently resurrect the stored value here.
		oldRaw := newRaw()
		update := schemas.Key{ID: "key-1", Value: *schemas.NewSecretVar("")}

		merged := merge(oldRaw, update)
		if merged.Value.GetValue() != "" {
			t.Fatalf("expected empty value preserved for validation, got %q", merged.Value.GetValue())
		}
	})
}

// TestMergeUpdatedKey_Name locks in the invariant that a PUT update omitting
// name must not clear the stored one. config_keys.name carries a global unique
// index, so silently clearing it lets the first such update claim "" and wedge
// every later name-omitting update behind a 409 (observed in a downstream
// production deployment: a single edit that omitted name broke every
// subsequent key edit going through this path).
func TestMergeUpdatedKey_Name(t *testing.T) {
	h := &ProviderHandler{}
	merge := func(oldRaw, update schemas.Key) schemas.Key {
		t.Helper()
		merged, err := h.mergeUpdatedKey(oldRaw, update)
		if err != nil {
			t.Fatalf("mergeUpdatedKey returned error: %v", err)
		}
		return merged
	}

	t.Run("name omitted from update preserves stored name", func(t *testing.T) {
		oldRaw := schemas.Key{ID: "key-1", Name: "prod-openai-key", Value: *schemas.NewSecretVar("sk-realkey1234567890abcdefghij")}
		update := schemas.Key{ID: "key-1", Value: oldRaw.Value} // client PUT body has no "name" field

		merged := merge(oldRaw, update)
		if merged.Name != "prod-openai-key" {
			t.Fatalf("expected stored name preserved, got %q", merged.Name)
		}
	})

	t.Run("explicit new name is applied", func(t *testing.T) {
		oldRaw := schemas.Key{ID: "key-1", Name: "prod-openai-key", Value: *schemas.NewSecretVar("sk-realkey1234567890abcdefghij")}
		update := schemas.Key{ID: "key-1", Name: "renamed-key", Value: oldRaw.Value}

		merged := merge(oldRaw, update)
		if merged.Name != "renamed-key" {
			t.Fatalf("expected new name applied, got %q", merged.Name)
		}
	})
}

// TestDecodeKeyUpdate_PartialBody covers issue #7572: a PUT that names only
// some fields must leave the others as stored. Omitted fields used to decode to
// zero values, so a body carrying only models emptied the key's value and set
// its weight to 0, and the update still returned 200.
func TestDecodeKeyUpdate_PartialBody(t *testing.T) {
	h := &ProviderHandler{}
	const rawValue = "sk-sglrealkey1234567890abcdefghij"
	stored := func() schemas.Key {
		return schemas.Key{
			ID:                "key-1",
			Name:              "sgl-key",
			Value:             *schemas.NewSecretVar(rawValue),
			Models:            schemas.WhiteList{"old-model"},
			BlacklistedModels: schemas.BlackList{"blocked-model"},
			Weight:            1,
			SGLKeyConfig:      &schemas.SGLKeyConfig{URL: *schemas.NewSecretVar("http://old:30000")},
			Enabled:           schemas.Ptr(false),
			UseForBatchAPI:    schemas.Ptr(true),
			Description:       "primary",
		}
	}
	update := func(t *testing.T, body string) schemas.Key {
		t.Helper()
		oldRaw := stored()
		updateKey, err := decodeKeyUpdate([]byte(body), oldRaw)
		if err != nil {
			t.Fatalf("decodeKeyUpdate returned error: %v", err)
		}
		updateKey.ID = oldRaw.ID
		merged, err := h.mergeUpdatedKey(oldRaw, updateKey)
		if err != nil {
			t.Fatalf("mergeUpdatedKey returned error: %v", err)
		}
		return merged
	}

	t.Run("omitted fields keep their stored values", func(t *testing.T) {
		merged := update(t, `{"models":["m1","m2"],"sgl_key_config":{"url":"http://new:30000"}}`)
		if merged.Value.GetValue() != rawValue {
			t.Fatalf("value: got %q, want the stored value", merged.Value.GetValue())
		}
		if merged.Weight != 1 {
			t.Fatalf("weight: got %v, want 1", merged.Weight)
		}
		if len(merged.BlacklistedModels) != 1 || merged.BlacklistedModels[0] != "blocked-model" {
			t.Fatalf("blacklisted_models: got %v, want [blocked-model]", merged.BlacklistedModels)
		}
		if merged.Enabled == nil || *merged.Enabled {
			t.Fatalf("enabled: got %v, want the stored false", merged.Enabled)
		}
		if merged.UseForBatchAPI == nil || !*merged.UseForBatchAPI {
			t.Fatalf("use_for_batch_api: got %v, want the stored true", merged.UseForBatchAPI)
		}
		if merged.Description != "primary" {
			t.Fatalf("description: got %q, want primary", merged.Description)
		}
		// The fields that were sent still apply.
		if len(merged.Models) != 2 || merged.Models[0] != "m1" {
			t.Fatalf("models: got %v, want [m1 m2]", merged.Models)
		}
		if merged.SGLKeyConfig == nil || merged.SGLKeyConfig.URL.GetValue() != "http://new:30000" {
			t.Fatalf("sgl_key_config.url: got %+v, want http://new:30000", merged.SGLKeyConfig)
		}
	})

	t.Run("an omitted provider config is kept", func(t *testing.T) {
		merged := update(t, `{"weight":2}`)
		if merged.SGLKeyConfig == nil || merged.SGLKeyConfig.URL.GetValue() != "http://old:30000" {
			t.Fatalf("sgl_key_config: got %+v, want the stored config", merged.SGLKeyConfig)
		}
		if merged.Weight != 2 {
			t.Fatalf("weight: got %v, want 2", merged.Weight)
		}
	})

	t.Run("fields sent explicitly empty are cleared", func(t *testing.T) {
		merged := update(t, `{"value":"","weight":0,"models":[],"description":"","sgl_key_config":null}`)
		if merged.Value.GetValue() != "" {
			t.Fatalf("value: got %q, want it cleared", merged.Value.GetValue())
		}
		if merged.Weight != 0 {
			t.Fatalf("weight: got %v, want 0", merged.Weight)
		}
		if len(merged.Models) != 0 {
			t.Fatalf("models: got %v, want empty", merged.Models)
		}
		if merged.Description != "" {
			t.Fatalf("description: got %q, want it cleared", merged.Description)
		}
		if merged.SGLKeyConfig != nil {
			t.Fatalf("sgl_key_config: got %+v, want nil", merged.SGLKeyConfig)
		}
	})
}

func TestMergeUpdatedKey_ProviderConfigMaskedPreviews(t *testing.T) {
	h := &ProviderHandler{}
	merge := func(oldRaw, update schemas.Key) schemas.Key {
		t.Helper()
		merged, err := h.mergeUpdatedKey(oldRaw, update)
		if err != nil {
			t.Fatalf("mergeUpdatedKey returned error: %v", err)
		}
		return merged
	}
	secret := func(value string) schemas.SecretVar { return *schemas.NewSecretVar(value) }
	secretPtr := func(value string) *schemas.SecretVar { return schemas.NewSecretVar(value) }
	staleMaskValue := func(prefix, suffix string) string {
		return prefix + strings.Repeat("*", 24) + suffix
	}
	staleMask := func(prefix, suffix string) schemas.SecretVar {
		return secret(staleMaskValue(prefix, suffix))
	}

	oldRaw := schemas.Key{
		AzureKeyConfig: &schemas.AzureKeyConfig{
			Endpoint:     secret("https://current.azure.example.com"),
			ClientSecret: secretPtr("azure-client-secret-current"),
		},
		VertexKeyConfig: &schemas.VertexKeyConfig{
			AuthCredentials: secret("vertex-auth-credentials-current"),
		},
		BedrockKeyConfig: &schemas.BedrockKeyConfig{
			AccessKey:    secret("bedrock-access-key-current"),
			SessionToken: secretPtr("bedrock-session-token-current"),
		},
		BedrockMantleKeyConfig: &schemas.BedrockMantleKeyConfig{
			SecretKey: secret("mantle-secret-key-current"),
		},
		VLLMKeyConfig:       &schemas.VLLMKeyConfig{URL: secret("https://current.vllm.example.com")},
		OllamaKeyConfig:     &schemas.OllamaKeyConfig{URL: secret("https://current.ollama.example.com")},
		SGLKeyConfig:        &schemas.SGLKeyConfig{URL: secret("https://current.sgl.example.com")},
		CloudflareKeyConfig: &schemas.CloudflareKeyConfig{AccountID: secret("0123456789abcdef0123456789abcdef")},
	}
	update := schemas.Key{
		AzureKeyConfig: &schemas.AzureKeyConfig{
			Endpoint:     staleMask("azur", "0001"),
			ClientSecret: secretPtr(staleMaskValue("azcs", "0002")),
		},
		VertexKeyConfig: &schemas.VertexKeyConfig{
			AuthCredentials: staleMask("vert", "0003"),
		},
		BedrockKeyConfig: &schemas.BedrockKeyConfig{
			AccessKey:    staleMask("beda", "0004"),
			SessionToken: secretPtr(staleMaskValue("beds", "0005")),
		},
		BedrockMantleKeyConfig: &schemas.BedrockMantleKeyConfig{
			SecretKey: staleMask("mant", "0006"),
		},
		VLLMKeyConfig:       &schemas.VLLMKeyConfig{URL: staleMask("vllm", "0007")},
		OllamaKeyConfig:     &schemas.OllamaKeyConfig{URL: staleMask("olla", "0008")},
		SGLKeyConfig:        &schemas.SGLKeyConfig{URL: staleMask("sgla", "0009")},
		CloudflareKeyConfig: &schemas.CloudflareKeyConfig{AccountID: staleMask("0123", "cdef")},
	}

	merged := merge(oldRaw, update)
	checks := []struct {
		name string
		got  string
		want string
	}{
		{"azure endpoint", merged.AzureKeyConfig.Endpoint.GetValue(), oldRaw.AzureKeyConfig.Endpoint.GetValue()},
		{"azure client secret", merged.AzureKeyConfig.ClientSecret.GetValue(), oldRaw.AzureKeyConfig.ClientSecret.GetValue()},
		{"vertex credentials", merged.VertexKeyConfig.AuthCredentials.GetValue(), oldRaw.VertexKeyConfig.AuthCredentials.GetValue()},
		{"bedrock access key", merged.BedrockKeyConfig.AccessKey.GetValue(), oldRaw.BedrockKeyConfig.AccessKey.GetValue()},
		{"bedrock session token", merged.BedrockKeyConfig.SessionToken.GetValue(), oldRaw.BedrockKeyConfig.SessionToken.GetValue()},
		{"mantle secret key", merged.BedrockMantleKeyConfig.SecretKey.GetValue(), oldRaw.BedrockMantleKeyConfig.SecretKey.GetValue()},
		{"vllm url", merged.VLLMKeyConfig.URL.GetValue(), oldRaw.VLLMKeyConfig.URL.GetValue()},
		{"ollama url", merged.OllamaKeyConfig.URL.GetValue(), oldRaw.OllamaKeyConfig.URL.GetValue()},
		{"sgl url", merged.SGLKeyConfig.URL.GetValue(), oldRaw.SGLKeyConfig.URL.GetValue()},
		{"cloudflare account id", merged.CloudflareKeyConfig.AccountID.GetValue(), oldRaw.CloudflareKeyConfig.AccountID.GetValue()},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s: expected stored value %q, got %q", check.name, check.want, check.got)
		}
	}

	update.VLLMKeyConfig.URL = secret("env.NEW_VLLM_URL")
	merged = merge(oldRaw, update)
	if !merged.VLLMKeyConfig.URL.IsFromEnv() || merged.VLLMKeyConfig.URL.GetRawRef() != "env.NEW_VLLM_URL" {
		t.Fatalf("expected nested env ref applied, got ref=%q", merged.VLLMKeyConfig.URL.GetRawRef())
	}
}

// TestMergeUpdatedKey_GithubCopilotKeyConfig covers the masked-update path for the GitHub
// App bundle. The API renders keys redacted on GET, so a client that edits one field and
// submits the form sends back a mask for every field it did not touch. Getting the merge
// wrong here either persists the literal mask as a credential, or silently drops the four
// App fields, and both failures look like a working save.
func TestMergeUpdatedKey_GithubCopilotKeyConfig(t *testing.T) {
	h := &ProviderHandler{}
	secret := func(v string) schemas.SecretVar { return *schemas.NewSecretVar(v) }
	mask := func(prefix, suffix string) schemas.SecretVar {
		return secret(prefix + strings.Repeat("*", 24) + suffix)
	}

	stored := func() schemas.Key {
		return schemas.Key{GithubCopilotKeyConfig: &schemas.GithubCopilotKeyConfig{
			AppID:          secret("123456"),
			InstallationID: secret("87654321"),
			RepositoryID:   secret("999000111"),
			PrivateKey:     secret(pkcs1TestPEM(t)),
			GithubDomain:   secret("acme.ghe.com"),
		}}
	}

	t.Run("masks resolve back to the stored values", func(t *testing.T) {
		update := schemas.Key{GithubCopilotKeyConfig: &schemas.GithubCopilotKeyConfig{
			AppID:          mask("1234", "3456"),
			InstallationID: mask("8765", "4321"),
			RepositoryID:   mask("9990", "0111"),
			PrivateKey:     mask("----", "----"),
			GithubDomain:   mask("acme", ".com"),
		}}

		merged, err := h.mergeUpdatedKey(stored(), update)
		if err != nil {
			t.Fatalf("mergeUpdatedKey returned error: %v", err)
		}
		cfg := merged.GithubCopilotKeyConfig
		if cfg == nil {
			t.Fatal("the App config was dropped by the merge")
		}
		for _, c := range []struct{ name, got, want string }{
			{"app_id", cfg.AppID.GetValue(), "123456"},
			{"installation_id", cfg.InstallationID.GetValue(), "87654321"},
			{"repository_id", cfg.RepositoryID.GetValue(), "999000111"},
			{"private_key", cfg.PrivateKey.GetValue(), pkcs1TestPEM(t)},
			{"github_domain", cfg.GithubDomain.GetValue(), "acme.ghe.com"},
		} {
			if c.got != c.want {
				t.Errorf("%s: got %q, want the stored value %q", c.name, c.got, c.want)
			}
			if strings.Contains(c.got, "****") {
				t.Errorf("%s: the mask was persisted as a credential", c.name)
			}
		}
	})

	t.Run("a mask with no stored counterpart is rejected", func(t *testing.T) {
		// Nothing to restore from, so accepting it would write asterisks as the App ID.
		update := schemas.Key{GithubCopilotKeyConfig: &schemas.GithubCopilotKeyConfig{
			AppID: mask("1234", "3456"),
		}}

		if _, err := h.mergeUpdatedKey(schemas.Key{}, update); err == nil {
			t.Fatal("expected an error when a mask has no stored value behind it")
		}
	})

	t.Run("unmasked literals overwrite the stored values", func(t *testing.T) {
		update := schemas.Key{GithubCopilotKeyConfig: &schemas.GithubCopilotKeyConfig{
			AppID:          secret("Iv1.b507a08c87ecfe98"),
			InstallationID: secret("11112222"),
			RepositoryID:   secret("333344445"),
			PrivateKey:     secret(pkcs8TestPEM(t)),
			GithubDomain:   secret(""),
		}}

		merged, err := h.mergeUpdatedKey(stored(), update)
		if err != nil {
			t.Fatalf("mergeUpdatedKey returned error: %v", err)
		}
		cfg := merged.GithubCopilotKeyConfig
		if cfg.AppID.GetValue() != "Iv1.b507a08c87ecfe98" {
			t.Errorf("app_id: got %q, want the new literal", cfg.AppID.GetValue())
		}
		if cfg.InstallationID.GetValue() != "11112222" {
			t.Errorf("installation_id: got %q, want the new literal", cfg.InstallationID.GetValue())
		}
		if cfg.PrivateKey.GetValue() != pkcs8TestPEM(t) {
			t.Error("private_key: the rotated key did not take effect")
		}
	})
}

func TestMergeUpdatedKey_RejectsMaskWithoutStoredCounterpart(t *testing.T) {
	h := &ProviderHandler{}
	mask := *schemas.NewSecretVar("abcd" + strings.Repeat("*", 24) + "wxyz")

	tests := []struct {
		name    string
		oldRaw  schemas.Key
		update  schemas.Key
		wantErr string
	}{
		{
			name:    "missing config section",
			oldRaw:  schemas.Key{},
			update:  schemas.Key{VLLMKeyConfig: &schemas.VLLMKeyConfig{URL: mask}},
			wantErr: "vllm_key_config.url",
		},
		{
			name: "missing optional field",
			oldRaw: schemas.Key{BedrockKeyConfig: &schemas.BedrockKeyConfig{
				AccessKey: *schemas.NewSecretVar("stored-access-key"),
			}},
			update: schemas.Key{BedrockKeyConfig: &schemas.BedrockKeyConfig{
				SessionToken: schemas.NewSecretVar(mask.GetValue()),
			}},
			wantErr: "bedrock_key_config.session_token",
		},
		{
			name: "empty stored value",
			oldRaw: schemas.Key{VLLMKeyConfig: &schemas.VLLMKeyConfig{
				URL: *schemas.NewSecretVar(""),
			}},
			update:  schemas.Key{VLLMKeyConfig: &schemas.VLLMKeyConfig{URL: mask}},
			wantErr: "vllm_key_config.url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.mergeUpdatedKey(tt.oldRaw, tt.update)
			if err == nil {
				t.Fatal("expected masked preview without stored counterpart to fail")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error to name %q, got %q", tt.wantErr, err)
			}
		})
	}
}

// validateProviderKeyURL must enforce every nested field config.schema.json
// marks as required, so neither create nor a masked-update merge can persist a
// key missing them.
func TestValidateProviderKeyRequiredNestedFields(t *testing.T) {
	region := schemas.NewSecretVar("us-east-1")
	cases := []struct {
		name     string
		provider schemas.ModelProvider
		key      schemas.Key
		wantErr  string
	}{
		{"azure missing endpoint", schemas.Azure, schemas.Key{AzureKeyConfig: &schemas.AzureKeyConfig{}}, "azure_key_config.endpoint"},
		{"azure nil config", schemas.Azure, schemas.Key{}, "azure_key_config.endpoint"},
		{"azure ok", schemas.Azure, schemas.Key{AzureKeyConfig: &schemas.AzureKeyConfig{Endpoint: *schemas.NewSecretVar("https://x.openai.azure.com")}}, ""},
		{"bedrock missing region", schemas.Bedrock, schemas.Key{BedrockKeyConfig: &schemas.BedrockKeyConfig{}}, "bedrock_key_config.region"},
		{"bedrock ok", schemas.Bedrock, schemas.Key{BedrockKeyConfig: &schemas.BedrockKeyConfig{Region: region}}, ""},
		{"mantle missing region", schemas.BedrockMantle, schemas.Key{BedrockMantleKeyConfig: &schemas.BedrockMantleKeyConfig{}}, "bedrock_mantle_key_config.region"},
		{"mantle ok", schemas.BedrockMantle, schemas.Key{BedrockMantleKeyConfig: &schemas.BedrockMantleKeyConfig{Region: region}}, ""},
		{"vllm missing url", schemas.VLLM, schemas.Key{VLLMKeyConfig: &schemas.VLLMKeyConfig{ModelName: "m"}}, "vllm_key_config.url"},
		{"vllm missing model_name", schemas.VLLM, schemas.Key{VLLMKeyConfig: &schemas.VLLMKeyConfig{URL: *schemas.NewSecretVar("http://vllm:8000")}}, "vllm_key_config.model_name"},
		{"vllm ok", schemas.VLLM, schemas.Key{VLLMKeyConfig: &schemas.VLLMKeyConfig{URL: *schemas.NewSecretVar("http://vllm:8000"), ModelName: "m"}}, ""},
		{"openai unaffected", schemas.OpenAI, schemas.Key{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProviderKeyURL(tc.provider, tc.key)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestMergeUpdatedKey_OAuthKeyConfig covers the masked-update path for oauth_key_config: a
// client that edits one field sends back a mask for every secret it did not touch, and the
// merge must restore the stored secret rather than persist the asterisks.
func TestMergeUpdatedKey_OAuthKeyConfig(t *testing.T) {
	h := &ProviderHandler{}
	secret := func(v string) *schemas.SecretVar { return schemas.NewSecretVar(v) }
	mask := func(prefix, suffix string) *schemas.SecretVar {
		return secret(prefix + strings.Repeat("*", 24) + suffix)
	}
	stored := func() schemas.Key {
		return schemas.Key{OAuthKeyConfig: &schemas.OAuthKeyConfig{
			GrantType:    schemas.OAuthGrantJWTBearer,
			TokenURL:     *secret("https://idp.example/oauth2/token"),
			ClientID:     secret("client-123"),
			ClientSecret: secret("client-secret-456"),
			PrivateKey:   secret(pkcs1TestPEM(t)),
			Issuer:       "client-123",
			Audience:     "api://acme",
		}}
	}

	t.Run("masks resolve back to the stored values", func(t *testing.T) {
		update := schemas.Key{OAuthKeyConfig: &schemas.OAuthKeyConfig{
			GrantType:    schemas.OAuthGrantJWTBearer,
			TokenURL:     *mask("http", "oken"),
			ClientID:     mask("clie", "-123"),
			ClientSecret: mask("clie", "-456"),
			PrivateKey:   mask("----", "----"),
			Issuer:       "client-123",
			Audience:     "api://other",
		}}
		merged, err := h.mergeUpdatedKey(stored(), update)
		if err != nil {
			t.Fatalf("mergeUpdatedKey returned error: %v", err)
		}
		cfg := merged.OAuthKeyConfig
		if cfg == nil {
			t.Fatal("the oauth config was dropped by the merge")
		}
		for _, c := range []struct{ name, got, want string }{
			{"token_url", cfg.TokenURL.GetValue(), "https://idp.example/oauth2/token"},
			{"client_id", cfg.ClientID.GetValue(), "client-123"},
			{"client_secret", cfg.ClientSecret.GetValue(), "client-secret-456"},
			{"private_key", cfg.PrivateKey.GetValue(), pkcs1TestPEM(t)},
		} {
			if c.got != c.want {
				t.Errorf("%s: got %q, want the stored value %q", c.name, c.got, c.want)
			}
		}
		if cfg.Audience != "api://other" {
			t.Errorf("audience: got %q, want the updated literal", cfg.Audience)
		}
	})

	t.Run("a mask with no stored counterpart is rejected", func(t *testing.T) {
		update := schemas.Key{OAuthKeyConfig: &schemas.OAuthKeyConfig{
			GrantType: schemas.OAuthGrantClientCredentials, TokenURL: *secret("https://idp.example/token"),
			ClientID: secret("id"), ClientSecret: mask("abcd", "wxyz"),
		}}
		if _, err := h.mergeUpdatedKey(schemas.Key{}, update); err == nil {
			t.Fatal("expected an error when a mask has no stored value behind it")
		}
	})

	t.Run("unmasked literals overwrite the stored values", func(t *testing.T) {
		update := schemas.Key{OAuthKeyConfig: &schemas.OAuthKeyConfig{
			GrantType: schemas.OAuthGrantClientCredentials, TokenURL: *secret("https://idp2.example/token"),
			ClientID: secret("new-id"), ClientSecret: secret("new-secret"),
		}}
		merged, err := h.mergeUpdatedKey(stored(), update)
		if err != nil {
			t.Fatalf("mergeUpdatedKey returned error: %v", err)
		}
		cfg := merged.OAuthKeyConfig
		if cfg.ClientSecret.GetValue() != "new-secret" || cfg.TokenURL.GetValue() != "https://idp2.example/token" {
			t.Errorf("literals were not applied: %q %q", cfg.ClientSecret.GetValue(), cfg.TokenURL.GetValue())
		}
		if cfg.PrivateKey != nil {
			t.Errorf("a field the update left out must not be resurrected from the stored config")
		}
	})

	t.Run("masked extra_params values resolve back to the stored values", func(t *testing.T) {
		storedWithParams := stored()
		storedWithParams.OAuthKeyConfig.ExtraParams = map[string]string{"client_assertion": "assertion-secret", "resource": "api://acme"}
		update := schemas.Key{OAuthKeyConfig: &schemas.OAuthKeyConfig{
			GrantType: schemas.OAuthGrantJWTBearer, TokenURL: *secret("https://idp.example/oauth2/token"),
			PrivateKey: secret(pkcs1TestPEM(t)), Issuer: "client-123", Audience: "api://acme",
			ExtraParams: map[string]string{"client_assertion": "asse" + strings.Repeat("*", 24) + "cret", "resource": "api://other"},
		}}
		merged, err := h.mergeUpdatedKey(storedWithParams, update)
		if err != nil {
			t.Fatalf("mergeUpdatedKey returned error: %v", err)
		}
		if merged.OAuthKeyConfig.ExtraParams["client_assertion"] != "assertion-secret" {
			t.Errorf("client_assertion: got %q, want the stored value", merged.OAuthKeyConfig.ExtraParams["client_assertion"])
		}
		if merged.OAuthKeyConfig.ExtraParams["resource"] != "api://other" {
			t.Errorf("resource: got %q, want the new literal", merged.OAuthKeyConfig.ExtraParams["resource"])
		}
	})

	t.Run("a masked extra_params value that looks like a secret reference restores the stored string", func(t *testing.T) {
		// "env.production" is sent to the token endpoint verbatim; it is not a Bifrost reference.
		// The GET masks it, and the masked form must resolve back to the stored string.
		storedWithParams := stored()
		storedWithParams.OAuthKeyConfig.ExtraParams = map[string]string{"resource": "env.production"}
		masked := storedWithParams.OAuthKeyConfig.Redacted().ExtraParams["resource"]
		update := schemas.Key{OAuthKeyConfig: &schemas.OAuthKeyConfig{
			GrantType: schemas.OAuthGrantJWTBearer, TokenURL: *secret("https://idp.example/oauth2/token"),
			PrivateKey: secret(pkcs1TestPEM(t)), Issuer: "client-123", Audience: "api://acme",
			ExtraParams: map[string]string{"resource": masked},
		}}
		merged, err := h.mergeUpdatedKey(storedWithParams, update)
		if err != nil {
			t.Fatalf("mergeUpdatedKey returned error: %v", err)
		}
		if merged.OAuthKeyConfig.ExtraParams["resource"] != "env.production" {
			t.Errorf("resource: got %q, want the stored string restored from its mask %q", merged.OAuthKeyConfig.ExtraParams["resource"], masked)
		}
	})

	// The UI switches auth methods by sending an explicit empty value (API key -> OAuth) or an
	// explicit null section (OAuth -> API key). Both must clear the stored half; an omitted
	// field keeps it. resolveKey prefers a static value, so a surviving one silently wins.
	t.Run("an explicit empty value clears the stored static key", func(t *testing.T) {
		old := stored()
		old.Value = *secret("sk-old")
		decoded, err := decodeKeyUpdate([]byte(`{"name":"k","value":""}`), old)
		if err != nil {
			t.Fatalf("decodeKeyUpdate: %v", err)
		}
		merged, err := h.mergeUpdatedKey(old, decoded)
		if err != nil {
			t.Fatalf("mergeUpdatedKey: %v", err)
		}
		if merged.Value.GetValue() != "" {
			t.Fatalf("value = %q, want cleared", merged.Value.GetValue())
		}
	})

	t.Run("an explicit null clears the stored oauth block", func(t *testing.T) {
		decoded, err := decodeKeyUpdate([]byte(`{"name":"k","value":"sk-new","oauth_key_config":null}`), stored())
		if err != nil {
			t.Fatalf("decodeKeyUpdate: %v", err)
		}
		if decoded.OAuthKeyConfig != nil {
			t.Fatal("an explicit null must clear the stored oauth_key_config")
		}
	})

	t.Run("an update without the section keeps the stored one", func(t *testing.T) {
		body := []byte(`{"name":"renamed"}`)
		decoded, err := decodeKeyUpdate(body, stored())
		if err != nil {
			t.Fatalf("decodeKeyUpdate: %v", err)
		}
		if decoded.OAuthKeyConfig == nil || decoded.OAuthKeyConfig.ClientSecret.GetValue() != "client-secret-456" {
			t.Fatal("an omitted oauth_key_config must keep the stored section")
		}
	})
}

// TestValidateProviderKeyOAuthKeyConfig pins the setup-time checks on oauth_key_config: it is
// accepted on any provider's key, must be whole for its grant, and literal values are
// shape-checked so a typo fails at save rather than at the first inference call.
func TestValidateProviderKeyOAuthKeyConfig(t *testing.T) {
	cc := func(mutate func(*schemas.OAuthKeyConfig)) *schemas.OAuthKeyConfig {
		c := &schemas.OAuthKeyConfig{
			GrantType:    schemas.OAuthGrantClientCredentials,
			TokenURL:     *schemas.NewSecretVar("https://idp.example/oauth2/token"),
			ClientID:     schemas.NewSecretVar("id"),
			ClientSecret: schemas.NewSecretVar("secret"),
		}
		if mutate != nil {
			mutate(c)
		}
		return c
	}
	jb := func(mutate func(*schemas.OAuthKeyConfig)) *schemas.OAuthKeyConfig {
		c := &schemas.OAuthKeyConfig{
			GrantType:  schemas.OAuthGrantJWTBearer,
			TokenURL:   *schemas.NewSecretVar("https://idp.example/oauth2/token"),
			PrivateKey: schemas.NewSecretVar(pkcs1TestPEM(t)),
			Issuer:     "client",
			Audience:   "https://idp.example/oauth2/token",
		}
		if mutate != nil {
			mutate(c)
		}
		return c
	}
	tests := []struct {
		name     string
		provider schemas.ModelProvider
		key      schemas.Key
		wantErr  string
	}{
		{"client_credentials on openai", schemas.OpenAI, schemas.Key{OAuthKeyConfig: cc(nil)}, ""},
		{"jwt_bearer on openai", schemas.OpenAI, schemas.Key{OAuthKeyConfig: jb(nil)}, ""},
		{"jwt_bearer with a PKCS#8 key", schemas.OpenAI, schemas.Key{OAuthKeyConfig: jb(func(c *schemas.OAuthKeyConfig) { c.PrivateKey = schemas.NewSecretVar(pkcs8TestPEM(t)) })}, ""},
		{"http on loopback is allowed", schemas.OpenAI, schemas.Key{OAuthKeyConfig: cc(func(c *schemas.OAuthKeyConfig) { c.TokenURL = *schemas.NewSecretVar("http://127.0.0.1:9/token") })}, ""},
		{"http on localhost in any letter case is allowed, as in core", schemas.OpenAI, schemas.Key{OAuthKeyConfig: cc(func(c *schemas.OAuthKeyConfig) { c.TokenURL = *schemas.NewSecretVar("http://LOCALHOST:8080/token") })}, ""},
		{"env-backed token url is not shape checked", schemas.OpenAI, schemas.Key{OAuthKeyConfig: cc(func(c *schemas.OAuthKeyConfig) { c.TokenURL = *schemas.NewSecretVar("env.IDP_TOKEN_URL") })}, ""},
		{"userinfo in the token url is refused", schemas.OpenAI, schemas.Key{OAuthKeyConfig: cc(func(c *schemas.OAuthKeyConfig) {
			c.TokenURL = *schemas.NewSecretVar("https://user:pass@idp.example/token")
		})}, "must not carry userinfo, a query, or a fragment"},
		{"a query in the token url is refused", schemas.OpenAI, schemas.Key{OAuthKeyConfig: cc(func(c *schemas.OAuthKeyConfig) {
			c.TokenURL = *schemas.NewSecretVar("https://idp.example/token?client_secret=x")
		})}, "must not carry userinfo, a query, or a fragment"},
		{"a fragment in the token url is refused", schemas.OpenAI, schemas.Key{OAuthKeyConfig: cc(func(c *schemas.OAuthKeyConfig) {
			c.TokenURL = *schemas.NewSecretVar("https://idp.example/token#frag")
		})}, "must not carry userinfo, a query, or a fragment"},
		{"plain http is refused", schemas.OpenAI, schemas.Key{OAuthKeyConfig: cc(func(c *schemas.OAuthKeyConfig) { c.TokenURL = *schemas.NewSecretVar("http://idp.example/token") })}, "https"},
		{"missing client secret", schemas.OpenAI, schemas.Key{OAuthKeyConfig: cc(func(c *schemas.OAuthKeyConfig) { c.ClientSecret = nil })}, "client_secret"},
		{"jwt_bearer missing audience", schemas.OpenAI, schemas.Key{OAuthKeyConfig: jb(func(c *schemas.OAuthKeyConfig) { c.Audience = "" })}, "audience is required"},
		{"jwt_bearer literal key is not a PEM", schemas.OpenAI, schemas.Key{OAuthKeyConfig: jb(func(c *schemas.OAuthKeyConfig) { c.PrivateKey = schemas.NewSecretVar("not a key") })}, "RSA or EC private key"},
		{"jwt_bearer env-backed key is not shape checked", schemas.OpenAI, schemas.Key{OAuthKeyConfig: jb(func(c *schemas.OAuthKeyConfig) { c.PrivateKey = schemas.NewSecretVar("env.IDP_KEY") })}, ""},
		{"an EC key under the default RS256 is refused at save", schemas.OpenAI, schemas.Key{OAuthKeyConfig: jb(func(c *schemas.OAuthKeyConfig) { c.PrivateKey = schemas.NewSecretVar(ecCurveTestPEM(t, elliptic.P256(), false)); c.SigningAlgorithm = "" })}, "signing_algorithm"},
		{"an RSA key with ES256 is refused at save", schemas.OpenAI, schemas.Key{OAuthKeyConfig: jb(func(c *schemas.OAuthKeyConfig) { c.PrivateKey = schemas.NewSecretVar(pkcs1TestPEM(t)); c.SigningAlgorithm = "ES256" })}, "signing_algorithm"},
		{"a P-384 key with ES256 is refused at save", schemas.OpenAI, schemas.Key{OAuthKeyConfig: jb(func(c *schemas.OAuthKeyConfig) { c.PrivateKey = schemas.NewSecretVar(ecCurveTestPEM(t, elliptic.P384(), false)); c.SigningAlgorithm = "ES256" })}, "signing_algorithm"},
		{"a P-256 key with ES256 is accepted", schemas.OpenAI, schemas.Key{OAuthKeyConfig: jb(func(c *schemas.OAuthKeyConfig) { c.PrivateKey = schemas.NewSecretVar(ecCurveTestPEM(t, elliptic.P256(), false)); c.SigningAlgorithm = "ES256" })}, ""},
		{"a P-384 PKCS#8 key with ES384 is accepted", schemas.OpenAI, schemas.Key{OAuthKeyConfig: jb(func(c *schemas.OAuthKeyConfig) { c.PrivateKey = schemas.NewSecretVar(ecCurveTestPEM(t, elliptic.P384(), true)); c.SigningAlgorithm = "ES384" })}, ""},
		{"a P-521 key with ES512 is accepted", schemas.OpenAI, schemas.Key{OAuthKeyConfig: jb(func(c *schemas.OAuthKeyConfig) { c.PrivateKey = schemas.NewSecretVar(ecCurveTestPEM(t, elliptic.P521(), false)); c.SigningAlgorithm = "ES512" })}, ""},
		{"an RSA key with PS256 is accepted", schemas.OpenAI, schemas.Key{OAuthKeyConfig: jb(func(c *schemas.OAuthKeyConfig) { c.PrivateKey = schemas.NewSecretVar(pkcs8TestPEM(t)); c.SigningAlgorithm = "PS256" })}, ""},
		{"a half block behind a value is still refused", schemas.OpenAI, schemas.Key{Value: *schemas.NewSecretVar("sk"), OAuthKeyConfig: cc(func(c *schemas.OAuthKeyConfig) { c.GrantType = "" })}, "grant_type is required"},
		{"refused on a provider that does not resolve it", schemas.Anthropic, schemas.Key{Value: *schemas.NewSecretVar("sk"), OAuthKeyConfig: cc(nil)}, "only supported on openai"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProviderKeyURL(tt.provider, tt.key)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}

	t.Run("the token url is a dial target", func(t *testing.T) {
		targets := keyDialTargets(schemas.Key{OAuthKeyConfig: cc(nil)})
		if targets["oauth_key_config.token_url"] == nil {
			t.Fatal("oauth_key_config.token_url must be guarded as a caller-chosen dial target")
		}
	})
}

// TestValidateProviderKeyGithubCopilotFormats pins that a literal GitHub App credential is
// checked for shape at save time, not just for presence. A non-numeric installation_id or a
// mangled PEM otherwise persists happily and fails on the first inference call, where it
// reads as a runtime fault rather than a typo in a form.
//
// Environment and vault references are exempt: their values are not available here, so
// checking them would reject every legitimate headless configuration.
func TestValidateProviderKeyGithubCopilotFormats(t *testing.T) {
	pemBody := pkcs1TestPEM(t)

	appConfig := func(mutate func(*schemas.GithubCopilotKeyConfig)) *schemas.GithubCopilotKeyConfig {
		c := &schemas.GithubCopilotKeyConfig{
			AppID:          *schemas.NewSecretVar("123456"),
			InstallationID: *schemas.NewSecretVar("87654321"),
			RepositoryID:   *schemas.NewSecretVar("999000111"),
			PrivateKey:     *schemas.NewSecretVar(pemBody),
		}
		if mutate != nil {
			mutate(c)
		}
		return c
	}

	cases := []struct {
		name    string
		key     schemas.Key
		wantErr string
	}{
		{"valid literal app config", schemas.Key{GithubCopilotKeyConfig: appConfig(nil)}, ""},
		{"direct token needs no app config", schemas.Key{Value: *schemas.NewSecretVar("tid=abc")}, ""},
		{
			"non-numeric installation_id",
			schemas.Key{GithubCopilotKeyConfig: appConfig(func(c *schemas.GithubCopilotKeyConfig) {
				c.InstallationID = *schemas.NewSecretVar("my-install")
			})},
			"installation_id",
		},
		{
			"path traversal in installation_id",
			schemas.Key{GithubCopilotKeyConfig: appConfig(func(c *schemas.GithubCopilotKeyConfig) {
				c.InstallationID = *schemas.NewSecretVar("1/../../../user")
			})},
			"installation_id",
		},
		{
			"non-numeric repository_id",
			schemas.Key{GithubCopilotKeyConfig: appConfig(func(c *schemas.GithubCopilotKeyConfig) {
				c.RepositoryID = *schemas.NewSecretVar("my-repo")
			})},
			"repository_id",
		},
		{
			"private key that is not PEM",
			schemas.Key{GithubCopilotKeyConfig: appConfig(func(c *schemas.GithubCopilotKeyConfig) {
				c.PrivateKey = *schemas.NewSecretVar("not a key")
			})},
			"private_key",
		},
		{
			"valid PKCS#8 private key",
			schemas.Key{GithubCopilotKeyConfig: appConfig(func(c *schemas.GithubCopilotKeyConfig) {
				c.PrivateKey = *schemas.NewSecretVar(pkcs8TestPEM(t))
			})},
			"",
		},
		{
			// An EC key is a perfectly well-formed PEM, so an envelope-only check waves it
			// through. GitHub App JWTs are RS256, so it fails at the first request instead.
			"EC private key",
			schemas.Key{GithubCopilotKeyConfig: appConfig(func(c *schemas.GithubCopilotKeyConfig) {
				c.PrivateKey = *schemas.NewSecretVar(ecTestPEM(t))
			})},
			"private_key",
		},
		{
			// Passphrase-protected keys cannot be used unattended, and the envelope alone
			// does not say so.
			"encrypted private key envelope",
			schemas.Key{GithubCopilotKeyConfig: appConfig(func(c *schemas.GithubCopilotKeyConfig) {
				c.PrivateKey = *schemas.NewSecretVar("-----BEGIN ENCRYPTED PRIVATE KEY-----\nZm9v\n-----END ENCRYPTED PRIVATE KEY-----")
			})},
			"private_key",
		},
		{
			"well-formed envelope with a garbage DER payload",
			schemas.Key{GithubCopilotKeyConfig: appConfig(func(c *schemas.GithubCopilotKeyConfig) {
				c.PrivateKey = *schemas.NewSecretVar("-----BEGIN RSA PRIVATE KEY-----\nZm9vYmFy\n-----END RSA PRIVATE KEY-----")
			})},
			"private_key",
		},
		{
			"PEM whose newlines survived as literal backslash-n",
			schemas.Key{GithubCopilotKeyConfig: appConfig(func(c *schemas.GithubCopilotKeyConfig) {
				c.PrivateKey = *schemas.NewSecretVar(strings.ReplaceAll(pkcs1TestPEM(t), "\n", `\n`))
			})},
			"",
		},
		{
			"no token and no app config at all",
			schemas.Key{},
			"github_copilot_key_config is required",
		},
		{
			"no token, missing app_id",
			schemas.Key{GithubCopilotKeyConfig: appConfig(func(c *schemas.GithubCopilotKeyConfig) {
				c.AppID = schemas.SecretVar{}
			})},
			"github_copilot_key_config.app_id is required",
		},
		{
			"no token, missing installation_id",
			schemas.Key{GithubCopilotKeyConfig: appConfig(func(c *schemas.GithubCopilotKeyConfig) {
				c.InstallationID = schemas.SecretVar{}
			})},
			"github_copilot_key_config.installation_id is required",
		},
		{
			"no token, missing repository_id",
			schemas.Key{GithubCopilotKeyConfig: appConfig(func(c *schemas.GithubCopilotKeyConfig) {
				c.RepositoryID = schemas.SecretVar{}
			})},
			"github_copilot_key_config.repository_id is required",
		},
		{
			"no token, missing private_key",
			schemas.Key{GithubCopilotKeyConfig: appConfig(func(c *schemas.GithubCopilotKeyConfig) {
				c.PrivateKey = schemas.SecretVar{}
			})},
			"github_copilot_key_config.private_key is required",
		},
		{
			// A token does not excuse a half-filled App block: it persists silently and only
			// breaks later, when the token expires or is removed.
			"direct token alongside an incomplete app config",
			schemas.Key{
				Value: *schemas.NewSecretVar("tid=abc"),
				GithubCopilotKeyConfig: &schemas.GithubCopilotKeyConfig{
					AppID: *schemas.NewSecretVar("123456"),
				},
			},
			"installation_id",
		},
		{
			"direct token alongside a malformed app config",
			schemas.Key{
				Value: *schemas.NewSecretVar("tid=abc"),
				GithubCopilotKeyConfig: appConfig(func(c *schemas.GithubCopilotKeyConfig) {
					c.RepositoryID = *schemas.NewSecretVar("not-a-number")
				}),
			},
			"repository_id",
		},
		{
			"direct token alongside a complete app config",
			schemas.Key{Value: *schemas.NewSecretVar("tid=abc"), GithubCopilotKeyConfig: appConfig(nil)},
			"",
		},
		{
			// GitHub documents the JWT issuer as "the client ID or application ID", and says
			// "use of the client ID is recommended". Client IDs look like Iv1.b507a08c87ecfe98,
			// so a digits-only rule on app_id would reject the recommended configuration.
			// https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
			"client ID as app_id is accepted",
			schemas.Key{GithubCopilotKeyConfig: appConfig(func(c *schemas.GithubCopilotKeyConfig) {
				c.AppID = *schemas.NewSecretVar("Iv1.b507a08c87ecfe98")
			})},
			"",
		},
		{
			"env references are not format-checked",
			schemas.Key{GithubCopilotKeyConfig: &schemas.GithubCopilotKeyConfig{
				AppID:          *schemas.NewSecretVar("env.COPILOT_APP_ID"),
				InstallationID: *schemas.NewSecretVar("env.COPILOT_INSTALLATION_ID"),
				RepositoryID:   *schemas.NewSecretVar("env.COPILOT_REPOSITORY_ID"),
				PrivateKey:     *schemas.NewSecretVar("env.COPILOT_PRIVATE_KEY"),
			}},
			"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProviderKeyURL(schemas.GithubCopilot, tc.key)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// refreshHandlerForTest builds a ProviderHandler with one keyed provider and a
// recording models manager.
func refreshHandlerForTest(mgr *mockModelsManager) *ProviderHandler {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})
	return &ProviderHandler{
		inMemoryStore: &lib.Config{
			Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
				"openai": {Keys: []schemas.Key{{ID: "key-1"}}},
			},
		},
		modelsManager: mgr,
	}
}

func TestRefreshProviderModels_DelegatesToModelsManager(t *testing.T) {
	mgr := &mockModelsManager{}
	h := refreshHandlerForTest(mgr)

	ctx := newTestRequestCtx("")
	ctx.SetUserValue("provider", "openai")
	h.refreshProviderModels(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("status got %d, want 200; body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if len(mgr.refreshProviderCalls) != 1 || mgr.refreshProviderCalls[0] != "openai" {
		t.Fatalf("expected one provider-level refresh for openai, got %v", mgr.refreshProviderCalls)
	}
}

func TestRefreshProviderKeyModels_DelegatesToModelsManager(t *testing.T) {
	mgr := &mockModelsManager{}
	h := refreshHandlerForTest(mgr)

	ctx := newTestRequestCtx("")
	ctx.SetUserValue("provider", "openai")
	ctx.SetUserValue("key_id", "key-1")
	h.refreshProviderKeyModels(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("status got %d, want 200; body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if len(mgr.refreshKeyCalls) != 1 || mgr.refreshKeyCalls[0].keyID != "key-1" {
		t.Fatalf("expected one refresh for key-1, got %v", mgr.refreshKeyCalls)
	}
}

// A refresh already running for the provider must surface as 409 rather than
// stacking another (enabled keys x 2) burst of upstream calls, so the UI can
// tell the user to wait instead of silently doubling the load.
func TestRefreshProviderModels_InFlightReturns409(t *testing.T) {
	mgr := &mockModelsManager{refreshErr: ErrRefreshInProgress}
	h := refreshHandlerForTest(mgr)

	ctx := newTestRequestCtx("")
	ctx.SetUserValue("provider", "openai")
	h.refreshProviderModels(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusConflict {
		t.Fatalf("status got %d, want 409; body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
}

func TestRefreshProviderKeyModels_UnknownKeyReturns404(t *testing.T) {
	mgr := &mockModelsManager{}
	h := refreshHandlerForTest(mgr)

	ctx := newTestRequestCtx("")
	ctx.SetUserValue("provider", "openai")
	ctx.SetUserValue("key_id", "does-not-exist")
	h.refreshProviderKeyModels(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusNotFound {
		t.Fatalf("status got %d, want 404; body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if len(mgr.refreshKeyCalls) != 0 {
		t.Fatalf("expected no upstream refresh for an unknown key, got %v", mgr.refreshKeyCalls)
	}
}

func TestRefreshProviderModels_UnknownProviderReturns404(t *testing.T) {
	mgr := &mockModelsManager{}
	h := refreshHandlerForTest(mgr)

	ctx := newTestRequestCtx("")
	ctx.SetUserValue("provider", "does-not-exist")
	h.refreshProviderModels(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusNotFound {
		t.Fatalf("status got %d, want 404; body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if len(mgr.refreshProviderCalls) != 0 {
		t.Fatalf("expected no upstream refresh for an unknown provider, got %v", mgr.refreshProviderCalls)
	}
}

// TestDeleteProviderKey_KeylessProviderRemovesResidualKey is the recovery
// half of issue #8500. A provider switched from keyed to keyless keeps its old
// keys, and adding or updating keys there is rightly refused, but refusing the
// DELETE too left no API or UI path to ever remove them. Deleting can only
// shrink the key set of a provider that ignores keys, so it must go through.
func TestDeleteProviderKey_KeylessProviderRemovesResidualKey(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	const provider schemas.ModelProvider = "keyless-custom"
	h := &ProviderHandler{
		inMemoryStore: &lib.Config{
			Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
				provider: {
					Keys: []schemas.Key{{ID: "residual-key", Name: "residual", Value: *schemas.NewSecretVar("sk-residual"), Weight: 1, Enabled: schemas.Ptr(false)}},
					CustomProviderConfig: &schemas.CustomProviderConfig{
						IsKeyLess:        true,
						BaseProviderType: schemas.OpenAI,
					},
				},
			},
		},
		modelsManager: &mockModelsManager{},
	}
	attachBifrostClient(t, h.inMemoryStore)

	ctx := newTestRequestCtx("")
	ctx.SetUserValue("provider", string(provider))
	ctx.SetUserValue("key_id", "residual-key")
	h.deleteProviderKey(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("delete residual key on keyless provider: status got %d, want 200; body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if keys := h.inMemoryStore.Providers[provider].Keys; len(keys) != 0 {
		t.Fatalf("residual key still stored after delete: %+v", keys)
	}
}

// Regression for the custom-provider path: required-field validation must run
// against the resolved BASE provider, not the custom route name, or a custom
// provider based on Bedrock would skip the region requirement entirely.
func TestCreateProviderKey_CustomBedrockRequiresRegion(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	h := &ProviderHandler{
		inMemoryStore: &lib.Config{
			Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
				"aws-custom": {
					CustomProviderConfig: &schemas.CustomProviderConfig{
						BaseProviderType: schemas.Bedrock,
					},
				},
			},
		},
		modelsManager: &mockModelsManager{},
	}

	ctx := newTestRequestCtx(`{"value":"AKIAEXAMPLEKEY","weight":1.0,"bedrock_key_config":{}}`)
	ctx.SetUserValue("provider", "aws-custom")

	h.createProviderKey(ctx)
	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Fatalf("custom-bedrock create without region: status got %d, want 400; body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if body := string(ctx.Response.Body()); !strings.Contains(body, "bedrock_key_config.region") {
		t.Fatalf("expected bedrock_key_config.region error, got %s", body)
	}
}

// TestUpdateProviderKey_EndpointGuardWhenAuthBypassed pins that the fail-open bypass only
// blocks a key update that moves the dial destination. Keeping the stored endpoint and
// editing an unrelated field (weight) must still go through, or the auth-disabled UI
// cannot edit any existing Ollama/SGL/VLLM/Azure key.
func TestUpdateProviderKey_EndpointGuardWhenAuthBypassed(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	const storedURL = "http://localhost:11434"
	cases := []struct {
		name       string
		body       string
		wantStatus int
		wantURL    string
		wantWeight float64
	}{
		{
			name:       "unchanged endpoint, weight edit",
			body:       `{"weight":2,"ollama_key_config":{"url":"` + storedURL + `"}}`,
			wantStatus: fasthttp.StatusOK,
			wantURL:    storedURL,
			wantWeight: 2,
		},
		{
			name:       "changed endpoint",
			body:       `{"weight":1,"ollama_key_config":{"url":"http://169.254.169.254/"}}`,
			wantStatus: fasthttp.StatusForbidden,
			wantURL:    storedURL,
			wantWeight: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &ProviderHandler{
				inMemoryStore: &lib.Config{
					Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
						schemas.Ollama: {Keys: []schemas.Key{{
							ID:              "key-1",
							Name:            "ollama-key",
							Weight:          1,
							OllamaKeyConfig: &schemas.OllamaKeyConfig{URL: *schemas.NewSecretVar(storedURL)},
						}}},
					},
				},
				modelsManager: &mockModelsManager{},
			}
			attachBifrostClient(t, h.inMemoryStore)

			ctx := newTestRequestCtx(tc.body)
			ctx.SetUserValue("provider", string(schemas.Ollama))
			ctx.SetUserValue("key_id", "key-1")
			ctx.SetUserValue(schemas.BifrostContextKeyAuthBypassed, true)

			h.updateProviderKey(ctx)

			if ctx.Response.StatusCode() != tc.wantStatus {
				t.Fatalf("status got %d, want %d; body=%s", ctx.Response.StatusCode(), tc.wantStatus, ctx.Response.Body())
			}
			stored := h.inMemoryStore.Providers[schemas.Ollama].Keys[0]
			if got := stored.OllamaKeyConfig.URL.GetValue(); got != tc.wantURL {
				t.Fatalf("stored url got %q, want %q", got, tc.wantURL)
			}
			if stored.Weight != tc.wantWeight {
				t.Fatalf("stored weight got %v, want %v", stored.Weight, tc.wantWeight)
			}
		})
	}
}

// TestProviderKeyWeight_RejectsNegative pins that neither key write path stores a negative weight.
// Key selection draws a key by its share of the pool's total weight, and a negative weight once
// drove that total below zero, which panicked inside the request worker and took the gateway down.
func TestProviderKeyWeight_RejectsNegative(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	cases := []struct {
		name       string
		create     bool
		body       string
		wantStatus int
		wantWeight float64 // the stored weight of key-1 after the call
	}{
		{name: "create with a negative weight", create: true, body: `{"name":"new-key","value":"sk-test","weight":-1}`, wantStatus: fasthttp.StatusBadRequest, wantWeight: 1},
		{name: "create with a zero weight", create: true, body: `{"name":"new-key","value":"sk-test","weight":0}`, wantStatus: fasthttp.StatusOK, wantWeight: 1},
		{name: "update to a negative weight", body: `{"name":"openai-key","weight":-0.5}`, wantStatus: fasthttp.StatusBadRequest, wantWeight: 1},
		{name: "update to a zero weight", body: `{"name":"openai-key","weight":0}`, wantStatus: fasthttp.StatusOK, wantWeight: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &ProviderHandler{
				inMemoryStore: &lib.Config{
					Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
						schemas.OpenAI: {Keys: []schemas.Key{{
							ID:     "key-1",
							Name:   "openai-key",
							Value:  *schemas.NewSecretVar("sk-stored"),
							Weight: 1,
						}}},
					},
				},
				modelsManager: &mockModelsManager{},
			}
			attachBifrostClient(t, h.inMemoryStore)

			ctx := newTestRequestCtx(tc.body)
			ctx.SetUserValue("provider", string(schemas.OpenAI))
			if tc.create {
				h.createProviderKey(ctx)
			} else {
				ctx.SetUserValue("key_id", "key-1")
				h.updateProviderKey(ctx)
			}

			if ctx.Response.StatusCode() != tc.wantStatus {
				t.Fatalf("status got %d, want %d; body=%s", ctx.Response.StatusCode(), tc.wantStatus, ctx.Response.Body())
			}
			if tc.wantStatus == fasthttp.StatusBadRequest && !strings.Contains(string(ctx.Response.Body()), "weight") {
				t.Fatalf("expected the error to name the weight, got %s", ctx.Response.Body())
			}
			keys := h.inMemoryStore.Providers[schemas.OpenAI].Keys
			if tc.create && tc.wantStatus == fasthttp.StatusBadRequest && len(keys) != 1 {
				t.Fatalf("a rejected key must not be stored, got %d keys", len(keys))
			}
			if keys[0].Weight != tc.wantWeight {
				t.Fatalf("stored weight of key-1 got %v, want %v", keys[0].Weight, tc.wantWeight)
			}
		})
	}
}

// TestProviderKeyEndpointGuard_CoversEveryDialTarget pins that the fail-open bypass guard
// keys off the fields Bifrost dials, not a provider-type list. Each of these fields sends the
// key's credential to the configured host, so a bypassed caller must not be able to set or
// move any of them. A Bedrock key with only a region carries no caller-chosen host and must
// still be creatable, which a provider-type guard would wrongly reject.
func TestProviderKeyEndpointGuard_CoversEveryDialTarget(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	copilotPEM := pkcs1TestPEM(t)
	copilotConfig := func(domain string) string {
		return `{"app_id":"123","installation_id":"456","repository_id":"789","private_key":` + strconv.Quote(copilotPEM) + `,"github_domain":"` + domain + `"}`
	}

	// A Vertex credential JSON names where the Google client dials: a service account's
	// token_uri, and for an external account the token_url plus a credential_source the client
	// reads (here a local file) and posts there. Swapping the JSON therefore moves the key's
	// destination as surely as moving an Azure endpoint does.
	const vertexServiceAccountJSON = `{"type":"service_account","project_id":"p","client_email":"sa@p.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n","token_uri":"https://oauth2.googleapis.com/token"}`
	const vertexExternalAccountJSON = `{"type":"external_account","audience":"//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","token_url":"https://evil.example.com/token","credential_source":{"file":"/etc/bifrost/config.json"}}`
	vertexConfig := func(credentials string) string {
		return `{"project_id":"p","region":"us-central1","auth_credentials":` + strconv.Quote(credentials) + `}`
	}
	vertexStored := func() *schemas.Key {
		return &schemas.Key{
			ID: "key-1", Name: "vertex-key", Weight: 1,
			VertexKeyConfig: &schemas.VertexKeyConfig{
				ProjectID:       *schemas.NewSecretVar("p"),
				Region:          *schemas.NewSecretVar("us-central1"),
				AuthCredentials: *schemas.NewSecretVar(vertexServiceAccountJSON),
			},
		}
	}

	cases := []struct {
		name        string
		provider    schemas.ModelProvider
		stored      *schemas.Key // nil means the request creates the key
		genuineAuth bool         // the request carries a real credential, not the fail-open bypass
		body        string
		want403     bool
		wantNamed   string // a 403 must name this field
	}{
		{
			name:     "create bedrock key with region only",
			provider: schemas.Bedrock,
			body:     `{"name":"bedrock-key","weight":1,"bedrock_key_config":{"access_key":"AKIAEXAMPLE","secret_key":"secret","region":"us-east-1"}}`,
			want403:  false,
		},
		{
			name:     "create bedrock key with runtime endpoint override",
			provider: schemas.Bedrock,
			body:     `{"name":"bedrock-key","weight":1,"bedrock_key_config":{"access_key":"AKIAEXAMPLE","secret_key":"secret","region":"us-east-1","endpoints":{"runtime":"evil.example.com"}}}`,
			want403:  true,
		},
		{
			name:     "update databricks workspace url",
			provider: schemas.Databricks,
			stored: &schemas.Key{
				ID: "key-1", Name: "databricks-key", Weight: 1,
				Value:               *schemas.NewSecretVar("dapi-token"),
				DatabricksKeyConfig: &schemas.DatabricksKeyConfig{WorkspaceURL: *schemas.NewSecretVar("https://adb-1.azuredatabricks.net")},
			},
			body:    `{"value":"dapi-token","weight":1,"databricks_key_config":{"workspace_url":"https://evil.example.com"}}`,
			want403: true,
		},
		{
			name:     "update bedrock mantle endpoint override",
			provider: schemas.BedrockMantle,
			stored: &schemas.Key{
				ID: "key-1", Name: "mantle-key", Weight: 1,
				BedrockMantleKeyConfig: &schemas.BedrockMantleKeyConfig{Region: schemas.NewSecretVar("us-east-1")},
			},
			body:    `{"weight":1,"bedrock_mantle_key_config":{"region":"us-east-1","endpoints":{"mantle":"evil.example.com"}}}`,
			want403: true,
		},
		{
			name:     "update github copilot github_domain",
			provider: schemas.GithubCopilot,
			stored: &schemas.Key{
				ID: "key-1", Name: "copilot-key", Weight: 1,
				Value: *schemas.NewSecretVar("ghu_copilot_token"),
				GithubCopilotKeyConfig: &schemas.GithubCopilotKeyConfig{
					AppID:          *schemas.NewSecretVar("123"),
					InstallationID: *schemas.NewSecretVar("456"),
					RepositoryID:   *schemas.NewSecretVar("789"),
					PrivateKey:     *schemas.NewSecretVar(copilotPEM),
					GithubDomain:   *schemas.NewSecretVar("acme.ghe.com"),
				},
			},
			body:    `{"value":"ghu_copilot_token","weight":1,"github_copilot_key_config":` + copilotConfig("evil.example.com") + `}`,
			want403: true,
		},
		{
			name:     "update azure key adding a per-alias endpoint",
			provider: schemas.Azure,
			stored: &schemas.Key{
				ID: "key-1", Name: "azure-key", Weight: 1,
				Value:          *schemas.NewSecretVar("azure-api-key"),
				AzureKeyConfig: &schemas.AzureKeyConfig{Endpoint: *schemas.NewSecretVar("https://myres.openai.azure.com")},
			},
			body:    `{"value":"azure-api-key","weight":1,"azure_key_config":{"endpoint":"https://myres.openai.azure.com"},"aliases":{"gpt-4o":{"model_id":"gpt-4o","endpoint":"https://evil.example.com"}}}`,
			want403: true,
		},
		{
			name:      "create vertex key with a credential json",
			provider:  schemas.Vertex,
			body:      `{"name":"vertex-key","weight":1,"vertex_key_config":` + vertexConfig(vertexServiceAccountJSON) + `}`,
			want403:   true,
			wantNamed: "vertex_key_config.auth_credentials",
		},
		{
			name:      "update vertex key swapping the credential json for an external account",
			provider:  schemas.Vertex,
			stored:    vertexStored(),
			body:      `{"weight":1,"vertex_key_config":` + vertexConfig(vertexExternalAccountJSON) + `}`,
			want403:   true,
			wantNamed: "vertex_key_config.auth_credentials",
		},
		{
			name:     "update vertex key removing the credential json",
			provider: schemas.Vertex,
			stored:   vertexStored(),
			body:     `{"weight":1,"vertex_key_config":{"project_id":"p","region":"us-central1","auth_credentials":""}}`,
			want403:  true,
		},
		{
			name:     "update vertex key keeping its stored credential json",
			provider: schemas.Vertex,
			stored:   vertexStored(),
			body:     `{"weight":2,"vertex_key_config":` + vertexConfig(vertexServiceAccountJSON) + `}`,
			want403:  false,
		},
		{
			name:        "genuinely authenticated update vertex key swapping the credential json",
			provider:    schemas.Vertex,
			stored:      vertexStored(),
			genuineAuth: true,
			body:        `{"weight":1,"vertex_key_config":` + vertexConfig(vertexExternalAccountJSON) + `}`,
			want403:     false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			providerConfig := configstore.ProviderConfig{}
			if tc.stored != nil {
				providerConfig.Keys = []schemas.Key{*tc.stored}
			}
			h := &ProviderHandler{
				inMemoryStore: &lib.Config{Providers: map[schemas.ModelProvider]configstore.ProviderConfig{tc.provider: providerConfig}},
				modelsManager: &mockModelsManager{},
			}
			attachBifrostClient(t, h.inMemoryStore)

			ctx := newTestRequestCtx(tc.body)
			ctx.SetUserValue("provider", string(tc.provider))
			if !tc.genuineAuth {
				ctx.SetUserValue(schemas.BifrostContextKeyAuthBypassed, true)
			}
			if tc.stored != nil {
				ctx.SetUserValue("key_id", tc.stored.ID)
				h.updateProviderKey(ctx)
			} else {
				h.createProviderKey(ctx)
			}

			got403 := ctx.Response.StatusCode() == fasthttp.StatusForbidden
			if got403 != tc.want403 {
				t.Fatalf("got status %d, want403=%v; body=%s", ctx.Response.StatusCode(), tc.want403, ctx.Response.Body())
			}
			if tc.wantNamed != "" && !strings.Contains(string(ctx.Response.Body()), tc.wantNamed) {
				t.Fatalf("the refusal must name %s, got %s", tc.wantNamed, ctx.Response.Body())
			}
			keys := h.inMemoryStore.Providers[tc.provider].Keys
			switch {
			case tc.want403 && tc.stored != nil:
				if len(keys) != 1 || !reflect.DeepEqual(keys[0], *tc.stored) {
					t.Fatalf("expected stored key unchanged after 403, got %+v", keys)
				}
			case tc.want403:
				if len(keys) != 0 {
					t.Fatalf("expected no key persisted after 403, got %d", len(keys))
				}
			default:
				if ctx.Response.StatusCode() != fasthttp.StatusOK || len(keys) != 1 {
					t.Fatalf("expected key persisted with 200, got status %d and %d keys; body=%s", ctx.Response.StatusCode(), len(keys), ctx.Response.Body())
				}
			}
		})
	}
}

// TestProviderKeyURL_RejectsLinkLocalDestination pins that a key-level server URL
// (Ollama/SGL/VLLM) is held to the same destination rule as a provider base URL, even for a
// genuinely authenticated admin: link-local and unspecified addresses are refused with 400,
// while loopback and private hosts - the documented self-hosted setup - stay allowed.
func TestProviderKeyURL_RejectsLinkLocalDestination(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	const storedURL = "http://localhost:11434"
	cases := []struct {
		name       string
		stored     bool
		body       string
		wantStatus int
	}{
		{name: "create with link-local url", body: `{"name":"ollama-key","weight":1,"ollama_key_config":{"url":"http://169.254.169.254/"}}`, wantStatus: fasthttp.StatusBadRequest},
		{name: "create with unspecified url", body: `{"name":"ollama-key","weight":1,"ollama_key_config":{"url":"http://0.0.0.0:11434"}}`, wantStatus: fasthttp.StatusBadRequest},
		{name: "create with private url", body: `{"name":"ollama-key","weight":1,"ollama_key_config":{"url":"http://10.0.0.5:11434"}}`, wantStatus: fasthttp.StatusOK},
		{name: "update to link-local url", stored: true, body: `{"weight":1,"ollama_key_config":{"url":"http://169.254.169.254/"}}`, wantStatus: fasthttp.StatusBadRequest},
		{name: "update to loopback url", stored: true, body: `{"weight":1,"ollama_key_config":{"url":"http://127.0.0.1:11435"}}`, wantStatus: fasthttp.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			providerConfig := configstore.ProviderConfig{}
			if tc.stored {
				providerConfig.Keys = []schemas.Key{{
					ID: "key-1", Name: "ollama-key", Weight: 1,
					OllamaKeyConfig: &schemas.OllamaKeyConfig{URL: *schemas.NewSecretVar(storedURL)},
				}}
			}
			h := &ProviderHandler{
				inMemoryStore: &lib.Config{Providers: map[schemas.ModelProvider]configstore.ProviderConfig{schemas.Ollama: providerConfig}},
				modelsManager: &mockModelsManager{},
			}
			attachBifrostClient(t, h.inMemoryStore)

			ctx := newTestRequestCtx(tc.body)
			ctx.SetUserValue("provider", string(schemas.Ollama))
			if tc.stored {
				ctx.SetUserValue("key_id", "key-1")
				h.updateProviderKey(ctx)
			} else {
				h.createProviderKey(ctx)
			}

			if ctx.Response.StatusCode() != tc.wantStatus {
				t.Fatalf("status got %d, want %d; body=%s", ctx.Response.StatusCode(), tc.wantStatus, ctx.Response.Body())
			}
			keys := h.inMemoryStore.Providers[schemas.Ollama].Keys
			switch {
			case tc.wantStatus != fasthttp.StatusOK && tc.stored:
				if len(keys) != 1 || keys[0].OllamaKeyConfig.URL.GetValue() != storedURL {
					t.Fatalf("expected stored url unchanged after 400, got %+v", keys)
				}
			case tc.wantStatus != fasthttp.StatusOK:
				if len(keys) != 0 {
					t.Fatalf("expected no key persisted after 400, got %d", len(keys))
				}
			default:
				if len(keys) != 1 {
					t.Fatalf("expected one key persisted, got %d", len(keys))
				}
			}
		})
	}
}

// TestProviderKeyRegion_RejectsHostShapedValues pins that a key-level or per-alias region can
// only name a vendor region. Region is interpolated into the provider host
// (<region>-aiplatform.googleapis.com, <service>.<region>.amazonaws.com), so a host-shaped value
// would carry the key's credential to a caller-chosen host while region stays outside the
// endpoint guard (a region-only Bedrock key must remain creatable without an admin session).
func TestProviderKeyRegion_RejectsHostShapedValues(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	cases := []struct {
		name       string
		provider   schemas.ModelProvider
		body       string
		wantStatus int
	}{
		{name: "bedrock valid region", provider: schemas.Bedrock, body: `{"name":"k","weight":1,"bedrock_key_config":{"access_key":"AKIAEXAMPLE","secret_key":"secret","region":"us-gov-west-1"}}`, wantStatus: fasthttp.StatusOK},
		{name: "bedrock host-shaped region", provider: schemas.Bedrock, body: `{"name":"k","weight":1,"bedrock_key_config":{"access_key":"AKIAEXAMPLE","secret_key":"secret","region":"evil.example/#"}}`, wantStatus: fasthttp.StatusBadRequest},
		{name: "bedrock region with userinfo", provider: schemas.Bedrock, body: `{"name":"k","weight":1,"bedrock_key_config":{"access_key":"AKIAEXAMPLE","secret_key":"secret","region":"us-east-1@evil.example"}}`, wantStatus: fasthttp.StatusBadRequest},
		{name: "bedrock alias host-shaped region", provider: schemas.Bedrock, body: `{"name":"k","weight":1,"bedrock_key_config":{"access_key":"AKIAEXAMPLE","secret_key":"secret","region":"us-east-1"},"aliases":{"claude":{"model_id":"anthropic.claude-3","region":"evil.example/#"}}}`, wantStatus: fasthttp.StatusBadRequest},
		{name: "bedrock alias valid region", provider: schemas.Bedrock, body: `{"name":"k","weight":1,"bedrock_key_config":{"access_key":"AKIAEXAMPLE","secret_key":"secret","region":"us-east-1"},"aliases":{"claude":{"model_id":"anthropic.claude-3","region":"eu-west-1"}}}`, wantStatus: fasthttp.StatusOK},
		{name: "vertex host-shaped region", provider: schemas.Vertex, body: `{"name":"k","weight":1,"vertex_key_config":{"project_id":"p","region":"attacker.example/x?","auth_credentials":"{}"}}`, wantStatus: fasthttp.StatusBadRequest},
		{name: "mantle host-shaped region", provider: schemas.BedrockMantle, body: `{"name":"k","weight":1,"bedrock_mantle_key_config":{"region":"evil.example/#"}}`, wantStatus: fasthttp.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &ProviderHandler{
				inMemoryStore: &lib.Config{Providers: map[schemas.ModelProvider]configstore.ProviderConfig{tc.provider: {}}},
				modelsManager: &mockModelsManager{},
			}
			attachBifrostClient(t, h.inMemoryStore)
			ctx := newTestRequestCtx(tc.body)
			ctx.SetUserValue("provider", string(tc.provider))
			h.createProviderKey(ctx)
			if ctx.Response.StatusCode() != tc.wantStatus {
				t.Fatalf("status got %d, want %d; body=%s", ctx.Response.StatusCode(), tc.wantStatus, ctx.Response.Body())
			}
			if tc.wantStatus == fasthttp.StatusBadRequest {
				if !strings.Contains(string(ctx.Response.Body()), "region") {
					t.Fatalf("rejection must name the region field, got %s", ctx.Response.Body())
				}
				if len(h.inMemoryStore.Providers[tc.provider].Keys) != 0 {
					t.Fatal("a rejected key must not be persisted")
				}
			}
		})
	}
}

// One RSA key for the whole file. Generating them is slow enough to notice per case.
var (
	handlerKeyOnce sync.Once
	handlerRSAKey  *rsa.PrivateKey
)

func handlerRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	handlerKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		handlerRSAKey = key
	})
	return handlerRSAKey
}

func pkcs1TestPEM(t *testing.T) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(handlerRSA(t))}))
}

func pkcs8TestPEM(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(handlerRSA(t))
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// ecCurveTestPEM returns an EC private key on the given curve, as SEC1 or as PKCS#8.
func ecCurveTestPEM(t *testing.T, curve elliptic.Curve, pkcs8 bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ec: %v", err)
	}
	if pkcs8 {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshal pkcs8: %v", err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal ec: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func ecTestPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal ec: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// TestMergeUpdatedKey_VertexAWSWorkloadIdentityRoleARN covers the one masked field inside the
// Vertex federation block. GET renders aws_role_arn as a mask, so an edit that leaves it alone
// sends the mask back; the merge must restore the stored ARN and must never persist the mask.
// The identifiers in the block (audience, service account, region) are returned in clear and
// therefore pass through untouched.
func TestMergeUpdatedKey_VertexAWSWorkloadIdentityRoleARN(t *testing.T) {
	h := &ProviderHandler{}
	secret := func(value string) schemas.SecretVar { return *schemas.NewSecretVar(value) }
	secretPtr := func(value string) *schemas.SecretVar { return schemas.NewSecretVar(value) }
	mask := "arn:" + strings.Repeat("*", 24) + "Hop0"

	stored := schemas.Key{
		VertexKeyConfig: &schemas.VertexKeyConfig{
			ProjectID: secret("my-project"),
			Region:    secret("us-central1"),
			AWSWorkloadIdentity: &schemas.VertexAWSWorkloadIdentityConfig{
				Audience:            secret("//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/aws"),
				ServiceAccountEmail: secretPtr("vertex@my-project.iam.gserviceaccount.com"),
				AWSRoleARN:          secretPtr("arn:aws:iam::123456789012:role/VertexHop"),
			},
		},
	}
	update := schemas.Key{
		VertexKeyConfig: &schemas.VertexKeyConfig{
			ProjectID: secret("my-project"),
			Region:    secret("us-central1"),
			AWSWorkloadIdentity: &schemas.VertexAWSWorkloadIdentityConfig{
				Audience:            secret("//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/aws"),
				ServiceAccountEmail: secretPtr("other@my-project.iam.gserviceaccount.com"),
				AWSRoleARN:          secretPtr(mask),
			},
		},
	}

	merged, err := h.mergeUpdatedKey(stored, update)
	if err != nil {
		t.Fatalf("mergeUpdatedKey returned error: %v", err)
	}
	if got := merged.VertexKeyConfig.AWSWorkloadIdentity.AWSRoleARN.GetValue(); got != "arn:aws:iam::123456789012:role/VertexHop" {
		t.Errorf("expected stored aws_role_arn to be preserved, got %q", got)
	}
	if got := merged.VertexKeyConfig.AWSWorkloadIdentity.ServiceAccountEmail.GetValue(); got != "other@my-project.iam.gserviceaccount.com" {
		t.Errorf("expected edited service_account_email to be applied, got %q", got)
	}

	// A mask with nothing stored behind it is a client bug and must be rejected, not persisted.
	// The first merge rewrote the update's pointer in place, so send a fresh mask.
	stored.VertexKeyConfig.AWSWorkloadIdentity = nil
	update.VertexKeyConfig.AWSWorkloadIdentity.AWSRoleARN = secretPtr(mask)
	if _, err := h.mergeUpdatedKey(stored, update); err == nil {
		t.Fatal("expected masked aws_role_arn without a stored value to be rejected")
	}

	// Omitting the role ARN entirely (direct access, no hop) must not trip the guard.
	update.VertexKeyConfig.AWSWorkloadIdentity.AWSRoleARN = nil
	if _, err := h.mergeUpdatedKey(stored, update); err != nil {
		t.Fatalf("expected federation block without aws_role_arn to merge cleanly, got: %v", err)
	}
}

// TestValidateVertexKeyAuth pins the API-side counterpart of the config.schema.json rule: a Vertex key
// must not carry both an aws_workload_identity block and a non-empty auth_credentials JSON. Without
// this check the API silently let federation take precedence over a credentials JSON the operator
// also supplied, while config.json rejected the same combination.
func TestValidateVertexKeyAuth(t *testing.T) {
	secret := func(v string) schemas.SecretVar { return *schemas.NewSecretVar(v) }
	wif := &schemas.VertexAWSWorkloadIdentityConfig{Audience: secret("//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/aws")}
	vertex := func(cfg *schemas.VertexKeyConfig) schemas.Key { return schemas.Key{VertexKeyConfig: cfg} }

	err := validateVertexKeyAuth(schemas.Vertex, vertex(&schemas.VertexKeyConfig{
		ProjectID: secret("p"), Region: secret("r"),
		AuthCredentials:     secret(`{"type":"service_account"}`),
		AWSWorkloadIdentity: wif,
	}))
	if err == nil {
		t.Fatal("expected auth_credentials alongside aws_workload_identity to be rejected")
	}
	for _, want := range []string{"auth_credentials", "aws_workload_identity"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should name %s", err.Error(), want)
		}
	}

	// An env reference for the credentials is just as much a second identity.
	t.Setenv("TEST_VERTEX_CREDS", `{"type":"service_account"}`)
	if err := validateVertexKeyAuth(schemas.Vertex, vertex(&schemas.VertexKeyConfig{
		ProjectID: secret("p"), Region: secret("r"),
		AuthCredentials: secret("env.TEST_VERTEX_CREDS"), AWSWorkloadIdentity: wif,
	})); err == nil {
		t.Fatal("expected env-referenced auth_credentials alongside aws_workload_identity to be rejected")
	}

	// A present block without an audience is a broken federation config, not "no federation": the
	// configuration schema requires audience whenever the block exists, and so does the API.
	for name, block := range map[string]*schemas.VertexAWSWorkloadIdentityConfig{
		"empty block":    {},
		"email only":     {ServiceAccountEmail: schemas.NewSecretVar("sa@p.iam.gserviceaccount.com")},
		"empty audience": {Audience: secret("")},
	} {
		err := validateVertexKeyAuth(schemas.Vertex, vertex(&schemas.VertexKeyConfig{ProjectID: secret("p"), Region: secret("r"), AWSWorkloadIdentity: block}))
		if err == nil || !strings.Contains(err.Error(), "audience") {
			t.Errorf("%s: expected an audience error, got %v", name, err)
		}
	}
	// token_lifetime_seconds mirrors the configuration schema bounds; zero means "not set".
	for _, lifetime := range []int{599, 43201, -1} {
		err := validateVertexKeyAuth(schemas.Vertex, vertex(&schemas.VertexKeyConfig{ProjectID: secret("p"), Region: secret("r"),
			AWSWorkloadIdentity: &schemas.VertexAWSWorkloadIdentityConfig{Audience: wif.Audience, TokenLifetimeSeconds: lifetime}}))
		if err == nil || !strings.Contains(err.Error(), "token_lifetime_seconds") {
			t.Errorf("lifetime %d: expected a token_lifetime_seconds error, got %v", lifetime, err)
		}
	}

	accepted := []schemas.Key{
		vertex(&schemas.VertexKeyConfig{ProjectID: secret("p"), Region: secret("r"), AWSWorkloadIdentity: wif}),
		vertex(&schemas.VertexKeyConfig{ProjectID: secret("p"), Region: secret("r"), AuthCredentials: secret(""), AWSWorkloadIdentity: wif}),
		vertex(&schemas.VertexKeyConfig{ProjectID: secret("p"), Region: secret("r"), AuthCredentials: secret(`{"type":"service_account"}`)}),
		vertex(&schemas.VertexKeyConfig{ProjectID: secret("p"), Region: secret("r")}),
		vertex(&schemas.VertexKeyConfig{ProjectID: secret("p"), Region: secret("r"), AWSWorkloadIdentity: &schemas.VertexAWSWorkloadIdentityConfig{Audience: wif.Audience, TokenLifetimeSeconds: 600}}),
		vertex(&schemas.VertexKeyConfig{ProjectID: secret("p"), Region: secret("r"), AWSWorkloadIdentity: &schemas.VertexAWSWorkloadIdentityConfig{Audience: wif.Audience, TokenLifetimeSeconds: 43200}}),
		{Value: secret("api-key")},
	}
	for i, key := range accepted {
		if err := validateVertexKeyAuth(schemas.Vertex, key); err != nil {
			t.Errorf("accepted case %d rejected: %v", i, err)
		}
	}
	// Other providers never carry the block and are never touched.
	if err := validateVertexKeyAuth(schemas.OpenAI, vertex(&schemas.VertexKeyConfig{AuthCredentials: secret("x"), AWSWorkloadIdentity: wif})); err != nil {
		t.Errorf("non-vertex provider must not be validated: %v", err)
	}
}

// TestRejectUnknownOAuthKeyConfigFields pins API parity with config.schema.json, which sets
// additionalProperties:false on oauth_key_config: sonic drops unknown fields, so a misspelled
// "scope" would otherwise save a block that never requests its scopes.
func TestRejectUnknownOAuthKeyConfigFields(t *testing.T) {
	valid := `"grant_type":"client_credentials","token_url":"https://idp.example/oauth2/token","client_id":"id","client_secret":"s"`
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"no block", `{"value":"sk","weight":1}`, ""},
		{"null block", `{"value":"sk","oauth_key_config":null}`, ""},
		{"known fields only", `{"oauth_key_config":{` + valid + `,"scopes":["inference"],"extra_params":{"resource":"r"}}}`, ""},
		{"secret references", `{"oauth_key_config":{` + valid + `,"client_secret":{"ref":"OAUTH_SECRET","type":"env"}}}`, ""},
		{"misspelled scopes", `{"oauth_key_config":{` + valid + `,"scope":["inference"]}}`, `unknown field "scope"`},
		{"unknown nested field", `{"oauth_key_config":{` + valid + `,"client_secrett":"s"}}`, `unknown field "client_secrett"`},
		{"unknown field outside the block is not this check's job", `{"oauth_key_config":{` + valid + `},"colour":"blue"}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := rejectUnknownOAuthKeyConfigFields([]byte(tc.body))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error got %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestProviderKeyWrites_RejectUnknownOAuthKeyConfigFields pins that both write paths refuse a
// block carrying a field the schema does not know, naming the field, instead of saving it
// without that setting.
func TestProviderKeyWrites_RejectUnknownOAuthKeyConfigFields(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})
	block := `{"grant_type":"client_credentials","token_url":"https://idp.example/oauth2/token","client_id":"id","client_secret":"s","scope":["inference"]}`

	t.Run("create", func(t *testing.T) {
		h := &ProviderHandler{
			inMemoryStore: &lib.Config{Providers: map[schemas.ModelProvider]configstore.ProviderConfig{schemas.OpenAI: {}}},
			modelsManager: &mockModelsManager{},
		}
		attachBifrostClient(t, h.inMemoryStore)
		ctx := newTestRequestCtx(`{"name":"oauth","weight":1,"oauth_key_config":` + block + `}`)
		ctx.SetUserValue("provider", string(schemas.OpenAI))
		h.createProviderKey(ctx)
		if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
			t.Fatalf("status got %d, want 400; body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
		}
		// The JSON error body escapes the quotes around the field name.
		if body := string(ctx.Response.Body()); !strings.Contains(body, `oauth_key_config: unknown field \"scope\"`) {
			t.Fatalf("the response must name the unknown field, got %s", body)
		}
	})

	t.Run("update", func(t *testing.T) {
		h := &ProviderHandler{
			inMemoryStore: &lib.Config{Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
				schemas.OpenAI: {Keys: []schemas.Key{{ID: "key-1", Name: "oauth", Weight: 1, OAuthKeyConfig: &schemas.OAuthKeyConfig{
					GrantType:    schemas.OAuthGrantClientCredentials,
					TokenURL:     *schemas.NewSecretVar("https://idp.example/oauth2/token"),
					ClientID:     schemas.NewSecretVar("id"),
					ClientSecret: schemas.NewSecretVar("s"),
				}}}},
			}},
			modelsManager: &mockModelsManager{},
		}
		attachBifrostClient(t, h.inMemoryStore)
		ctx := newTestRequestCtx(`{"oauth_key_config":` + block + `}`)
		ctx.SetUserValue("provider", string(schemas.OpenAI))
		ctx.SetUserValue("key_id", "key-1")
		h.updateProviderKey(ctx)
		if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
			t.Fatalf("status got %d, want 400; body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
		}
		// The JSON error body escapes the quotes around the field name.
		if body := string(ctx.Response.Body()); !strings.Contains(body, `oauth_key_config: unknown field \"scope\"`) {
			t.Fatalf("the response must name the unknown field, got %s", body)
		}
		if stored := h.inMemoryStore.Providers[schemas.OpenAI].Keys[0]; len(stored.OAuthKeyConfig.Scopes) != 0 || stored.OAuthKeyConfig.ClientID.GetValue() != "id" {
			t.Fatalf("the stored key must be untouched, got %+v", stored.OAuthKeyConfig)
		}
	})
}

// tokenWriteStore records the key writes the token-persistence path performs. It embeds the
// interface so a method this path does not touch panics rather than silently returning a zero
// value, and so the assertions below can only pass on a real store round-trip.
type tokenWriteStore struct {
	configstore.ConfigStore
	keys map[string]schemas.Key
	// mu guards keys and writes: the rotation write runs on a background goroutine, so the test
	// goroutine and the store goroutine touch these fields concurrently.
	mu     sync.Mutex
	writes int
	// persistDelay stalls every store call, so a test can prove the request path does not wait
	// for the write. It is applied to both UpdateProviderKey and GetProviderKey.
	persistDelay time.Duration
	// delayFor, when set, returns the delay for one UpdateProviderKey call. It is keyed on the row
	// being written rather than on arrival order: arrival order is what the test is trying to
	// control, so using it to assign delays lets the two writes swap and pass a mutation they
	// should catch.
	delayFor func(key schemas.Key) time.Duration
}

func newTokenWriteStore(keys ...schemas.Key) *tokenWriteStore {
	store := &tokenWriteStore{keys: make(map[string]schemas.Key, len(keys))}
	for _, key := range keys {
		store.keys[key.ID] = key
	}
	return store
}

func (s *tokenWriteStore) UpdateProviderKey(ctx context.Context, _ schemas.ModelProvider, keyID string, key schemas.Key, _ ...*gorm.DB) error {
	delay := s.persistDelay
	if s.delayFor != nil {
		delay = s.delayFor(key)
	}

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[keyID]; !ok {
		return configstore.ErrNotFound
	}
	s.keys[keyID] = key
	s.writes++
	return nil
}

func (s *tokenWriteStore) GetProviderKey(ctx context.Context, _ schemas.ModelProvider, keyID string) (*schemas.Key, error) {
	if s.persistDelay > 0 {
		select {
		case <-time.After(s.persistDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.keys[keyID]
	if !ok {
		return nil, configstore.ErrNotFound
	}
	return &key, nil
}

// storedKey returns one key as the store holds it now.
func (s *tokenWriteStore) storedKey(t *testing.T, keyID string) schemas.Key {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys[keyID]
}

// writeCount reports how many store writes have landed.
func (s *tokenWriteStore) writeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

// storedProviderKey reads a key through the locked accessor. The rotation write persists on a
// background goroutine, so a test that indexed config.Providers directly would race with it.
func storedProviderKey(t *testing.T, config *lib.Config, keyID string) schemas.Key {
	t.Helper()
	key, err := config.GetProviderKeyRaw(schemas.CodeBuddyCN, keyID)
	if err != nil {
		t.Fatalf("GetProviderKeyRaw: %v", err)
	}
	return *key
}

// awaitWrites waits for the asynchronous rotation write to land. The rotation applies to the
// in-memory key synchronously and persists on a background goroutine, so an assertion about the
// store has to wait rather than read immediately.
func (s *tokenWriteStore) awaitWrites(t *testing.T, want int) {
	t.Helper()
	require.Eventually(t, func() bool { return s.writeCount() == want }, 5*time.Second, time.Millisecond,
		"store writes = %d, want %d", s.writeCount(), want)
}

// browserLoginConfig is a complete browser_login bundle. The endpoint is the real CodeBuddy one,
// which is https and therefore accepted by the management API's token-URL shape check.
func browserLoginConfig() *schemas.OAuthKeyConfig {
	return &schemas.OAuthKeyConfig{
		GrantType:    schemas.OAuthGrantBrowserLogin,
		TokenURL:     *schemas.NewSecretVar("https://copilot.tencent.com/v2/plugin/auth/token/refresh"),
		AccessToken:  schemas.NewSecretVar("access-stored"),
		RefreshToken: schemas.NewSecretVar("refresh-stored"),
		ExpiresAt:    "2026-10-22T12:00:00Z",
	}
}

// TestUpdateProviderKeyResolvesMaskedOAuthTokens pins the write-side guard for the two rotating
// browser_login fields. A GET masks access_token and refresh_token; the UI echoes those masks on
// every save. Without the preserve entries the asterisks are stored as the credential, the next
// refresh sends them upstream, and the key dies permanently.
func TestUpdateProviderKeyResolvesMaskedOAuthTokens(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	stored := browserLoginConfig()
	masked := stored.Redacted()
	h := &ProviderHandler{
		inMemoryStore: &lib.Config{
			Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
				schemas.CodeBuddyCN: {Keys: []schemas.Key{{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: stored}}},
			},
		},
		modelsManager: &mockModelsManager{},
	}
	attachBifrostClient(t, h.inMemoryStore)

	body, err := json.Marshal(map[string]any{
		"name": "cb",
		"oauth_key_config": map[string]any{
			"grant_type":    string(schemas.OAuthGrantBrowserLogin),
			"token_url":     "https://copilot.tencent.com/v2/plugin/auth/token/refresh",
			"access_token":  masked.AccessToken.GetValue(),
			"refresh_token": masked.RefreshToken.GetValue(),
			"expires_at":    "2026-10-22T12:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	ctx := newTestRequestCtx(string(body))
	ctx.SetUserValue("provider", string(schemas.CodeBuddyCN))
	ctx.SetUserValue("key_id", "key-1")
	h.updateProviderKey(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("status got %d, want 200; body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	got := h.inMemoryStore.Providers[schemas.CodeBuddyCN].Keys[0].OAuthKeyConfig
	if got.AccessToken.GetValue() != "access-stored" {
		t.Errorf("stored access token = %q, want the stored credential, not the mask", got.AccessToken.GetValue())
	}
	if got.RefreshToken.GetValue() != "refresh-stored" {
		t.Errorf("stored refresh token = %q, want the stored credential, not the mask", got.RefreshToken.GetValue())
	}
}

// TestCodeBuddyCNAllowsEmptyValueWithOAuthBundle pins the OAuth-only key: the credential is the
// bundle, so an empty value is not a missing credential.
func TestCodeBuddyCNAllowsEmptyValueWithOAuthBundle(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	h := &ProviderHandler{
		inMemoryStore: &lib.Config{
			Providers: map[schemas.ModelProvider]configstore.ProviderConfig{schemas.CodeBuddyCN: {}},
		},
		modelsManager: &mockModelsManager{},
	}
	attachBifrostClient(t, h.inMemoryStore)

	body, err := json.Marshal(map[string]any{
		"name": "cb-oauth",
		"oauth_key_config": map[string]any{
			"grant_type":    string(schemas.OAuthGrantBrowserLogin),
			"token_url":     "https://copilot.tencent.com/v2/plugin/auth/token/refresh",
			"refresh_token": "refresh-1",
		},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	ctx := newTestRequestCtx(string(body))
	ctx.SetUserValue("provider", string(schemas.CodeBuddyCN))
	h.createProviderKey(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("an oauth-only key must be accepted, got %d; body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
}

// TestCodeBuddyCNRejectsBothAuthModes closes the ambiguity the two credential shapes create: a
// key carrying both a pasted value and an oauth bundle does not say which one authenticates, and
// resolveKey would silently prefer the pasted value, leaving the login unused.
func TestCodeBuddyCNRejectsBothAuthModes(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	h := &ProviderHandler{
		inMemoryStore: &lib.Config{
			Providers: map[schemas.ModelProvider]configstore.ProviderConfig{schemas.CodeBuddyCN: {}},
		},
		modelsManager: &mockModelsManager{},
	}
	attachBifrostClient(t, h.inMemoryStore)

	ctx := newTestRequestCtx(`{"name":"cb-both","value":"sk-pasted","oauth_key_config":{` +
		`"grant_type":"browser_login",` +
		`"token_url":"https://copilot.tencent.com/v2/plugin/auth/token/refresh",` +
		`"refresh_token":"refresh-1"}}`)
	ctx.SetUserValue("provider", string(schemas.CodeBuddyCN))
	h.createProviderKey(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Fatalf("status got %d, want 400; body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if body := string(ctx.Response.Body()); !strings.Contains(body, "either a pasted api key or an oauth login, not both") {
		t.Fatalf("the rejection must name the conflict, got %s", body)
	}
	if keys := h.inMemoryStore.Providers[schemas.CodeBuddyCN].Keys; len(keys) != 0 {
		t.Fatalf("a rejected key must not be stored, got %+v", keys)
	}
}

// TestCodeBuddyCNRejectsNeitherAuthMode closes the window CanProviderKeyValueBeEmpty opened:
// codebuddy-cn admits an empty value, but only because the bundle then carries the credential.
// A key with neither is unusable and must be refused where the operator can fix it.
func TestCodeBuddyCNRejectsNeitherAuthMode(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	h := &ProviderHandler{
		inMemoryStore: &lib.Config{
			Providers: map[schemas.ModelProvider]configstore.ProviderConfig{schemas.CodeBuddyCN: {}},
		},
		modelsManager: &mockModelsManager{},
	}
	attachBifrostClient(t, h.inMemoryStore)

	ctx := newTestRequestCtx(`{"name":"cb-empty"}`)
	ctx.SetUserValue("provider", string(schemas.CodeBuddyCN))
	h.createProviderKey(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Fatalf("status got %d, want 400; body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if body := string(ctx.Response.Body()); !strings.Contains(body, "requires either value or oauth_key_config") {
		t.Fatalf("the rejection must name the missing auth mode, got %s", body)
	}
}

// TestUpdateProviderKeyTokensSkipsProviderRebuild pins the difference between an operator editing
// a key and a routine token refresh. The write must reach the store and the in-memory key, but
// must not rebuild the provider: that stops and restarts the provider's worker queue, which is
// wrong on the inference path a refresh runs on.
func TestUpdateProviderKeyTokensSkipsProviderRebuild(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	store := newTokenWriteStore(schemas.Key{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()})
	inMemory := &lib.Config{
		ConfigStore: store,
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {Keys: []schemas.Key{{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()}}},
		},
	}
	client := attachBifrostClientReturning(t, inMemory)
	before := client.GetProviderByKey(schemas.CodeBuddyCN)
	if before == nil {
		t.Fatal("codebuddy-cn provider was not constructed")
	}

	if err := inMemory.UpdateProviderKeyTokens(context.Background(), schemas.CodeBuddyCN, "key-1", "access-2", "refresh-2", "2026-10-22T13:00:00Z"); err != nil {
		t.Fatalf("UpdateProviderKeyTokens: %v", err)
	}

	if got := inMemory.Providers[schemas.CodeBuddyCN].Keys[0].OAuthKeyConfig; got.AccessToken.GetValue() != "access-2" || got.RefreshToken.GetValue() != "refresh-2" {
		t.Fatalf("in-memory key still carries %q/%q, want access-2/refresh-2", got.AccessToken.GetValue(), got.RefreshToken.GetValue())
	}
	store.awaitWrites(t, 1)
	if got := store.storedKey(t, "key-1").OAuthKeyConfig; got == nil || got.RefreshToken.GetValue() != "refresh-2" {
		t.Fatalf("the store must receive the rotation, got %+v", got)
	}
	// A refresh must not touch the runtime shape: Bifrost.UpdateProvider swaps the provider
	// instance wholesale, so the same pointer is the observable proof that no rebuild happened.
	if after := client.GetProviderByKey(schemas.CodeBuddyCN); after != before {
		t.Fatal("the provider was rebuilt; a token write must not restart the worker queue")
	}
	// Everything else on the struct is preserved: a rotation only rewrites the two tokens and
	// the expiry, never the grant, endpoint, or operator-set fields.
	if got := storedProviderKey(t, inMemory, "key-1"); got.Name != "cb" || got.Weight != 1 {
		t.Fatalf("the rotation clobbered unrelated key fields: %+v", got)
	}
}

// attachBifrostClientReturning is attachBifrostClient for tests that need to observe the runtime
// provider list, which is the only place a provider rebuild becomes visible.
func attachBifrostClientReturning(t *testing.T, store *lib.Config) *bifrost.Bifrost {
	t.Helper()
	client, err := bifrost.Init(context.Background(), schemas.BifrostConfig{
		Account: lib.NewBaseAccount(store),
		Logger:  bifrost.NewDefaultLogger(schemas.LogLevelError),
	})
	if err != nil {
		t.Fatalf("failed to init bifrost client: %v", err)
	}
	t.Cleanup(client.Shutdown)
	store.SetBifrostClient(client)
	return client
}

// TestUpdateProviderKeyTokensIdempotentAndAccessOnly covers the two guards on the token write that
// are not about the provider rebuild.
func TestUpdateProviderKeyTokensIdempotentAndAccessOnly(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	newConfig := func() (*lib.Config, *tokenWriteStore) {
		store := newTokenWriteStore(schemas.Key{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()})
		config := &lib.Config{
			ConfigStore: store,
			Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
				schemas.CodeBuddyCN: {Keys: []schemas.Key{{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()}}},
			},
		}
		return config, store
	}

	t.Run("an identical delivery is not written twice", func(t *testing.T) {
		config, store := newConfig()
		for range 2 {
			if err := config.UpdateProviderKeyTokens(context.Background(), schemas.CodeBuddyCN, "key-1", "access-stored", "refresh-stored", "2026-10-22T12:00:00Z"); err != nil {
				t.Fatalf("UpdateProviderKeyTokens: %v", err)
			}
		}
		// No goroutine is started for a delivery that changes nothing, so this is a real
		// assertion about absence rather than a wait.
		if n := store.writeCount(); n != 0 {
			t.Fatalf("store writes = %d, want 0 for a delivery that changes nothing", n)
		}
	})

	t.Run("a new access token is written even when the refresh token did not rotate", func(t *testing.T) {
		// The upstream may answer a refresh with a fresh access token and no rotated refresh
		// token. Skipping that write would leave the stored access token stale and force the next
		// request to mint again.
		config, store := newConfig()
		if err := config.UpdateProviderKeyTokens(context.Background(), schemas.CodeBuddyCN, "key-1", "access-2", "refresh-stored", "2026-10-22T13:00:00Z"); err != nil {
			t.Fatalf("UpdateProviderKeyTokens: %v", err)
		}
		store.awaitWrites(t, 1)
		if got := storedProviderKey(t, config, "key-1").OAuthKeyConfig; got.AccessToken.GetValue() != "access-2" || got.ExpiresAt != "2026-10-22T13:00:00Z" {
			t.Fatalf("access token/expiry not persisted: %+v", got)
		}
		if got := storedProviderKey(t, config, "key-1").OAuthKeyConfig.RefreshToken.GetValue(); got != "refresh-stored" {
			t.Fatalf("refresh token = %q, want the unrotated one", got)
		}
	})

	t.Run("an unknown key is reported, not silently ignored", func(t *testing.T) {
		config, _ := newConfig()
		err := config.UpdateProviderKeyTokens(context.Background(), schemas.CodeBuddyCN, "key-missing", "a", "r", "")
		if !errors.Is(err, lib.ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
}

// TestInstallCodeBuddyCredentialSinkPersistsARotation pins the wiring end to end: a real provider
// refresh invokes the sink this function installs, and the rotation lands in the config store.
// Driving persistRotatedCredential directly would leave the installation itself untested.
func TestInstallCodeBuddyCredentialSinkPersistsARotation(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})
	t.Cleanup(func() { codebuddycn.SetCredentialSink(nil) })

	var refreshCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/plugin/auth/token/refresh":
			refreshCalls++
			_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"access-2","refreshToken":"refresh-2","expiresIn":3600}}`))
		default:
			_, _ = w.Write([]byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`))
		}
	}))
	defer server.Close()

	store := newTokenWriteStore(schemas.Key{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()})
	config := &lib.Config{
		ConfigStore: store,
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {Keys: []schemas.Key{{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()}}},
		},
	}
	InstallCodeBuddyCredentialSink(config)

	provider, err := codebuddycn.NewCodeBuddyCNProvider(&schemas.ProviderConfig{
		NetworkConfig: schemas.NetworkConfig{
			BaseURL:                        server.URL,
			AllowPrivateNetwork:            true,
			DefaultRequestTimeoutInSeconds: 10,
		},
	}, &mockLogger{})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	key := storedProviderKey(t, config, "key-1")
	key.OAuthKeyConfig.TokenURL = *schemas.NewSecretVar(server.URL + "/v2/plugin/auth/token/refresh")
	key.OAuthKeyConfig.RefreshToken = schemas.NewSecretVar("refresh-1")

	_, bErr := provider.ChatCompletion(schemas.NewBifrostContext(context.Background(), schemas.NoDeadline), key, &schemas.BifrostChatRequest{
		Provider: schemas.CodeBuddyCN,
		Model:    "m",
		Input: []schemas.ChatMessage{{
			Role:    schemas.ChatMessageRoleUser,
			Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr("hi")},
		}},
	})
	if bErr != nil {
		t.Fatalf("ChatCompletion: %v", bErr)
	}
	if refreshCalls != 1 {
		t.Fatalf("refresh calls = %d, want 1", refreshCalls)
	}

	if got := storedProviderKey(t, config, "key-1").OAuthKeyConfig; got.RefreshToken.GetValue() != "refresh-2" {
		t.Fatalf("refresh token = %q, want refresh-2", got.RefreshToken.GetValue())
	}
	store.awaitWrites(t, 1)
	if got := store.storedKey(t, "key-1").OAuthKeyConfig; got.AccessToken.GetValue() != "access-2" {
		t.Fatalf("store did not receive the rotation: %+v", got)
	}
}

// TestRotatedTokenPersistDoesNotBlockTheRequestPath pins the reason UpdateProviderKeyTokens splits
// the in-memory apply from the store write. The provider invokes the sink while tokencache holds
// that credential's slot mutex, so a store write awaited there would stall every concurrent request
// for that key.
//
// What it asserts is narrowly the mint's latency: the call returns in a fraction of the time a slow
// store takes, and the write is demonstrably still in flight when it does. It deliberately does not
// assert that the new token is readable at return, because reading it needs c.Mu and the background
// write holds that lock while it waits on the store — the token is in memory, but not observable
// without waiting out the write. The memory assertion below therefore runs after the bounded write
// finishes.
//
// The store stub sleeps far longer than the assertion window, so a synchronous write cannot pass by
// being fast.
func TestRotatedTokenPersistDoesNotBlockTheRequestPath(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	store := newTokenWriteStore(schemas.Key{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()})
	store.persistDelay = 1500 * time.Millisecond
	config := &lib.Config{
		ConfigStore: store,
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {Keys: []schemas.Key{{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()}}},
		},
	}

	start := time.Now()
	if err := config.UpdateProviderKeyTokens(context.Background(), schemas.CodeBuddyCN, "key-1", "access-2", "refresh-2", "2026-10-22T13:00:00Z"); err != nil {
		t.Fatalf("UpdateProviderKeyTokens: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed > 250*time.Millisecond {
		t.Fatalf("UpdateProviderKeyTokens took %s against a store that sleeps 1.5s; the mint path must not await the write", elapsed)
	}
	// The write must still be in flight at this point — otherwise the assertion above proved
	// nothing about asynchrony.
	if n := store.writeCount(); n != 0 {
		t.Fatalf("test setup: the store write finished in %s; it was supposed to still be running", elapsed)
	}

	store.awaitWrites(t, 1)
	if got := storedProviderKey(t, config, "key-1").OAuthKeyConfig; got.AccessToken.GetValue() != "access-2" || got.RefreshToken.GetValue() != "refresh-2" {
		t.Fatalf("in-memory tokens = %q/%q, want access-2/refresh-2", got.AccessToken.GetValue(), got.RefreshToken.GetValue())
	}
}

// TestOperatorUpdateKeepsAConcurrentRotation pins the window between the handler's read and its
// write. The handler captures a key, merges outside the lock, then writes the whole key; a refresh
// that lands in between rotates the refresh token, and a naive write would restore the precursor —
// which upstream has already invalidated, killing the key until a re-login.
func TestOperatorUpdateKeepsAConcurrentRotation(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	stale := browserLoginConfig()
	config := &lib.Config{
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {Keys: []schemas.Key{{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()}}},
		},
	}
	// The operator path rebuilds the provider, so it needs a client; the rotation path must not.
	attachBifrostClient(t, config)

	// The rotation lands after the operator's read but before the operator's write.
	if err := config.UpdateProviderKeyTokens(context.Background(), schemas.CodeBuddyCN, "key-1", "access-2", "refresh-2", "2026-10-22T13:00:00Z"); err != nil {
		t.Fatalf("UpdateProviderKeyTokens: %v", err)
	}

	// The operator saves what it read: a key carrying the masks it was shown, plus a rename.
	operatorKey := schemas.Key{
		ID:             "key-1",
		Name:           "renamed",
		Weight:         1,
		OAuthKeyConfig: stale.Redacted(),
	}
	// The read-time block travels with the write, which is how the config layer knows these tokens
	// are an echo of what was read rather than a new login.
	if err := config.UpdateProviderKeyWithReadTokens(context.Background(), schemas.CodeBuddyCN, "key-1", operatorKey, stale); err != nil {
		t.Fatalf("UpdateProviderKeyWithReadTokens: %v", err)
	}

	got := storedProviderKey(t, config, "key-1").OAuthKeyConfig
	if got.RefreshToken.GetValue() != "refresh-2" {
		t.Fatalf("refresh token = %q, want the rotated refresh-2; the operator write restored the invalidated precursor", got.RefreshToken.GetValue())
	}
	if got.AccessToken.GetValue() != "access-2" {
		t.Fatalf("access token = %q, want the rotated access-2", got.AccessToken.GetValue())
	}
	// The operator's actual edit must still apply.
	if stored := storedProviderKey(t, config, "key-1"); stored.Name != "renamed" {
		t.Fatalf("the operator's rename was lost: %+v", stored)
	}
}

// TestOperatorUpdateWritesThroughAFreshLogin pins the legitimate action the single-writer rule must
// not break: replacing a dead credential by logging in again. The login flow obtains a new pair and
// saves it through this same endpoint; if the write discarded it, re-authenticating would be a
// silent no-op and a key with an invalidated refresh token could never be repaired.
//
// The new pair differs from what the request read, which is what distinguishes it from an echo.
func TestOperatorUpdateWritesThroughAFreshLogin(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	store := newTokenWriteStore(schemas.Key{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()})
	config := &lib.Config{
		ConfigStore: store,
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {Keys: []schemas.Key{{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()}}},
		},
	}
	attachBifrostClient(t, config)

	// The handler's read: the pair the client is shown.
	readTime, err := config.GetProviderKeyRaw(schemas.CodeBuddyCN, "key-1")
	if err != nil {
		t.Fatalf("GetProviderKeyRaw: %v", err)
	}

	fresh := browserLoginConfig()
	fresh.AccessToken = schemas.NewSecretVar("access-fresh")
	fresh.RefreshToken = schemas.NewSecretVar("refresh-fresh")
	fresh.ExpiresAt = "2026-10-23T09:00:00Z"
	if err := config.UpdateProviderKeyWithReadTokens(context.Background(), schemas.CodeBuddyCN, "key-1", schemas.Key{
		ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: fresh,
	}, readTime.OAuthKeyConfig); err != nil {
		t.Fatalf("UpdateProviderKeyWithReadTokens: %v", err)
	}

	inMemory := storedProviderKey(t, config, "key-1").OAuthKeyConfig
	if inMemory.AccessToken.GetValue() != "access-fresh" || inMemory.RefreshToken.GetValue() != "refresh-fresh" {
		t.Fatalf("memory tokens = %q/%q, want the fresh pair", inMemory.AccessToken.GetValue(), inMemory.RefreshToken.GetValue())
	}
	// The expiry must come from the new pair, not from the row it replaces: a fresh token with a
	// stale expiry would be re-minted on the very next request.
	if inMemory.ExpiresAt != "2026-10-23T09:00:00Z" {
		t.Fatalf("expiry = %q, want the fresh pair's expiry", inMemory.ExpiresAt)
	}

	store.awaitWrites(t, 1)
	storedCfg := store.storedKey(t, "key-1").OAuthKeyConfig
	if storedCfg.AccessToken.GetValue() != "access-fresh" || storedCfg.RefreshToken.GetValue() != "refresh-fresh" || storedCfg.ExpiresAt != "2026-10-23T09:00:00Z" {
		t.Fatalf("store tokens = %q/%q/%q, want the fresh pair", storedCfg.AccessToken.GetValue(), storedCfg.RefreshToken.GetValue(), storedCfg.ExpiresAt)
	}
}

// TestOperatorUpdateKeepsTheStoredRotationWhenThePairIsEchoed is the other half of the same rule: a
// save whose tokens still match what it read is an echo, so a rotation that landed in between must
// survive. This is the window the handler's read→merge→write opens, exercised with literal values
// rather than the mask.
func TestOperatorUpdateKeepsTheStoredRotationWhenThePairIsEchoed(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	store := newTokenWriteStore(schemas.Key{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()})
	config := &lib.Config{
		ConfigStore: store,
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {Keys: []schemas.Key{{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()}}},
		},
	}
	attachBifrostClient(t, config)

	readTime, err := config.GetProviderKeyRaw(schemas.CodeBuddyCN, "key-1")
	if err != nil {
		t.Fatalf("GetProviderKeyRaw: %v", err)
	}

	// A refresh rotates the credential after the read.
	if err := config.UpdateProviderKeyTokens(context.Background(), schemas.CodeBuddyCN, "key-1", "access-2", "refresh-2", "2026-10-22T13:00:00Z"); err != nil {
		t.Fatalf("UpdateProviderKeyTokens: %v", err)
	}
	store.awaitWrites(t, 1)

	// The client echoes the literal pair it read, plus a rename.
	echo := *readTime.OAuthKeyConfig
	if err := config.UpdateProviderKeyWithReadTokens(context.Background(), schemas.CodeBuddyCN, "key-1", schemas.Key{
		ID: "key-1", Name: "renamed", Weight: 1, OAuthKeyConfig: &echo,
	}, readTime.OAuthKeyConfig); err != nil {
		t.Fatalf("UpdateProviderKeyWithReadTokens: %v", err)
	}

	inMemory := storedProviderKey(t, config, "key-1")
	if got := inMemory.OAuthKeyConfig; got.AccessToken.GetValue() != "access-2" || got.RefreshToken.GetValue() != "refresh-2" || got.ExpiresAt != "2026-10-22T13:00:00Z" {
		t.Fatalf("memory reverted the rotation: %q/%q/%q", got.AccessToken.GetValue(), got.RefreshToken.GetValue(), got.ExpiresAt)
	}
	if inMemory.Name != "renamed" {
		t.Fatalf("the rename was lost: %q", inMemory.Name)
	}
	storedCfg := store.storedKey(t, "key-1")
	if got := storedCfg.OAuthKeyConfig; got.RefreshToken.GetValue() != "refresh-2" || got.AccessToken.GetValue() != "access-2" {
		t.Fatalf("store reverted the rotation: %q/%q", got.AccessToken.GetValue(), got.RefreshToken.GetValue())
	}
}

// TestOperatorUpdateAddsOAuthAfterAPastedValue covers the second legitimate action: converting a
// pasted-key row into a login. There is no stored block to preserve, so the incoming bundle must be
// written through — including its refresh token, or the key persists in a state that fails at first
// use while the API has already answered 200.
func TestOperatorUpdateAddsOAuthAfterAPastedValue(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	pasted := schemas.Key{ID: "key-1", Name: "cb", Weight: 1, Value: *schemas.NewSecretVar("sk-pasted")}
	store := newTokenWriteStore(pasted)
	config := &lib.Config{
		ConfigStore: store,
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {Keys: []schemas.Key{pasted}},
		},
	}
	attachBifrostClient(t, config)

	readTime, err := config.GetProviderKeyRaw(schemas.CodeBuddyCN, "key-1")
	if err != nil {
		t.Fatalf("GetProviderKeyRaw: %v", err)
	}
	if readTime.OAuthKeyConfig != nil {
		t.Fatal("test setup: the stored key should have no oauth block")
	}

	login := browserLoginConfig()
	login.AccessToken = schemas.NewSecretVar("access-login")
	login.RefreshToken = schemas.NewSecretVar("refresh-login")
	login.ExpiresAt = "2026-10-23T10:00:00Z"
	if err := config.UpdateProviderKeyWithReadTokens(context.Background(), schemas.CodeBuddyCN, "key-1", schemas.Key{
		ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: login,
	}, readTime.OAuthKeyConfig); err != nil {
		t.Fatalf("UpdateProviderKeyWithReadTokens: %v", err)
	}

	inMemory := storedProviderKey(t, config, "key-1")
	if inMemory.OAuthKeyConfig == nil {
		t.Fatal("the oauth block was dropped")
	}
	if inMemory.OAuthKeyConfig.RefreshToken.GetValue() != "refresh-login" {
		t.Fatalf("refresh token = %q, want the login's; a token-less bundle would fail at first use", inMemory.OAuthKeyConfig.RefreshToken.GetValue())
	}
	if inMemory.OAuthKeyConfig.AccessToken.GetValue() != "access-login" || inMemory.OAuthKeyConfig.ExpiresAt != "2026-10-23T10:00:00Z" {
		t.Fatalf("the login's access token/expiry were not persisted: %q/%q", inMemory.OAuthKeyConfig.AccessToken.GetValue(), inMemory.OAuthKeyConfig.ExpiresAt)
	}
	// It must be usable: the provider requires the browser_login grant to mint from.
	if err := inMemory.OAuthKeyConfig.Validate(); err != nil {
		t.Fatalf("the persisted bundle does not validate: %v", err)
	}

	store.awaitWrites(t, 1)
	if got := store.storedKey(t, "key-1").OAuthKeyConfig; got == nil || got.RefreshToken.GetValue() != "refresh-login" {
		t.Fatalf("the store did not receive the login: %+v", got)
	}
}

// TestRenameOnlySavePreservesTheRotatedTokens is Finding A's exact reproduction. The handler reads
// the key, decodes and merges outside the lock, and only then writes — so a body that omits
// oauth_key_config carries the whole block as it looked at read time. A rotation landing inside that
// window then gets reverted by the save, restoring the refresh token upstream already invalidated.
//
// The stages are driven explicitly to place the rotation inside the window deterministically; the
// handler's own decode and merge functions do the rest, so this is the real path, not a stand-in.
func TestRenameOnlySavePreservesTheRotatedTokens(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	store := newTokenWriteStore(schemas.Key{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()})
	config := &lib.Config{
		ConfigStore: store,
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {Keys: []schemas.Key{{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()}}},
		},
	}
	attachBifrostClient(t, config)
	h := &ProviderHandler{inMemoryStore: config, modelsManager: &mockModelsManager{}}

	// Stage 1: the handler's read, before any rotation.
	readTime, err := config.GetProviderKeyRaw(schemas.CodeBuddyCN, "key-1")
	if err != nil {
		t.Fatalf("GetProviderKeyRaw: %v", err)
	}

	// Stage 2: a refresh rotates the credential while the request is being processed.
	if err := config.UpdateProviderKeyTokens(context.Background(), schemas.CodeBuddyCN, "key-1", "access-2", "refresh-2", "2026-10-22T13:00:00Z"); err != nil {
		t.Fatalf("UpdateProviderKeyTokens: %v", err)
	}
	store.awaitWrites(t, 1)

	// Stage 3: the handler decodes and merges the rename-only body against its stale read.
	updateKey, err := decodeKeyUpdate([]byte(`{"name":"renamed"}`), *readTime)
	if err != nil {
		t.Fatalf("decodeKeyUpdate: %v", err)
	}
	merged, err := h.mergeUpdatedKey(*readTime, updateKey)
	if err != nil {
		t.Fatalf("mergeUpdatedKey: %v", err)
	}
	// The stale literal pair really is in the merged key — this is the shape that used to win.
	if merged.OAuthKeyConfig.RefreshToken.GetValue() != "refresh-stored" {
		t.Fatalf("test setup: the merge was expected to carry the stale literal, got %q", merged.OAuthKeyConfig.RefreshToken.GetValue())
	}

	// Stage 4: the handler's write, carrying the block it read.
	if err := config.UpdateProviderKeyWithReadTokens(context.Background(), schemas.CodeBuddyCN, "key-1", merged, readTime.OAuthKeyConfig); err != nil {
		t.Fatalf("UpdateProviderKeyWithReadTokens: %v", err)
	}

	inMemory := storedProviderKey(t, config, "key-1")
	if inMemory.OAuthKeyConfig.RefreshToken.GetValue() != "refresh-2" || inMemory.OAuthKeyConfig.AccessToken.GetValue() != "access-2" {
		t.Fatalf("memory reverted the rotation: %q/%q", inMemory.OAuthKeyConfig.AccessToken.GetValue(), inMemory.OAuthKeyConfig.RefreshToken.GetValue())
	}
	if inMemory.Name != "renamed" {
		t.Fatalf("the rename was lost: %q", inMemory.Name)
	}
	storedCfg := store.storedKey(t, "key-1")
	if storedCfg.OAuthKeyConfig.RefreshToken.GetValue() != "refresh-2" || storedCfg.OAuthKeyConfig.AccessToken.GetValue() != "access-2" {
		t.Fatalf("store reverted the rotation: %q/%q", storedCfg.OAuthKeyConfig.AccessToken.GetValue(), storedCfg.OAuthKeyConfig.RefreshToken.GetValue())
	}
	if storedCfg.Name != "renamed" {
		t.Fatalf("store lost the rename: %q", storedCfg.Name)
	}
}

// TestEchoIsRecognisedWhenTheReadAccessTokenIsNil is Finding 1's reproduction. A browser_login key
// is created with a refresh token and no access token, so nil is the canonical post-login state for
// that field. A rename-only save omits oauth_key_config, decodeKeyUpdate copies the read block, and a
// comparison that treats nil-vs-nil as divergence declares the pair new and persists the superseded
// refresh token — Finding A's failure in the one shape none of the other echo tests use.
func TestEchoIsRecognisedWhenTheReadAccessTokenIsNil(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	freshLogin := func() *schemas.OAuthKeyConfig {
		return &schemas.OAuthKeyConfig{
			GrantType:    schemas.OAuthGrantBrowserLogin,
			TokenURL:     *schemas.NewSecretVar("https://copilot.tencent.com/v2/plugin/auth/token/refresh"),
			RefreshToken: schemas.NewSecretVar("refresh-1"),
		}
	}
	store := newTokenWriteStore(schemas.Key{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: freshLogin()})
	config := &lib.Config{
		ConfigStore: store,
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {Keys: []schemas.Key{{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: freshLogin()}}},
		},
	}
	attachBifrostClient(t, config)
	h := &ProviderHandler{inMemoryStore: config, modelsManager: &mockModelsManager{}}

	readTime, err := config.GetProviderKeyRaw(schemas.CodeBuddyCN, "key-1")
	if err != nil {
		t.Fatalf("GetProviderKeyRaw: %v", err)
	}
	if readTime.OAuthKeyConfig.AccessToken != nil {
		t.Fatal("test setup: a freshly created browser_login key has no access token")
	}

	// The first refresh rotates the durable credential; it also fills in an access token.
	if err := config.UpdateProviderKeyTokens(context.Background(), schemas.CodeBuddyCN, "key-1", "access-2", "refresh-2", "2026-10-22T13:00:00Z"); err != nil {
		t.Fatalf("UpdateProviderKeyTokens: %v", err)
	}
	store.awaitWrites(t, 1)

	updateKey, err := decodeKeyUpdate([]byte(`{"name":"renamed"}`), *readTime)
	if err != nil {
		t.Fatalf("decodeKeyUpdate: %v", err)
	}
	merged, err := h.mergeUpdatedKey(*readTime, updateKey)
	if err != nil {
		t.Fatalf("mergeUpdatedKey: %v", err)
	}
	if err := config.UpdateProviderKeyWithReadTokens(context.Background(), schemas.CodeBuddyCN, "key-1", merged, readTime.OAuthKeyConfig); err != nil {
		t.Fatalf("UpdateProviderKeyWithReadTokens: %v", err)
	}

	inMemory := storedProviderKey(t, config, "key-1").OAuthKeyConfig
	if inMemory.RefreshToken.GetValue() != "refresh-2" {
		t.Fatalf("refresh token = %q, want the rotated refresh-2; a nil read access token was mistaken for a new pair", inMemory.RefreshToken.GetValue())
	}
	if inMemory.ExpiresAt != "2026-10-22T13:00:00Z" {
		t.Fatalf("expiry = %q, want the rotated expiry", inMemory.ExpiresAt)
	}
	store.awaitWrites(t, 2)
	if got := store.storedKey(t, "key-1").OAuthKeyConfig.RefreshToken.GetValue(); got != "refresh-2" {
		t.Fatalf("store refresh token = %q, want refresh-2", got)
	}
}

// TestMaskedAccessTokenWithANewRefreshTokenResolvesTheMask is Finding 2's reproduction. A client that
// echoes the masked access token but supplies a new refresh token must not persist the asterisks: a
// masked access token is merely unusable, but a masked refresh token would be unrecoverable.
func TestMaskedAccessTokenWithANewRefreshTokenResolvesTheMask(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	store := newTokenWriteStore(schemas.Key{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()})
	config := &lib.Config{
		ConfigStore: store,
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {Keys: []schemas.Key{{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()}}},
		},
	}
	attachBifrostClient(t, config)

	readTime, err := config.GetProviderKeyRaw(schemas.CodeBuddyCN, "key-1")
	if err != nil {
		t.Fatalf("GetProviderKeyRaw: %v", err)
	}

	mixed := *readTime.OAuthKeyConfig
	mixed.AccessToken = readTime.OAuthKeyConfig.AccessToken.Redacted()
	mixed.RefreshToken = schemas.NewSecretVar("refresh-new")
	mixed.ExpiresAt = "2026-10-22T15:00:00Z"
	if err := config.UpdateProviderKeyWithReadTokens(context.Background(), schemas.CodeBuddyCN, "key-1", schemas.Key{
		ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: &mixed,
	}, readTime.OAuthKeyConfig); err != nil {
		t.Fatalf("UpdateProviderKeyWithReadTokens: %v", err)
	}

	inMemory := storedProviderKey(t, config, "key-1").OAuthKeyConfig
	if inMemory.AccessToken.GetValue() != "access-stored" {
		t.Fatalf("access token = %q, want the stored credential, never the mask", inMemory.AccessToken.GetValue())
	}
	if inMemory.AccessToken.IsMaskedPlaceholder() {
		t.Fatalf("a masked placeholder was persisted as the access token: %q", inMemory.AccessToken.GetValue())
	}
	if inMemory.RefreshToken.GetValue() != "refresh-new" {
		t.Fatalf("refresh token = %q, want the new literal", inMemory.RefreshToken.GetValue())
	}
	// One field came from storage, so the stored expiry is the consistent choice.
	if inMemory.ExpiresAt != "2026-10-22T12:00:00Z" {
		t.Fatalf("expiry = %q, want the stored expiry", inMemory.ExpiresAt)
	}

	store.awaitWrites(t, 1)
	if got := store.storedKey(t, "key-1").OAuthKeyConfig; got.AccessToken.IsMaskedPlaceholder() || got.AccessToken.GetValue() != "access-stored" {
		t.Fatalf("store access token = %q, want the stored credential", got.AccessToken.GetValue())
	}
}

// TestMaskedTokensWithNothingStoredAreRefused pins the stored == nil half of the mask rule. There is
// no value to resolve a mask to, and silently dropping it would persist a bundle that cannot mint —
// so the save is refused instead.
func TestMaskedTokensWithNothingStoredAreRefused(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	pasted := schemas.Key{ID: "key-1", Name: "cb", Weight: 1, Value: *schemas.NewSecretVar("sk-pasted")}
	config := &lib.Config{
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {Keys: []schemas.Key{pasted}},
		},
	}
	attachBifrostClient(t, config)

	masked := browserLoginConfig()
	masked.AccessToken = masked.AccessToken.Redacted()
	masked.RefreshToken = masked.RefreshToken.Redacted()
	err := config.UpdateProviderKeyWithReadTokens(context.Background(), schemas.CodeBuddyCN, "key-1", schemas.Key{
		ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: masked,
	}, nil)
	if !errors.Is(err, lib.ErrInvalidKeyCredential) {
		t.Fatalf("err = %v, want ErrInvalidKeyCredential", err)
	}
	if got := storedProviderKey(t, config, "key-1").OAuthKeyConfig; got != nil {
		t.Fatalf("the refused save still mutated the key: %+v", got)
	}
}

// TestConcurrentClearThenEchoedSaveDoesNotPanic reproduces the panic window the echo rule opens:
// request A reads the key, request B clears the OAuth block, then A writes back the pair it read.
// With `stored` nil and a non-nil read snapshot, an echo branch that copied "the stored values" would
// dereference nil.
//
// The save completes and the resolved block is written: a write that reaches the store last wins, so
// A's echoed block replaces the clear. The result is a structurally valid browser_login key (the
// echoed pair, no pasted value) rather than a panic or a half-filled block. That the clear loses is a
// trade-off of the prescribed rule and is recorded in the report; the invariant under test here is
// that there is no nil dereference in the window.
func TestConcurrentClearThenEchoedSaveDoesNotPanic(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	store := newTokenWriteStore(schemas.Key{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()})
	config := &lib.Config{
		ConfigStore: store,
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {Keys: []schemas.Key{{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()}}},
		},
	}
	attachBifrostClient(t, config)

	// Request A's read.
	readTime, err := config.GetProviderKeyRaw(schemas.CodeBuddyCN, "key-1")
	if err != nil {
		t.Fatalf("GetProviderKeyRaw: %v", err)
	}

	// Request B clears the OAuth block.
	if err := config.UpdateProviderKey(context.Background(), schemas.CodeBuddyCN, "key-1", schemas.Key{
		ID: "key-1", Name: "cb", Weight: 1, Value: *schemas.NewSecretVar("sk-pasted"),
	}); err != nil {
		t.Fatalf("clearing update: %v", err)
	}
	if got := storedProviderKey(t, config, "key-1").OAuthKeyConfig; got != nil {
		t.Fatalf("test setup: the block should be cleared, got %+v", got)
	}

	// Request A writes back the pair it read, unchanged.
	echo := *readTime.OAuthKeyConfig
	var err2 error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("the echoed save panicked with the block cleared: %v", r)
			}
		}()
		err2 = config.UpdateProviderKeyWithReadTokens(context.Background(), schemas.CodeBuddyCN, "key-1", schemas.Key{
			ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: &echo,
		}, readTime.OAuthKeyConfig)
	}()
	if err2 != nil {
		t.Fatalf("UpdateProviderKeyWithReadTokens: %v", err2)
	}

	// The echoed block is written, and it is a complete one — not a half-filled block and not a key
	// carrying both auth modes.
	stored := storedProviderKey(t, config, "key-1")
	if stored.OAuthKeyConfig == nil {
		t.Fatal("the echoed save left no oauth block behind")
	}
	if got := stored.OAuthKeyConfig.RefreshToken.GetValue(); got != "refresh-stored" {
		t.Fatalf("refresh token = %q, want the echoed value", got)
	}
	if got := stored.Value.GetValue(); got != "" {
		t.Fatalf("pasted value = %q, want empty so the key has exactly one auth mode", got)
	}
	if err := stored.OAuthKeyConfig.Validate(); err != nil {
		t.Fatalf("the persisted block is not usable: %v", err)
	}
}

// TestConcurrentClearThenEchoedSaveKeepsItsOwnNewTokens pins the other side of the same window: the
// clear is in the way, but the save carries a genuinely new pair, so it must still be written.
func TestConcurrentClearThenEchoedSaveKeepsItsOwnNewTokens(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	store := newTokenWriteStore(schemas.Key{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()})
	config := &lib.Config{
		ConfigStore: store,
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {Keys: []schemas.Key{{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()}}},
		},
	}
	attachBifrostClient(t, config)

	readTime, err := config.GetProviderKeyRaw(schemas.CodeBuddyCN, "key-1")
	if err != nil {
		t.Fatalf("GetProviderKeyRaw: %v", err)
	}
	if err := config.UpdateProviderKey(context.Background(), schemas.CodeBuddyCN, "key-1", schemas.Key{
		ID: "key-1", Name: "cb", Weight: 1, Value: *schemas.NewSecretVar("sk-pasted"),
	}); err != nil {
		t.Fatalf("clearing update: %v", err)
	}

	login := browserLoginConfig()
	login.AccessToken = schemas.NewSecretVar("access-login")
	login.RefreshToken = schemas.NewSecretVar("refresh-login")
	var err2 error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("the save panicked with the block cleared: %v", r)
			}
		}()
		err2 = config.UpdateProviderKeyWithReadTokens(context.Background(), schemas.CodeBuddyCN, "key-1", schemas.Key{
			ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: login,
		}, readTime.OAuthKeyConfig)
	}()
	if err2 != nil {
		t.Fatalf("UpdateProviderKeyWithReadTokens: %v", err2)
	}

	got := storedProviderKey(t, config, "key-1").OAuthKeyConfig
	if got == nil || got.RefreshToken.GetValue() != "refresh-login" {
		t.Fatalf("a fresh login was dropped because the block had been cleared: %+v", got)
	}
}

// TestSlowRotationPersistDoesNotClobberALaterEdit pins the observable outcome of Finding B: a slow
// rotation write overlapping an operator rename must leave the durable row carrying both changes.
//
// It does not force a particular interleaving. With the fix both writers serialize on c.Mu and each
// builds its row from the state the previous one left, so the rename is either already in memory
// when the rotation builds its row or is written after it; either way the last write includes both.
// The failure it catches is the structural one: if the rotation wrote a row captured when it was
// scheduled, the rename would be reverted in the store (durable row "cb", memory "renamed") — which
// is exactly what the mutation check in the report reproduces.
//
// Two distinct regressions fail it, which is why the comment names the mechanism rather than a race:
// a rotation writing a row captured when it was scheduled (the snapshot variant), and a rotation
// writing without holding c.Mu at all (the round-1 variant, where the two store calls interleave
// freely and the older row can land last).
func TestSlowRotationPersistDoesNotClobberALaterEdit(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	store := newTokenWriteStore(schemas.Key{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()})
	// The rotation's write carries the pre-rename row, so it is identified by the name it writes:
	// 400ms. The operator's write carries "renamed" and is immediate. Keying on content rather than
	// arrival order means the two can never swap.
	store.delayFor = func(key schemas.Key) time.Duration {
		if key.Name == "renamed" {
			return 0
		}
		return 400 * time.Millisecond
	}
	config := &lib.Config{
		ConfigStore: store,
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {Keys: []schemas.Key{{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()}}},
		},
	}
	attachBifrostClient(t, config)

	if err := config.UpdateProviderKeyTokens(context.Background(), schemas.CodeBuddyCN, "key-1", "access-2", "refresh-2", "2026-10-22T13:00:00Z"); err != nil {
		t.Fatalf("UpdateProviderKeyTokens: %v", err)
	}

	// The rename lands while the rotation's row write is still sleeping in the store.
	h := &ProviderHandler{inMemoryStore: config, modelsManager: &mockModelsManager{}}
	ctx := newTestRequestCtx(`{"name":"renamed"}`)
	ctx.SetUserValue("provider", string(schemas.CodeBuddyCN))
	ctx.SetUserValue("key_id", "key-1")
	h.updateProviderKey(ctx)
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("status got %d, want 200; body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	// Both writes must finish before the assertion, or the rotation could still be sleeping.
	store.awaitWrites(t, 2)

	finalStore := store.storedKey(t, "key-1")
	if finalStore.Name != "renamed" {
		t.Fatalf("store name = %q, want renamed; the rotation's write clobbered the edit", finalStore.Name)
	}
	if finalStore.OAuthKeyConfig.RefreshToken.GetValue() != "refresh-2" {
		t.Fatalf("store refresh token = %q, want refresh-2", finalStore.OAuthKeyConfig.RefreshToken.GetValue())
	}
	inMemory := storedProviderKey(t, config, "key-1")
	if inMemory.Name != finalStore.Name {
		t.Fatalf("memory name %q disagrees with store name %q", inMemory.Name, finalStore.Name)
	}
	if inMemory.OAuthKeyConfig.RefreshToken.GetValue() != finalStore.OAuthKeyConfig.RefreshToken.GetValue() {
		t.Fatalf("memory refresh %q disagrees with store %q", inMemory.OAuthKeyConfig.RefreshToken.GetValue(), finalStore.OAuthKeyConfig.RefreshToken.GetValue())
	}
}

// TestSlowRotationPersistDoesNotClobberALaterTokenEdit is the same race for the credential itself:
// a second rotation can land while the first one's write is queued, and the store must end up with
// the newer pair. (An operator can supply tokens by hand — a re-login — but this case is about the
// two writers that both mint, so it uses rotations.)
func TestSlowRotationPersistDoesNotClobberALaterTokenEdit(t *testing.T) {
	SetLogger(&mockLogger{})
	lib.SetLogger(&mockLogger{})

	store := newTokenWriteStore(schemas.Key{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()})
	// Staggered so the OLDER write lands last if the row were captured when the rotation was
	// applied: the refresh-2 write sleeps 300ms, the refresh-3 write is immediate. With a
	// captured-at-apply snapshot that ordering ends on access-2/refresh-2 — the superseded pair,
	// whose refresh token upstream has already invalidated. Keyed on the token each write carries,
	// so the assignment cannot invert.
	store.delayFor = func(key schemas.Key) time.Duration {
		if key.OAuthKeyConfig != nil && key.OAuthKeyConfig.RefreshToken.GetValue() == "refresh-2" {
			return 300 * time.Millisecond
		}
		return 0
	}
	config := &lib.Config{
		ConfigStore: store,
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.CodeBuddyCN: {Keys: []schemas.Key{{ID: "key-1", Name: "cb", Weight: 1, OAuthKeyConfig: browserLoginConfig()}}},
		},
	}

	if err := config.UpdateProviderKeyTokens(context.Background(), schemas.CodeBuddyCN, "key-1", "access-2", "refresh-2", "2026-10-22T13:00:00Z"); err != nil {
		t.Fatalf("first rotation: %v", err)
	}
	if err := config.UpdateProviderKeyTokens(context.Background(), schemas.CodeBuddyCN, "key-1", "access-3", "refresh-3", "2026-10-22T14:00:00Z"); err != nil {
		t.Fatalf("second rotation: %v", err)
	}

	// Wait for both writes to land. Asserting on an intermediate state would pass spuriously:
	// the newer write lands first here, so catching it early says nothing about the older one
	// that is still sleeping.
	store.awaitWrites(t, 2)

	final := store.storedKey(t, "key-1").OAuthKeyConfig
	if final.RefreshToken.GetValue() != "refresh-3" || final.AccessToken.GetValue() != "access-3" {
		t.Fatalf("store tokens = %q/%q, want the newer access-3/refresh-3", final.AccessToken.GetValue(), final.RefreshToken.GetValue())
	}
	// Memory must agree with the store; a disagreement is what a restart would surface.
	inMemory := storedProviderKey(t, config, "key-1").OAuthKeyConfig
	if inMemory.RefreshToken.GetValue() != final.RefreshToken.GetValue() || inMemory.AccessToken.GetValue() != final.AccessToken.GetValue() {
		t.Fatalf("memory %q/%q disagrees with store %q/%q", inMemory.AccessToken.GetValue(), inMemory.RefreshToken.GetValue(), final.AccessToken.GetValue(), final.RefreshToken.GetValue())
	}
}
