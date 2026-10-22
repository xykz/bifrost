package codebuddycn

import (
	"strings"

	schemas "github.com/maximhq/bifrost/core/schemas"
)

// Editor identity. CodeBuddy validates that a caller looks like its own CLI and refuses
// requests that look like generic API clients, so these four travel on every inference call.
//
// The values come from the official CLI's constants module; X-Product is the product's
// deploymentType. They are not covered by a published contract, so refresh them from the CLI
// bundle when Tencent ships a release that changes them.
const (
	editorProduct = "SaaS"
	editorIDEType = "CLI"
	editorIDEName = "CodeBuddy"
	editorVersion = "0.0.0"

	// apiKeyHeader carries a pasted API key.
	apiKeyHeader = "X-API-Key"
)

// Credential header names and the scheme prefix, shared by authHeaderFor and its callers.
const (
	authorizationHeader = "Authorization"
	bearerPrefix        = "Bearer "
)

// editorHeaderValues is the identity set, as name/value pairs in a fixed order so the map built
// from it is the only allocation. X-Product is the product's deploymentType in the official CLI.
var editorHeaderValues = [...]struct{ name, value string }{
	{"X-Product", editorProduct},
	{"X-IDE-Type", editorIDEType},
	{"X-IDE-Name", editorIDEName},
	{"X-IDE-Version", editorVersion},
}

// editorHeaders returns the identity headers CodeBuddy requires. Requests without them are
// treated as generic API clients and refused before inference.
//
// The map is returned as SecretVar because that is the shape the shared OpenAI helpers accept
// for extraHeaders; nothing here is secret. SecretVars are built as literals rather than with
// NewSecretVar, which resolves references and so costs a JSON probe per header.
func editorHeaders() map[string]schemas.SecretVar {
	headers := make(map[string]schemas.SecretVar, len(editorHeaderValues))
	for _, header := range editorHeaderValues {
		headers[header.name] = schemas.SecretVar{Val: header.value, SecretType: schemas.SecretTypePlainText}
	}
	return headers
}

// authHeaderFor chooses the credential header: a pasted key travels in X-API-Key, an OAuth
// access token in Authorization. Verified against the live gateway: a bogus X-API-Key reaches
// credential validation, while a bogus bearer is rejected by APISIX with an HTML 401.
//
// key is the credential as configured, which is what distinguishes the two modes; accessToken
// is what the OAuth path minted, and is ignored for a key that carries a pasted value. Both
// empty yields no credential header at all, so a keyless custom provider still works.
//
// Whitespace-only is treated as empty here and in resolveKey: the two must agree, or a blank
// value would suppress the mint and then send no credential at all. Trimming matches
// bifrost.go's own key validation.
func authHeaderFor(key schemas.Key, accessToken string) map[string]string {
	if value := strings.TrimSpace(key.Value.GetValue()); value != "" {
		return map[string]string{apiKeyHeader: value}
	}
	if accessToken != "" {
		return map[string]string{authorizationHeader: bearerPrefix + accessToken}
	}
	return map[string]string{}
}
