package codebuddycn

import (
	"strings"

	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	schemas "github.com/maximhq/bifrost/core/schemas"
)

// codeBuddyCatalog is the pinned model catalog this provider lists and validates nothing
// against. The gateway serves no model list to an unauthenticated caller and its /v2/models
// route answers 404, so the ids are hand-maintained here: refresh them with
// GET /v2/plugin/models against a live credential.
//
// A model id missing from this list is not rejected anywhere; the catalog exists to populate
// the UI's model picker, and chat requests pass whatever id the caller sends to the gateway.
var codeBuddyCatalog = []string{
	"hunyuan-chat",
	"deepseek-v3",
	"glm-5.2",
}

// catalogListModelsResponse renders the pinned catalog in Bifrost's list shape, filtered
// through the standard pipeline so a key's model allowlist, blacklist and aliases apply
// exactly as they do to a live listing.
func catalogListModelsResponse(allowedModels schemas.WhiteList, blacklistedModels schemas.BlackList, aliases schemas.KeyAliases, unfiltered bool) *schemas.BifrostListModelsResponse {
	response := &schemas.BifrostListModelsResponse{
		Data: make([]schemas.Model, 0, len(codeBuddyCatalog)),
	}

	pipeline := &providerUtils.ListModelsPipeline{
		AllowedModels:     allowedModels,
		BlacklistedModels: blacklistedModels,
		Aliases:           aliases,
		Unfiltered:        unfiltered,
		ProviderKey:       schemas.CodeBuddyCN,
		MatchFns:          providerUtils.DefaultMatchFns(),
	}
	if pipeline.ShouldEarlyExit() {
		return response
	}

	included := make(map[string]bool, len(codeBuddyCatalog))
	for _, modelID := range codeBuddyCatalog {
		for _, result := range pipeline.FilterModel(modelID) {
			entry := schemas.Model{
				ID:   string(schemas.CodeBuddyCN) + "/" + result.ResolvedID,
				Name: schemas.Ptr(providerUtils.ToDisplayName(result.ResolvedID)),
			}
			if result.AliasValue != "" {
				entry.Alias = schemas.Ptr(result.AliasValue)
			}
			response.Data = append(response.Data, entry)
			included[strings.ToLower(result.ResolvedID)] = true
		}
	}

	response.Data = append(response.Data, pipeline.BackfillModels(included)...)
	return response
}
