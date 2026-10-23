# CodeBuddy CN provider — design

Date: 2026-10-22
Status: awaiting approval

## Intent and why

Bifrost should support Tencent CodeBuddy (China, `copilot.tencent.com`) as a first-class
provider. Bifrost today has no way to reach it, so users of CodeBuddy's subscription cannot
route their traffic through the gateway.

The reference implementation is the official CLI, `@tencent-ai/codebuddy-code`. Its auth
and inference behaviour was read out of `dist/codebuddy.js` (v2.172.1) and verified against
the live endpoints. A third-party implementation exists in another project
(`/tmp/durindoor`, `open-sse/providers/registry/codebuddy-cn.js`) and is explicitly **not**
the reference: it has bugs and diverges from the official client. Where the two disagree,
the official CLI wins.

## What CodeBuddy actually is

An OpenAI-compatible chat-completions gateway at `https://copilot.tencent.com/v2`, OpenAI
shape in and out, fronted by an APISIX gateway. Four behaviours make it unlike the other
OpenAI-compatible providers:

1. **Credentials expire.** Access tokens are short-lived (minutes to hours) and are renewed
   with a long-lived refresh token. There is no long-lived API key unless the user creates
   one.
2. **Interactive login is the normal path.** A device/browser handshake, not a
   client-credentials grant.
3. **Streaming is the CLI's normal mode, but not the only one.** The official CLI builds its
   body with `stream: !!flag` and adds `stream_options: {include_usage: true}` only when
   streaming. So both shapes exist upstream, and Bifrost need not force or aggregate
   anything. (A third-party implementation claims non-streaming is rejected with code
   `11101`; that code does not exist in the official bundle — every `11101` hit there is
   Unicode table data. The claim is treated as unverified and unused.)
4. **Editor-identity headers are required.** Requests without `X-Product`, `X-IDE-Type`,
   `X-IDE-Name` are treated as generic API clients and refused.

Verified request/response shapes:

| Step | Call | Result |
|---|---|---|
| Login start | `POST {endpoint}/v2/plugin/auth/state?platform=CLI` | `{state, authUrl}`; `authUrl` = `{endpoint}/login?platform=CLI&state=<uuid>` |
| Login poll | `GET {endpoint}/v2/plugin/auth/token?state=<uuid>` | `code:11217` = pending; `code:0` + `{accessToken, refreshToken, expiresIn, tokenType}` = done |
| Refresh | `POST {endpoint}/v2/plugin/auth/token/refresh` | refresh token in the `X-Refresh-Token` **header**; 401 / `code 12153` = dead refresh token |
| Inference | `POST {endpoint}/v2/chat/completions` | `Authorization: Bearer <accessToken>`, editor headers, `stream` as the caller asked |

Notes recorded during recon, so nobody has to rediscover them:

- `POST {endpoint}/v2/auth/state` (no `/plugin`) returns 404. The `/plugin` prefix is
  load-bearing; it comes from the product config's `authentication.attributes.prefixPath`.
- `GET {endpoint}/v3/config` returns `models: null` unless authenticated, so the model list
  cannot be discovered unauthenticated. The provider ships a static catalog.
- Pending and failure signals are HTTP-200 bodies carrying a non-zero `code`, not HTTP
  status codes. Only the refresh endpoint answers a real 401.
- The official CLI's `expiresIn` is absent in some responses; expiry must tolerate a
  missing value.

### Auth header placement, verified

Probed against the live gateway with a bogus credential, which distinguishes the rejection
layers:

| Headers sent | Response | Reading |
|---|---|---|
| `X-API-Key: bogus` | `401 {"message":"invalid_format"}` | reached credential validation — the API-key path |
| `Authorization: Bearer bogus` | APISIX HTML 401 | rejected by the gateway before credential validation |
| both | `401 {"message":"invalid_format"}` | same as `X-API-Key` alone |

So a pasted API key belongs in **`X-API-Key`**, and the OAuth access token in
`Authorization: Bearer`. The official CLI sends both headers on every model request, so
Bifrost does the same: `X-API-Key` when the key has a pasted value, `Authorization` when it
has an OAuth bundle.

Editor-identity values, read from the CLI's constants module (the `Vo`/`KR` exports):
`X-Product: SaaS` (from the product's `deploymentType`), `X-IDE-Type: CLI`,
`X-IDE-Name: CodeBuddy`, `X-IDE-Version: 0.0.0`. Sending these plus a bogus `X-API-Key`
gets past the header checks and fails only at credential validation, which is the
observation above.

## Goals

- Administrators can add CodeBuddy CN as a provider and create keys under it.
- A key authenticates either with a pasted API key **or** with a browser login performed
  from the Bifrost UI. Both reach the same upstream.
- OAuth keys renew themselves transparently for as long as the refresh token lives.
- Streaming and non-streaming client requests both work, even though upstream only streams.
- Multiple keys under the provider load-balance through the existing key selection, and
  each key carries its own credential lifecycle.
- Nothing about this provider costs the other providers anything at request time.

## Non-goals

- The international CodeBuddy surface (`www.codebuddy.ai`). The provider is CN-only; the
  endpoint is configurable, so an intl variant is a follow-up, not a redesign.
- Non-chat endpoints: embeddings, images, speech, batch, files. CodeBuddy exposes some of
  these, but nothing in the official CLI needs them and the wire formats are unverified.
  They return "not supported".
- Per-end-user CodeBuddy identities. Credentials belong to the gateway administrator, one
  set per key, shared by all traffic that key serves.
- Billing/quota lookup endpoints.
- Migrating or importing credentials from other tools.

## Decisions taken

Each of these was chosen during the design conversation; they constrain the build.

1. **Credentials live on the key, using the existing `oauth_key_config`** rather than a new
   `codebuddy_cn_key_config` struct. This avoids a config-store migration entirely — see the
   storage comparison below — at the cost of one struct carrying both machine-to-machine and
   interactive-login grants, distinguished by `grant_type`.
2. **A key has exactly one auth mode**: either `value` (pasted API key) or
   `oauth_key_config` (browser login). Validation rejects both and rejects neither, and no
   new rule is needed — the existing "value or oauth" logic covers it.
3. **The login is a modal in the key form.** It opens a popup, the popup closes itself on
   success, and the token is written into the form the administrator is already editing.
   No page navigation, no "come back later".
4. **The access token is stored on the key and refreshed before use**, so a restart does not
   force a re-login. The refresh token is the durable credential.
5. **Pass the caller's `stream` flag through unchanged.** No forcing, no aggregation. The CLI
   proves both shapes are constructed; if a live run shows non-streaming rejected upstream,
   the fallback is to force stream and aggregate, and that is a contained change inside the
   provider package. This is settled by a live check before the streaming task is closed.
6. **Static model catalog**, since the gateway cannot enumerate models unauthenticated.
7. **Minimize upstream-conflict surface.** Every change to a shared file must be an additive
   branch, never a rewrite of shared logic. The provider's own behaviour lives in
   `core/providers/codebuddycn/`; shared files gain a `case`, an allowlist entry, or a field.

## How it fits the existing architecture

### Provider constants and registration

- `schemas.CodeBuddyCN ModelProvider = "codebuddy-cn"`, added to `StandardProviders`.
- Constructed in `core/bifrost.go`'s provider switch.
- `CanProviderKeyValueBeEmpty` gains `CodeBuddyCN` (a key may carry only the OAuth bundle).

### New key config — extends `OAuthKeyConfig`, no new table, no migration

The credential model reuses the existing `oauth_key_config` instead of adding a
`codebuddy_cn_key_config`. The reason is storage: `TableKey.OAuthSettingsJSON` is a
**generic, already-encrypted column** that holds a JSON serialization of the whole
`OAuthKeyConfig` with only four credential fields split out into their own columns
(`framework/configstore/tables/key.go` `BeforeSave`/`AfterFind`). Adding fields to
`OAuthKeyConfig` therefore persists them with **zero schema changes**:

| | New `codebuddy_cn_key_config` | Extend `OAuthKeyConfig` (chosen) |
|---|---|---|
| New `config_keys` columns | 3–5 encrypted columns | **0** |
| Hand-written `ALTER TABLE` migration | required | **none** |
| `tables/key.go` BeforeSave/AfterFind | ~20 lines of provider-specific copying | **none** — fields ride in `oauth_settings_json` |
| `clientconfig.go` redaction + ConfigHash | new provider-specific branch | `Redacted()` + hash view, a few lines |
| `mergeUpdatedKey` masked-update | new provider-specific branch | two more entries in the existing loop |
| Files touched by provider config plumbing | ~25, ~300 lines | ~6, small additive branches |

The new grant joins the existing enum:

```go
// OAuthGrantBrowserLogin is the interactive device/browser login used by CodeBuddy CN.
// Unlike client_credentials and jwt_bearer, the token endpoint is a *refresh* endpoint and
// the durable credential is the refresh token, not a client secret.
const OAuthGrantBrowserLogin OAuthGrantType = "browser_login"
```

and `OAuthKeyConfig` gains three fields, all of which serialize into `oauth_settings_json`:

```go
AccessToken  *SecretVar `json:"access_token,omitempty"`  // short-lived bearer; refreshed before use
RefreshToken *SecretVar `json:"refresh_token,omitempty"` // durable credential that mints access tokens
ExpiresAt    string     `json:"expires_at,omitempty"`    // RFC3339; empty means "unknown, refresh on use"
```

`Endpoint` is **not** added: the login and refresh endpoints derive from the provider's
`network_config.base_url`, so there is one place to point the provider elsewhere.

Consequences that must be handled, each a small additive change:

1. **`Redacted()`** must mask `AccessToken` and `RefreshToken` — two lines, same pattern as
   `ClientSecret`.
2. **`oauthKeyConfigHashView()`** must keep rotating state out of `ConfigHash`. A refresh
   changes the access token and expiry, and if those fed the hash a config.json-managed key
   would look "changed" on every reconciliation and get rewritten from file, wiping the
   refreshed credential. So the hash view substitutes a constant for `AccessToken` and
   `ExpiresAt`, and reduces `RefreshToken` to its source marker (`ref:`/`val:`) rather than
   its value. The hash then represents declared configuration, not runtime state.
3. **`mergeUpdatedKey`** adds `access_token` and `refresh_token` to the existing
   preserve-on-mask loop, so a form save that echoes masks resolves to the stored tokens.
4. **`Validate()`** needs a `browser_login` case: `token_url` (the refresh endpoint) is
   required, `client_id`/`client_secret` are not, and the https/no-query rules still apply.
5. **`MinterForConfig`** gains a branch that refreshes via the refresh endpoint with the
   refresh token in the `X-Refresh-Token` header.
6. **`ProviderSupportsOAuthKeyConfig`** gains `CodeBuddyCN`.

Vault deployments: `oauth_settings_json` is stored as one vault blob, so a vault-backed key
read resolves that blob. Existing `OAuthKeyConfig` users already have this shape; the build
must confirm whether that read is cached, and if not, that the key is read once per request
rather than once per retry.

**Persistence.** The refreshed token has to survive a restart, otherwise every restart
forces a re-login once the old access token ages out. Providers are handed keys per request
(`bifrost.account.GetKeysForProvider`), and the account lives behind an interface, so the
write-back does **not** need a provider rebuild:

- The provider returns the new credential through a small sink on `ProviderConfig`
  (an interface the transport supplies), rather than reaching for a store handle it does
  not have.
- The sink updates the account's in-memory key entry, so the *next* request's
  `GetKeysForProvider` returns the fresh token. No `Bifrost.UpdateProvider`, no queue
  rebuild, no worker respawn.
- The sink also writes through to the config store when one exists, using the existing
  `Config.UpdateProviderKey` path with `BifrostContextKeySkipDBUpdate` for the in-memory
  overlay and a debounced store write so a token refreshed once per expiry window produces
  one row write, not one per request.

**A refresh token may rotate.** The official CLI replaces its stored refresh token
unconditionally on every refresh, which is consistent with rotation but does not prove the
server invalidates the old one. The design therefore assumes rotation is possible and makes
write-back mandatory rather than best-effort: a refresh is single-flighted per key, and the
new refresh token is committed before the request that triggered it is dispatched. If a
write is lost, the credential degrades to a re-login, so the failure is loud rather than
silent.

**File-only deployments.** With `config_store.enabled: false` there is nothing to write to.
Refreshed tokens then live in memory for the process lifetime, and a restart after expiry
requires a re-login. This is stated in the provider docs rather than worked around.

**Multi-replica deployments.** The login flow table must be the shared `KVStore` (it already
carries a cluster sync delegate), not an in-process map, or `POST /login` on one replica and
`GET /login/{id}` on another would break. Refresh single-flight is per process; two replicas
may each refresh once, which is harmless unless refresh tokens are single-use, in which case
one replica's write wins and the other's credential dies. This is the accepted risk of the
rotation assumption above, and it is why the failure surfaces as "re-login required" instead
of a retry storm.

### Provider package

`core/providers/codebuddycn/`, Category 2 (OpenAI-compatible) in shape, with:

- `codebuddycn.go` — constructor, `Provider` interface, credential resolution, key health.
- `auth.go` — the four auth calls (state, poll, refresh) plus the exported login helpers.
- `credential.go` — resolve refresh decision (expired / near-expiry / valid).
- `chat.go` — the request decoration (force stream, editor headers) and the
  stream→response aggregation for non-streaming callers.
- `errors.go` — `code`/`msg` envelope → `*schemas.BifrostError`, including the auth-specific
  codes so a dead credential is not retried.
- `models.go` — static catalog.
- `codebuddycn_test.go` — the one test file for the package.

Chat, embedding, etc. delegate to the `openai` package helpers, passing a decorated
`authHeader` map and `extraHeaders`. `ChatCompletion` and `ChatCompletionStream` take
separate paths because of the forced-stream asymmetry.

### Refresh strategy

Refresh runs on the request path, gated on the stored expiry minus a margin (60s, matching
`tokencache.DefaultRefreshMargin`). A valid token costs one comparison and no allocation.
Concurrent refreshes for the same key collapse through `tokencache.Cache`, keyed by a hash
of the refresh token — the cache already provides single-flight, negative caching and
backoff, so one misconfigured key cannot hammer Tencent.

A dead refresh token (`12153` / 401) is a **permanent** error: the key is marked unhealthy,
the request fails with an actionable message telling the administrator to re-login, and
fallback to another key/provider proceeds normally. It is never retried in a loop.

"Unhealthy" here means **per-request only**, matching the existing `deadKeyIDs` behaviour in
`core/bifrost.go`: the key is skipped for the rest of that request and tried again on the
next one. Nothing is persisted and nothing is auto-disabled, so load balancing does not
silently change. The UI surfaces the problem where the administrator can act on it: the key
row shows "Re-authenticate" when its stored refresh is known-dead, which the provider records
by returning a typed error the key-status path recognises.

Error classification: the gateway returns HTTP 200 bodies with a non-zero `code` for most
failures, while core's retry/fallback/dead-key logic keys off `StatusCode`. Mapping:

| `code` | Meaning | `StatusCode` | Retriable |
|---|---|---|---|
| `11217` | login still pending (poll only) | — | n/a |
| `12153` | refresh token dead | 401 | no — permanent, dead-key |
| anything else | unknown | 502 | yes, with the upstream `code`/`msg` preserved in the error body |

Note: the `11101` / `11102` mappings present in an earlier draft came from a third-party
implementation and are **not** corroborated by the official bundle, so they are not used.
Unknown codes take the 502-retriable path, and a live probe confirms the real values.

### Skipped

- Only chat completions (streaming and not) and model listing. `Embedding`, `Speech`,
  `Transcription`, `ImageGeneration`, `Batch*`, `File*`, `Container*` return "not supported"
  with the standard error shape.

### Non-streaming and streaming

Both delegate to the `openai` package helpers with the caller's `stream` flag intact:
`HandleOpenAIChatCompletionRequest` for unary and `HandleOpenAIChatCompletionStreaming` for
streams. No stream→response aggregation is written, because the official CLI constructs both
request shapes and the gateway therefore accepts both.

If a live run proves non-streaming is rejected, the fix is contained to
`CodeBuddyCNProvider.ChatCompletion`: call the streaming helper with `stream: true`, drain
the returned channel, and fold chunks into a `BifrostChatResponse`. That is a fallback inside
one file, not a design change, and the plan checks it early with a live probe.

Cost: a CodeBuddy request pays only the header set the provider requires — no aggregation,
no forced-stream round trip.

## Login flow (end to end)

```
Admin clicks "Sign in with CodeBuddy" in the key form
      │
      ├─ POST /api/providers/{provider}/codebuddy-cn/login        (Bifrost)
      │     └─ upstream POST /v2/plugin/auth/state?platform=CLI
      │         ← {flow_id, auth_url, expires_at}
      │
      ├─ UI opens auth_url in a popup  (window.open, inside the click handler)
      │
      └─ UI polls GET /api/providers/{provider}/codebuddy-cn/login/{flow_id}
            └─ upstream GET /v2/plugin/auth/token?state=<uuid>
                code 11217 → {"status":"pending"} → keep polling (5s)
                code 0     → {"status":"completed","access_token":…,"refresh_token":…}
                error      → {"status":"failed","error":…}
            │
      popup closes, form fields populate, admin saves the key
```

Design points worth stating:

- **The server holds the flow.** The browser never talks to Tencent, so CORS is a non-issue
  and the state nonce never leaves the gateway.
- **Both endpoints require an authenticated admin session.** Without one they return 403,
  following the existing `isAuthBypassed(ctx)` guard pattern in `config.go`. A login endpoint
  hands out a live upstream credential, so it is not reachable on a dashboard with
  authentication disabled — the same standard the repo already applies to the global proxy
  and the MCP private allowlist.
- **The upstream endpoint is not caller-controlled.** It comes from the provider's
  `network_config.base_url` (defaulting to `https://copilot.tencent.com`), never from the
  request body, so the login endpoint cannot be turned into an arbitrary-host dial target.
  A key-level `endpoint` override applies only to inference for an already-saved key and is
  validated as https.
- **`window.open` is called synchronously in the click handler**, before the `auth/state`
  request resolves. Browsers block a popup opened after an `await`; the existing MCP
  authorizer hit this exact problem and solved it with an `initialPopup` prop. The new
  modal reuses that pattern.
- **Flows live in the shared `KVStore`**, keyed by an opaque `flow_id`, with a 15-minute TTL
  (matching the MCP flow convention). Not an in-process map: behind a load balancer the
  start and the poll can land on different replicas. The upstream `state` nonce is stored
  server-side and never sent to the browser.
- **Polling stops** on completion, failure, admin cancel, modal close, or TTL expiry. The
  UI also closes the popup on success.
- **Tokens never appear in a URL**, only in a JSON body over the admin's authenticated
  session.

## UI

### Provider presence

- `ui/lib/constants/config.ts` — model placeholder, key-optional flag.
- `ui/lib/constants/icons.tsx` — provider icon.
- `ui/lib/constants/logs.ts` — display name (both places).
- `transports/config.schema.json` — provider entry and enum (both locations).
- `docs/openapi/openapi.json` — spec update.
- `docs/providers/supported-providers/codebuddy-cn.mdx` — provider doc page.

### Key form

A new fragment block in `apiKeysFormFragment.tsx`, gated on
`effectiveProvider === "codebuddy-cn"`, offering two mutually exclusive modes:

- **API key** — the ordinary `value` input, unchanged.
- **OAuth login** — a status row plus a "Sign in" / "Re-authenticate" button, a
  "Connected as …" state when a token is present, and an expiry readout.

The login modal is a new component next to the form (not a rewrite of the MCP
`OAuth2Authorizer`, which is MCP-specific in its API calls and copy). It borrows that
component's proven mechanics: synchronous popup, polling with backoff, timeout, cancel,
and the accessibility/`data-testid` conventions of `authorizerUi.tsx`.

The "connected" state shows the credential's expiry, not an account name: the verified
login response carries no identity, and the CLI's account call (`/v2/plugin/account`) is
not usable here (it 401s at the gateway with a bad bearer and is not part of the documented
login response). Dismissing the modal with a token present keeps the tokens in form state;
the administrator still has to save the key.

Zod validation in `ui/lib/types/schemas.ts` and `ui/lib/schemas/providerForm.ts` mirrors the
server rule: exactly one of `value` / `oauth_key_config` for a `codebuddy-cn` key.

### RTK Query

Two endpoints in the providers API slice — `startCodeBuddyCNLogin` (mutation) and
`getCodeBuddyCNLoginStatus` (query, polled via `pollingInterval`, stopped by `skip` once
terminal). Tags: `["Providers"]` on completion so the key table refreshes.

## Testing

Following the repo's testing contract:

- **Unit tests** in `codebuddycn_test.go`: request decoration (editor headers, auth header
  choice, `stream` passthrough), refresh-decision boundaries, `11217`/`12153`/dead-token
  classification, redaction round-trip, exactly-one-auth-mode validation.
- **Handler tests** for the two login endpoints: flow lifecycle, TTL sweep, polling
  transitions, error mapping, the auth guard, and that tokens are not returned before
  `code:0`.
- **UI tests**: zod schema cases in `providerForm.test.ts` (mirroring
  `providerForm.copilot.test.ts`), and a modal test for popup + polling + populate.
- **Provider-harness cases** for the wire-visible parts: a non-streaming chat through
  `/v1/chat/completions` with a `codebuddy-cn/` model prefix, and a streaming one, both
  asserting the editor headers are invisible to the client.
- **`make test-core PROVIDER=codebuddy-cn`** with a live credential, at the end.

## Cost on the request path

- Non-CodeBuddy providers: one `switch` case in the constructor and one boolean in
  `CanProviderKeyValueBeEmpty`. Zero allocations added.
- CodeBuddy keys with a valid token: one time comparison, one map load for the cached
  credential, plus the header set the provider requires anyway.
- Refresh: once per expiry window per key, outside the request's critical path only in the
  sense that it happens before dispatch; `tokencache` guarantees a single exchange for
  concurrent requests.
- Retained memory: one token entry per key in the provider's `tokencache` slot, a few
  hundred bytes per distinct credential history, bounded by key count; and one in-memory
  login flow per in-progress admin login, TTL-swept at 15 minutes.

## Risks and open items

- **The static model catalog will drift.** Tencent adds and retires model ids. Mitigation:
  the catalog is a single slice, and unknown model ids are passed through rather than
  rejected, so a new model works before the catalog is updated.
- **Refresh-token rotation is assumed.** If Tencent single-uses refresh tokens, a lost
  write-back or a second replica's refresh can force a re-login. Mitigated by single-flight
  refresh and committing the new token before dispatch, and surfaced as an explicit
  "re-authenticate" state rather than retries.
- **`expiresIn` is unreliable.** Treated as a hint; expiry is stored as an absolute time and
  a missing value means "refresh on next use".
- **File-only deployments cannot persist a refresh.** Stated in the docs; re-login after
  restart-and-expiry is the accepted outcome.
- **The key-config migration is no longer scope.** Extending `OAuthKeyConfig` reuses the
  encrypted `oauth_settings_json` column, so there is no schema change. The remaining risk is
  the opposite one: because the tokens now live in a shared generic column, `Redacted()` and
  the ConfigHash view must be right, or a reconciliation can leak a token or wipe a refresh.

## Upstream-conflict surface

The stated goal is that syncing from upstream stays cheap. Measured against
`github_copilot_key_config`, the closest existing precedent, which appears in 25 files and
~298 lines — much of it provider-specific branches inserted *inside* shared functions
(`BeforeSave`, `AfterFind`, `mergeUpdatedKey`, `validateProviderKey`):

| Area | Change | Conflict risk |
|---|---|---|
| `core/providers/codebuddycn/` | new package, all provider logic | none — new files |
| `core/schemas/bifrost.go` | one const, one list entry | trivial, additive |
| `core/schemas/account.go` | 3 fields + one enum const + `Validate`/`Redacted`/hash-view branches | low, additive |
| `core/bifrost.go` | one `case` in the provider switch | trivial, additive |
| `core/utils.go` | `CodeBuddyCN` in two allowlists | trivial, additive |
| `core/providers/utils/tokencache/oauthkey.go` | one `MinterForConfig` branch | low, additive |
| `transports/bifrost-http/handlers/providers.go` | two login routes | additive — new file possible |
| `transports/bifrost-http/handlers/provider_keys.go` | two entries in the preserve loop | low, additive |
| `framework/configstore/` | **nothing** | none |
| `transports/config.schema.json` | two entries | trivial, JSON |
| `ui/` | provider constants + a new form fragment + modal component | low; new files for the modal |
| `docs/` | one provider page + openapi entries | none |

No shared function body is rewritten. The highest-risk items are the `Validate`/`Redacted`/
hash-view edits in `account.go`, because they sit inside functions other providers also use —
so each is written as a guard on `GrantType`, mirroring how the existing two grants already
coexist there.

## Left to the builder

- Exact JSON field names for the two login endpoints' responses, beyond the states named
  above.
- The exact shape of the credential sink on `ProviderConfig` (an interface field vs. a
  callback), and whether the debounced store write lives in `lib.Config` or the handler.
- Whether the login modal is a `Dialog` or a `Sheet` — matching whichever the providers page
  already uses for key editing.
- Icon artwork choice.
- Whether the token cache lives on the provider struct or is shared; the existing
  `tokencache.Cache` usage pattern in `githubcopilot` is the default.
- Test fixture shape for a fake CodeBuddy upstream.
