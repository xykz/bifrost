package codebuddycn

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/valyala/fasthttp"

	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
)

// deadRefreshTokenCode is the gateway's "this credential is gone" code. The refresh endpoint
// reports a dead refresh token either as a real 401 or as this code inside an HTTP-200 body.
const deadRefreshTokenCode = 12153

// parseError converts an upstream failure into a BifrostError.
//
// The gateway's own envelope carries a numeric code where an HTTP status would normally say the
// same thing, and the front end answers a rejected credential with a bare message or an HTML page,
// so the body is read leniently. A 401 or the dead-token code is a permanent credential fault:
// retrying it, or draining the request onto a fallback provider, hides a key the administrator has
// to re-authenticate behind traffic billed somewhere else. Everything else is 502 and retriable,
// since an unknown code may be a transient upstream condition.
//
// The upstream code and detail ride in the body so an operator can act on them; the detail is
// what the gateway said, prefixed to make clear which provider produced it.
func parseError(resp *fasthttp.Response) *schemas.BifrostError {
	// The generic handler supplies the raw response and the retry hint; only the status and
	// the message are ours to decide.
	var upstream schemas.BifrostError
	bifrostErr := providerUtils.HandleProviderAPIError(resp, &upstream)
	bifrostErr.EventID = upstream.EventID
	if upstream.Error != nil {
		bifrostErr.Error = upstream.Error
	}

	code, detail := readEnvelope(resp.Body())
	applyEnvelope(bifrostErr, code, detail, resp.StatusCode())
	return bifrostErr
}

// codeKeyPresence is the cheapest possible pre-filter for the success path. gjson rescanning a
// whole completion body costs ~200ns; a byte scan for the key costs a tenth of that and rules out
// the overwhelming majority of bodies, which carry no gateway code at all. A false positive (the
// word "code" inside message content) merely falls through to the gjson lookups, which then find
// no code field and return success — so this can only ever save work, never change an answer.
var codeKeyPresence = []byte(`"code"`)

// readEnvelope pulls the gateway code and its human detail out of a response body, tolerating the
// three shapes seen in practice: {"code":N,"msg":"..."}, a bare {"message":"..."} from the front
// end, and an HTML error page. It returns code 0 when the body carries no gateway code, which is
// what distinguishes a failure envelope from a completion payload.
//
// This is the thorough version, for the error path where the body is already known to be a
// failure and the detail is worth any number of lookups. The success path goes through
// envelopeError, which pre-filters before calling here.
func readEnvelope(body []byte) (code int, detail string) {
	if len(body) == 0 {
		return 0, ""
	}
	if node := gjson.GetBytes(body, "code"); node.Exists() {
		code = int(node.Int())
	}
	detail = strings.TrimSpace(gjson.GetBytes(body, "msg").String())
	if detail == "" {
		detail = strings.TrimSpace(gjson.GetBytes(body, "message").String())
	}
	return code, detail
}

// applyEnvelope fills a BifrostError from one gateway envelope. It is the single place the
// envelope→error mapping exists, shared by the non-200 path (parseError) and the 200 path
// (chatResponseHandler), so the two cannot classify the same failure differently.
//
// A 401 or the dead-token code is a permanent credential fault and pins the status to 401 with
// fallbacks blocked; everything else is 502 and retriable. httpStatus is the status the response
// carried, used to spot a rejected credential and to phrase the message when the envelope said
// nothing. A retried condition says so in the message: a 502 from a refused model would otherwise
// read as a gateway outage rather than the transient upstream answer the spec treats it as.
func applyEnvelope(bifrostErr *schemas.BifrostError, code int, detail string, httpStatus int) {
	if bifrostErr.Error == nil {
		bifrostErr.Error = &schemas.ErrorField{}
	}
	if code != 0 {
		bifrostErr.Error.Code = schemas.Ptr(strconv.Itoa(code))
	}

	dead := httpStatus == fasthttp.StatusUnauthorized || code == deadRefreshTokenCode
	if dead {
		bifrostErr.StatusCode = schemas.Ptr(http.StatusUnauthorized)
		bifrostErr.AllowFallbacks = schemas.Ptr(false)
	} else {
		bifrostErr.StatusCode = schemas.Ptr(http.StatusBadGateway)
	}

	switch {
	case detail != "" && code != 0:
		bifrostErr.Error.Message = fmt.Sprintf("codebuddy-cn: %s (code %d)%s", detail, code, transientNote(code, dead))
	case detail != "":
		bifrostErr.Error.Message = "codebuddy-cn: " + detail
	case code != 0:
		bifrostErr.Error.Message = fmt.Sprintf("codebuddy-cn: the provider returned code %d without a message%s", code, transientNote(code, dead))
	case dead:
		bifrostErr.Error.Message = "codebuddy-cn: the credential was rejected (401); re-authenticate the key"
	default:
		bifrostErr.Error.Message = fmt.Sprintf("codebuddy-cn: the provider returned status %d without a message", httpStatus)
	}
}

// transientNote explains, in one short clause, why a non-401 answer with a gateway code is being
// retried rather than treated as a permanent fault. Without it the 502 reads as an infrastructure
// failure, so an operator cannot tell a model-availability refusal the spec says to retry from an
// outage — and the retries look like a gateway problem rather than the ruling they are.
func transientNote(code int, dead bool) string {
	if dead || code == 0 {
		return ""
	}
	return "; transient, retrying"
}

// envelopeError reports whether a response body is a gateway failure envelope rather than a
// payload, and converts it if so.
//
// The gateway reports most inference failures as an HTTP 200 carrying {"code":N,"msg":"..."},
// which is why this has to run on the success path at all — and on the streaming path, once per
// frame. A normal completion has no gateway code, so the common case here must be as cheap as
// possible: one byte scan rejects it before gjson is asked to parse anything, and no allocation
// is made. A non-zero code is authoritative; the gateway only sets it on failure.
func envelopeError(body []byte) *schemas.BifrostError {
	if !bytes.Contains(body, codeKeyPresence) {
		return nil
	}
	code, detail := readEnvelope(body)
	if code == 0 {
		return nil
	}
	bifrostErr := &schemas.BifrostError{IsBifrostError: false}
	applyEnvelope(bifrostErr, code, detail, http.StatusOK)
	return bifrostErr
}

// chatResponseHandler is the provider's customResponseHandler for both the unary and streaming
// chat helpers. It exists for one reason: neither shared path looks for CodeBuddy's
// {"code":N,"msg":"..."} envelope, so on a 200 the failure would be decoded into an empty
// completion and handed back as a success.
//
// A body carrying no gateway code is a genuine payload and goes through the same
// providerUtils.HandleProviderResponse call the shared path makes, so successful responses behave
// exactly as they would without a handler.
//
// The body here is one JSON document: on the streaming path the helper passes it a single SSE
// `data:` frame, so the same envelope detection serves both.
func chatResponseHandler(responseBody []byte, response *schemas.BifrostChatResponse, requestBody []byte, sendBackRawRequest bool, sendBackRawResponse bool) (interface{}, interface{}, *schemas.BifrostError) {
	if bErr := envelopeError(responseBody); bErr != nil {
		return nil, nil, bErr
	}
	return providerUtils.HandleProviderResponse(responseBody, response, requestBody, sendBackRawRequest, sendBackRawResponse)
}
