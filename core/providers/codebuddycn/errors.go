package codebuddycn

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/valyala/fasthttp"

	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
)

// deadRefreshTokenCode is the gateway's "this credential is gone" code. The refresh endpoint
// reports a dead refresh token either as a real 401 or as this code inside an HTTP-200 body.
const deadRefreshTokenCode = 12153

// codebuddyErrorBody covers both envelopes the gateway uses: its own {"code":N,"msg":"..."} and
// the bare {"message":"..."} the APISIX front end returns for a rejected credential.
type codebuddyErrorBody struct {
	Code    *int   `json:"code"`    // Gateway code; 0 or absent on success
	Msg     string `json:"msg"`     // Detail for a gateway code
	Message string `json:"message"` // Detail for a front-end rejection
}

// parseError converts an upstream failure into a BifrostError.
//
// The gateway's own envelope carries a numeric code where an HTTP status would normally say the
// same thing, and the front end answers a rejected credential with a bare message, so both shapes
// are read. A 401 or the dead-token code is a permanent credential fault: retrying it, or
// draining the request onto a fallback provider, hides a key the administrator has to
// re-authenticate behind traffic billed somewhere else. Everything else is 502 and retriable,
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
	if bifrostErr.Error == nil {
		bifrostErr.Error = &schemas.ErrorField{}
	}

	var body codebuddyErrorBody
	if raw := resp.Body(); len(raw) > 0 {
		_ = sonic.Unmarshal(raw, &body)
	}

	detail := strings.TrimSpace(body.Msg)
	if detail == "" {
		detail = strings.TrimSpace(body.Message)
	}
	code := 0
	if body.Code != nil {
		code = *body.Code
		if code != 0 {
			bifrostErr.Error.Code = schemas.Ptr(fmt.Sprintf("%d", code))
		}
	}

	dead := resp.StatusCode() == fasthttp.StatusUnauthorized || code == deadRefreshTokenCode
	if dead {
		bifrostErr.StatusCode = schemas.Ptr(http.StatusUnauthorized)
		bifrostErr.AllowFallbacks = schemas.Ptr(false)
	} else {
		bifrostErr.StatusCode = schemas.Ptr(http.StatusBadGateway)
	}

	switch {
	case detail != "" && code != 0:
		bifrostErr.Error.Message = fmt.Sprintf("codebuddy-cn: %s (code %d)", detail, code)
	case detail != "":
		bifrostErr.Error.Message = "codebuddy-cn: " + detail
	case code != 0:
		bifrostErr.Error.Message = fmt.Sprintf("codebuddy-cn: the provider returned code %d without a message", code)
	case dead:
		bifrostErr.Error.Message = "codebuddy-cn: the credential was rejected (401); re-authenticate the key"
	default:
		bifrostErr.Error.Message = fmt.Sprintf("codebuddy-cn: the provider returned status %d without a message", resp.StatusCode())
	}

	return bifrostErr
}
