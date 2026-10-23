package codebuddycn

import (
	"sync/atomic"

	schemas "github.com/maximhq/bifrost/core/schemas"
)

// CredentialSink receives a freshly rotated browser_login credential so the transport that owns
// persistence can store it. expiresAt is reported as an RFC3339 timestamp, which is the shape
// OAuthKeyConfig.ExpiresAt stores, so the sink never has to agree on a time format.
//
// provider is passed by the provider itself rather than captured by the caller: one process hosts
// every provider and a single sink is installed for all of them, so the callback has to say which
// provider's key it is talking about.
type CredentialSink func(provider schemas.ModelProvider, keyID, accessToken, refreshToken, expiresAt string)

// credentialSink holds the process-wide callback. It is an atomic pointer so the request path can
// read it without a lock and without allocating: a load of a pointer the runtime keeps in a
// register, plus a nil test on the path that reaches the OAuth branch only.
//
// A package-level variable is deliberate. The alternative — a field on schemas.ProviderConfig —
// would add a CodeBuddy-specific hook to the struct all 20+ providers are constructed from.
var credentialSink atomic.Pointer[CredentialSink]

// SetCredentialSink installs the process-wide callback, or clears it when fn is nil. It runs once
// at boot from the transport; passing nil is what tests and a bare Go SDK caller leave in place,
// and it means rotations are simply not persisted.
//
// Installing twice replaces the previous sink, so a test that installs one must clear it again.
func SetCredentialSink(fn func(provider schemas.ModelProvider, keyID, accessToken, refreshToken, expiresAt string)) {
	if fn == nil {
		credentialSink.Store(nil)
		return
	}
	sink := CredentialSink(fn)
	credentialSink.Store(&sink)
}

// currentCredentialSink returns the installed sink, or nil. The caller must nil-check before
// calling: a nil CredentialSink is a valid func value and calling it panics.
func currentCredentialSink() CredentialSink {
	if sink := credentialSink.Load(); sink != nil {
		return *sink
	}
	return nil
}
