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

// CredentialReader returns the key as the persistence layer currently holds it, so the provider can
// retry from a credential that has changed since the caller snapped its copy. The bool is false when
// the provider or key is unknown, which a caller treats as "no fresher copy available".
//
// It exists because a rotation lands in the store while the request that triggered it is still in
// flight: the caller's schemas.Key is a snapshot, and after a mint its refresh token is one
// generation behind the row. A 401 then has to invalidate and retry from the row, not from the
// snapshot, or the retry offers a refresh token the upstream has already retired.
type CredentialReader func(provider schemas.ModelProvider, keyID string) (schemas.Key, bool)

// credentialSink holds the process-wide callback. It is an atomic pointer so the request path can
// read it without a lock and without allocating: a load of a pointer the runtime keeps in a
// register, plus a nil test on the path that reaches the OAuth branch only.
//
// A package-level variable is deliberate. The alternative — a field on schemas.ProviderConfig —
// would add a CodeBuddy-specific hook to the struct all 20+ providers are constructed from.
var credentialSink atomic.Pointer[CredentialSink]

// credentialReader holds the optional read-back hook, nil when no persistence layer installed one.
var credentialReader atomic.Pointer[CredentialReader]

// SetCredentialSink installs the process-wide callback, or clears it when fn is nil. It runs once
// at boot from the transport; passing nil is what tests and a bare Go SDK caller leave in place,
// and it means rotations are simply not persisted.
//
// Installing twice replaces the previous sink. A caller that owns the install should prefer
// HasCredentialSink before doing so and its returned uninstall on shutdown, or two servers in one
// process end up sharing whichever sink booted last.
func SetCredentialSink(fn func(provider schemas.ModelProvider, keyID, accessToken, refreshToken, expiresAt string)) {
	if fn == nil {
		credentialSink.Store(nil)
		return
	}
	sink := CredentialSink(fn)
	credentialSink.Store(&sink)
}

// SetCredentialReader installs the read-back hook, or clears it when fn is nil. It is installed by
// the same wiring that installs the sink, so a process that persists rotations can also read the
// one it just persisted. Without it an invalidation still clears the access token, but the retry
// has only the caller's snapshot to work from.
func SetCredentialReader(fn CredentialReader) {
	if fn == nil {
		credentialReader.Store(nil)
		return
	}
	reader := fn
	credentialReader.Store(&reader)
}

// currentCredentialSink returns the installed sink, or nil. The caller must nil-check before
// calling: a nil CredentialSink is a valid func value and calling it panics.
func currentCredentialSink() CredentialSink {
	if sink := credentialSink.Load(); sink != nil {
		return *sink
	}
	return nil
}

// currentCredentialReader returns the installed reader, or nil. Same nil contract as the sink.
func currentCredentialReader() CredentialReader {
	if reader := credentialReader.Load(); reader != nil {
		return *reader
	}
	return nil
}

// HasCredentialSink reports whether a sink is currently installed. It exists so the transport can
// tell a first install from a replacement: replacing one silently is what makes two servers in one
// process (or a leaked test) share whichever sink booted last.
func HasCredentialSink() bool {
	return credentialSink.Load() != nil
}
