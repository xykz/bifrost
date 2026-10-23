package lib

import (
	"errors"

	"github.com/maximhq/bifrost/core/schemas"
)

// Thin wrapper, keeping it here since it is exported
func NormalizeJSONErrorStatus(code int) int {
	return schemas.NormalizeJSONErrorStatus(code)
}

var ErrNotFound = errors.New("not found")
var ErrAlreadyExists = errors.New("already exists")

// ErrInvalidKeyCredential marks an update the caller got wrong rather than a store failure, so the
// handler can answer 400 instead of 500. It carries no detail of its own; the wrapped message does.
var ErrInvalidKeyCredential = errors.New("invalid key credential")

// ErrInvalidPluginConfig wraps a plugin config refused before the plugin is loaded, so callers
// can tell a config the caller got wrong apart from a failure to load a valid one.
var ErrInvalidPluginConfig = errors.New("invalid plugin config")
