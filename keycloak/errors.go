package keycloak

import (
	"errors"
	"fmt"

	"github.com/Nerzal/gocloak/v13"
)

// HTTPStatusError is returned when Keycloak answered with a non-2xx HTTP status.
type HTTPStatusError struct {
	StatusCode int
	URL        string
	// Message is the original error message, if any. It is used verbatim by [HTTPStatusError.Error].
	Message string
}

func (e *HTTPStatusError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("unexpected HTTP status %d from %s", e.StatusCode, e.URL)
}

// TransportError is returned when a request to Keycloak failed before a response was received
// (e.g. connection refused, connection reset, timeout).
//
// gocloak flattens the underlying network error into a string, so the original error chain is not available.
type TransportError struct {
	Message string
}

func (e *TransportError) Error() string {
	return e.Message
}

// translateGocloakError maps a [gocloak.APIError] to [HTTPStatusError] or [TransportError] so that callers can
// classify it. The error message is preserved. Other errors are returned unchanged.
func translateGocloakError(err error) error {
	var apiErr *gocloak.APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	if apiErr.Code == 0 {
		return &TransportError{Message: apiErr.Message}
	}
	return &HTTPStatusError{StatusCode: apiErr.Code, Message: apiErr.Message}
}
