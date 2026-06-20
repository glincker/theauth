package theauth

import "fmt"

// KavachError is the base error type for all TheAuth API errors.
type KavachError struct {
	Code       string                 `json:"code"`
	Message    string                 `json:"message"`
	StatusCode int                    `json:"statusCode,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

func (e *KavachError) Error() string {
	return fmt.Sprintf("theauth: [%s] %s", e.Code, e.Message)
}

// ErrAuthentication is returned when the request lacks valid credentials (HTTP 401).
type ErrAuthentication struct {
	KavachError
}

// ErrPermission is returned when the caller lacks permission for the action (HTTP 403).
type ErrPermission struct {
	KavachError
}

// ErrNotFound is returned when the requested resource does not exist (HTTP 404).
type ErrNotFound struct {
	KavachError
}

// ErrRateLimit is returned when the rate limit is exceeded (HTTP 429).
// RetryAfter holds the suggested wait time in seconds if provided by the server.
type ErrRateLimit struct {
	KavachError
	RetryAfter *int
}

// ErrServer is returned for unexpected server-side errors (HTTP 5xx).
type ErrServer struct {
	KavachError
}

// ErrNetwork is returned when the HTTP request fails at the transport layer.
type ErrNetwork struct {
	KavachError
}

// IsNotFound reports whether err is an ErrNotFound.
func IsNotFound(err error) bool {
	_, ok := err.(*ErrNotFound)
	return ok
}

// IsAuthentication reports whether err is an ErrAuthentication.
func IsAuthentication(err error) bool {
	_, ok := err.(*ErrAuthentication)
	return ok
}

// IsPermission reports whether err is an ErrPermission.
func IsPermission(err error) bool {
	_, ok := err.(*ErrPermission)
	return ok
}

// IsRateLimit reports whether err is an ErrRateLimit.
func IsRateLimit(err error) bool {
	_, ok := err.(*ErrRateLimit)
	return ok
}

// IsServer reports whether err is an ErrServer.
func IsServer(err error) bool {
	_, ok := err.(*ErrServer)
	return ok
}
