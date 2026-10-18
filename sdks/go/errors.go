package theauth

import "fmt"

// TheAuthError is the base error type for all TheAuth API errors.
type TheAuthError struct {
	Code       string                 `json:"code"`
	Message    string                 `json:"message"`
	StatusCode int                    `json:"statusCode,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
	// Issues holds validation issues from the { error: { issues } } envelope
	// returned by plugin endpoints. Nil when the server sent none.
	Issues interface{} `json:"issues,omitempty"`
}

func (e *TheAuthError) Error() string {
	return fmt.Sprintf("theauth: [%s] %s", e.Code, e.Message)
}

// ErrAuthentication is returned when the request lacks valid credentials (HTTP 401).
type ErrAuthentication struct {
	TheAuthError
}

// ErrPermission is returned when the caller lacks permission for the action (HTTP 403).
type ErrPermission struct {
	TheAuthError
}

// ErrNotFound is returned when the requested resource does not exist (HTTP 404).
type ErrNotFound struct {
	TheAuthError
}

// ErrRateLimit is returned when the rate limit is exceeded (HTTP 429).
// RetryAfter holds the suggested wait time in seconds if provided by the server.
type ErrRateLimit struct {
	TheAuthError
	RetryAfter *int
}

// ErrServer is returned for unexpected server-side errors (HTTP 5xx).
type ErrServer struct {
	TheAuthError
}

// ErrNetwork is returned when the HTTP request fails at the transport layer.
type ErrNetwork struct {
	TheAuthError
}

// IsNotFound reports whether err is an ErrNotFound.
func IsNotFound(err error) bool {
	_, ok := err.(*ErrNotFound)
	return ok
}

// IsAuthentication reports whether err is an ErrAuthentication or an ErrStepUpRequired.
func IsAuthentication(err error) bool {
	switch err.(type) {
	case *ErrAuthentication, *ErrStepUpRequired:
		return true
	}
	return false
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

// IsCSRFRejected reports whether err is a 403 with code CSRF_REJECTED.
func IsCSRFRejected(err error) bool {
	e, ok := err.(*ErrPermission)
	return ok && e.Code == "CSRF_REJECTED"
}

// IsRateLimited reports whether err is a 429 rate limit error and returns the
// Retry-After value in seconds (0 when the server did not send one).
func IsRateLimited(err error) (retryAfterSeconds int, ok bool) {
	e, isRL := err.(*ErrRateLimit)
	if !isRL {
		return 0, false
	}
	if e.RetryAfter != nil {
		return *e.RetryAfter, true
	}
	return 0, true
}

// ValidationIssues returns the issues attached to err, or nil.
func ValidationIssues(err error) interface{} {
	switch e := err.(type) {
	case *TheAuthError:
		return e.Issues
	case *ErrPermission:
		return e.Issues
	case *ErrAuthentication:
		return e.Issues
	case *ErrNotFound:
		return e.Issues
	case *ErrRateLimit:
		return e.Issues
	case *ErrServer:
		return e.Issues
	}
	return nil
}
