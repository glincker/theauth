package theauth

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// InsufficientUserAuthentication is the error value of a step-up challenge (RFC 9470).
const InsufficientUserAuthentication = "insufficient_user_authentication"

// acr classes the server issues, weakest first (ACR in the TypeScript core).
const (
	ACRNone              = "urn:theauth:acr:none"
	ACRSingleFactor      = "urn:theauth:acr:single-factor"
	ACRMFA               = "urn:theauth:acr:mfa"
	ACRPhishingResistant = "urn:theauth:acr:phishing-resistant"
)

// ACROrder lists every class, weakest first. The ordering is a theAuth rule;
// RFC 9470 itself treats acr values as opaque strings.
var ACROrder = []string{ACRNone, ACRSingleFactor, ACRMFA, ACRPhishingResistant}

// StepUpChallenge is what a resource asked for in an
// insufficient_user_authentication challenge.
type StepUpChallenge struct {
	Scheme string
	// ACRValues are the acceptable acr values. The user needs any one of them.
	ACRValues []string
	// MaxAge is the maximum age of the sign-in in seconds, nil when not asked.
	MaxAge           *int
	ErrorDescription string
	ResourceMetadata string
}

// AuthorizeParams returns acr_values and max_age for the authorization request
// that answers the challenge (RFC 9470 section 4).
func (c *StepUpChallenge) AuthorizeParams() map[string]string {
	params, _ := StepUpParams(c.ACRValues, c.MaxAge)
	return params
}

// StepUpParams builds acr_values and max_age for an authorization request. It
// fails on a negative max_age or an acr value that is empty or holds whitespace.
func StepUpParams(acrValues []string, maxAge *int) (map[string]string, error) {
	params := map[string]string{}
	for _, v := range acrValues {
		if v == "" || strings.ContainsAny(v, " \t\r\n") {
			return nil, fmt.Errorf("theauth: invalid acr value %q", v)
		}
	}
	if len(acrValues) > 0 {
		params["acr_values"] = strings.Join(acrValues, " ")
	}
	if maxAge != nil {
		if *maxAge < 0 {
			return nil, fmt.Errorf("theauth: max_age must be a non-negative number of seconds")
		}
		params["max_age"] = strconv.Itoa(*maxAge)
	}
	return params, nil
}

// ParseStepUpChallenge reads WWW-Authenticate values and returns the step-up
// challenge in them, or nil when none carries
// error="insufficient_user_authentication". A malformed max_age is dropped
// rather than guessed. Pass resp.Header.Values("WWW-Authenticate").
func ParseStepUpChallenge(headers ...string) *StepUpChallenge {
	for _, header := range headers {
		for _, ch := range parseChallenges(header) {
			if ch.params["error"] != InsufficientUserAuthentication {
				continue
			}
			out := &StepUpChallenge{
				Scheme:           ch.scheme,
				ACRValues:        strings.Fields(ch.params["acr_values"]),
				ErrorDescription: ch.params["error_description"],
				ResourceMetadata: ch.params["resource_metadata"],
			}
			if raw, ok := ch.params["max_age"]; ok && isDigits(raw) {
				if n, err := strconv.Atoi(raw); err == nil {
					out.MaxAge = &n
				}
			}
			return out
		}
	}
	return nil
}

// ACRSatisfies reports whether have is at least as strong as one of want. A
// missing have, or a class outside ACROrder, never satisfies.
func ACRSatisfies(have string, want ...string) bool {
	rank := acrRank(have)
	if rank < 0 {
		return false
	}
	for _, w := range want {
		if r := acrRank(w); r >= 0 && rank >= r {
			return true
		}
	}
	return false
}

// AuthIsFresh reports whether authTime (epoch seconds) is no older than maxAge
// seconds at now. A zero authTime is never fresh. A time more than skew in the
// future is not fresh either.
func AuthIsFresh(authTime int64, maxAge time.Duration, now time.Time, skew time.Duration) bool {
	if authTime == 0 {
		return false
	}
	age := now.Sub(time.Unix(authTime, 0))
	return age >= -skew && age <= maxAge
}

func acrRank(v string) int {
	for i, c := range ACROrder {
		if c == v {
			return i
		}
	}
	return -1
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type challenge struct {
	scheme string
	params map[string]string
}

// parseChallenges splits a header into challenges (RFC 9110 section 11.6.1).
// Parameter names are lower cased.
func parseChallenges(header string) []challenge {
	var out []challenge
	var cur *challenge
	i, n := 0, len(header)
	for i < n {
		for i < n && (header[i] == ' ' || header[i] == '\t' || header[i] == ',') {
			i++
		}
		start := i
		for i < n && !strings.ContainsRune(" \t,=", rune(header[i])) {
			i++
		}
		word := header[start:i]
		if word == "" {
			break
		}
		j := i
		for j < n && (header[j] == ' ' || header[j] == '\t') {
			j++
		}
		if j < n && header[j] == '=' && !(j+1 < n && header[j+1] == '=') {
			j++
			for j < n && (header[j] == ' ' || header[j] == '\t') {
				j++
			}
			var value string
			value, i = readParamValue(header, j)
			if cur != nil {
				cur.params[strings.ToLower(word)] = value
			}
			continue
		}
		out = append(out, challenge{scheme: word, params: map[string]string{}})
		cur = &out[len(out)-1]
		i = j
	}
	return out
}

func readParamValue(header string, i int) (string, int) {
	n := len(header)
	if i < n && header[i] == '"' {
		i++
		var b strings.Builder
		for i < n {
			c := header[i]
			if c == '\\' && i+1 < n {
				b.WriteByte(header[i+1])
				i += 2
				continue
			}
			if c == '"' {
				return b.String(), i + 1
			}
			b.WriteByte(c)
			i++
		}
		return b.String(), i
	}
	start := i
	for i < n && header[i] != ' ' && header[i] != '\t' && header[i] != ',' {
		i++
	}
	return header[start:i], i
}

// ErrStepUpRequired is returned when the caller must sign in again, stronger
// or more recently (HTTP 401, RFC 9470). IsAuthentication is also true for it.
// Challenge is nil when the server sent the error code without a header. Send
// the user through authorization with Challenge.AuthorizeParams().
type ErrStepUpRequired struct {
	TheAuthError
	Challenge *StepUpChallenge
}

// IsStepUpRequired reports whether err is an ErrStepUpRequired.
func IsStepUpRequired(err error) bool {
	_, ok := err.(*ErrStepUpRequired)
	return ok
}
