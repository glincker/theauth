package theauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// ProvenanceKind says where an input came from.
type ProvenanceKind string

const (
	ProvenanceUserMessage       ProvenanceKind = "user_message"
	ProvenanceToolOutput        ProvenanceKind = "tool_output"
	ProvenanceRetrievedDocument ProvenanceKind = "retrieved_document"
	ProvenanceAgent             ProvenanceKind = "agent"
)

// ProvenanceInput is one input that shaped a call. Send Content and let the
// server hash it with its audit key, or send a Hash (64 lowercase hex characters)
// you computed yourself with HashVersion set to the version the server expects
// (2 today). The content is never stored.
type ProvenanceInput struct {
	Kind        ProvenanceKind `json:"kind"`
	ID          string         `json:"id,omitempty"`
	Content     string         `json:"content,omitempty"`
	Hash        string         `json:"hash,omitempty"`
	HashVersion int            `json:"hashVersion,omitempty"`
}

// InputsHeader is the header proxies and gateways can use when they cannot
// rewrite a body. The server ignores a malformed header and the body wins when
// both are present.
const InputsHeader = "TheAuth-Inputs"

const (
	maxInputs      = 32
	maxHeaderChars = 8192
)

// EncodeInputsHeader returns the header value for inputs: base64url without
// padding of the JSON array. Prefer entries with a Hash over Content here,
// since proxies log headers. It fails when the server would ignore the value
// (more than 32 inputs or more than 8192 characters).
func EncodeInputsHeader(inputs []ProvenanceInput) (string, error) {
	if len(inputs) > maxInputs {
		return "", fmt.Errorf("theauth: at most %d inputs fit in the header", maxInputs)
	}
	raw, err := json.Marshal(inputs)
	if err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	if len(value) > maxHeaderChars {
		return "", fmt.Errorf("theauth: encoded inputs are %d characters, the limit is %d", len(value), maxHeaderChars)
	}
	return value, nil
}
