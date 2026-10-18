package toolguard

// Throwaway generator for packages/core/tests/fixtures/approval-hash-vectors.json in the TypeScript
// SDK repo. It is NOT part of theauth-go. Copy it into policy/toolguard of a scratch copy of
// theauth-go (see README.md next to this file), then run:
//
//	GEN_IN=/abs/inputs.json GEN_OUT=/abs/approval-hash-vectors.json go test -run TestGenerateApprovalHashVectors ./policy/toolguard
//
// Every hash and pre-image comes from the real HashApprovalAction path (normalizeArgs, then
// json.Marshal), never from the TypeScript side. Each input is decoded two ways, because callers
// differ: plain json.Unmarshal (numbers become float64) and a decoder with UseNumber (numbers keep
// their source text).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type hashIn struct {
	Name          string `json:"name"`
	Action        string `json:"action"`
	Resource      string `json:"resource"`
	ArgumentsJSON string `json:"argumentsJson"`
	NumberText    bool   `json:"numberTextCase,omitempty"`
}

type hashOut struct {
	hashIn
	Float64   goHash `json:"float64"`
	UseNumber goHash `json:"useNumber"`
}

type goHash struct {
	Canonical string `json:"canonical,omitempty"`
	Hash      string `json:"hash,omitempty"`
	Error     string `json:"error,omitempty"`
}

func goHashOf(action, resource string, args any) goHash {
	h, err := HashApprovalAction(action, resource, args)
	if err != nil {
		return goHash{Error: err.Error()}
	}
	norm, _ := normalizeArgs(args)
	raw, _ := json.Marshal(map[string]any{"action": action, "resource": resource, "arguments": norm})
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != h {
		panic("preimage does not hash to HashApprovalAction")
	}
	return goHash{Canonical: string(raw), Hash: h}
}

func TestGenerateApprovalHashVectors(t *testing.T) {
	in, out := os.Getenv("GEN_IN"), os.Getenv("GEN_OUT")
	if in == "" || out == "" {
		t.Skip("GEN_IN and GEN_OUT not set")
	}
	raw, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []hashIn `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var cases []hashOut
	for _, c := range doc.Cases {
		var f any
		if err := json.Unmarshal([]byte(c.ArgumentsJSON), &f); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		dec := json.NewDecoder(bytes.NewReader([]byte(c.ArgumentsJSON)))
		dec.UseNumber()
		var n any
		if err := dec.Decode(&n); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		cases = append(cases, hashOut{hashIn: c,
			Float64:   goHashOf(c.Action, c.Resource, f),
			UseNumber: goHashOf(c.Action, c.Resource, n)})
	}
	res := map[string]any{
		"producer": "theauth-go policy/toolguard HashApprovalAction",
		"cases":    cases,
	}
	b, err := json.MarshalIndent(res, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
