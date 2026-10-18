package audit

// Throwaway generator for packages/core/tests/fixtures/go-audit-chain-vectors.json in the TypeScript
// SDK repo. It is NOT part of theauth-go. Copy it into internal/audit of a scratch checkout of
// theauth-go (see README.md next to this file), then run:
//
//	GEN_OUT=/abs/path/go-audit-chain-vectors.json go test -run TestGenerateGoChainVectors ./internal/audit
//
// Every hash comes from the real BuildChainEntry. Each chain is also re-verified with the real
// VerifyChainRows before it is written.

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	oklog "github.com/oklog/ulid/v2"
)

const vecSecret = "0123456789abcdef0123456789abcdef"

type vecRow struct {
	Row     map[string]any `json:"row"`
	Payload string         `json:"payload"`
	Hash    string         `json:"hash"`
}

type vecChain struct {
	Name     string   `json:"name"`
	ChainKey string   `json:"chainKey"`
	Rows     []vecRow `json:"rows"`
}

func vid(prefix string, n int) oklog.ULID {
	u, err := oklog.Parse(fmt.Sprintf("%s%022d", prefix, n))
	if err != nil {
		panic(err)
	}
	return u
}

func ptr(u oklog.ULID) *models.ULID { return &u }

// exportRow mirrors what an exporter writes: the JSON of models.AuditEvent plus the four hashed
// pseudonyms (needed to verify rows whose raw ids were erased).
func exportRow(t *testing.T, e models.AuditEvent, entry ChainEntry, erase bool) map[string]any {
	t.Helper()
	e.ChainSeq = uint64(entry.Payload.Seq)
	e.PrevHash = entry.Payload.Prev
	e.Hash = entry.Hash
	if erase {
		e.ActorUserID, e.SubjectID, e.ActorID, e.ApproverID = nil, "", "", ""
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["actorUserPseudonym"] = entry.Payload.ActorUserPseudo
	m["subjectPseudonym"] = entry.Payload.SubjectPseudo
	m["actorPseudonym"] = entry.Payload.ActorPseudo
	m["approverPseudonym"] = entry.Payload.ApproverPseudo
	return m
}

func buildChain(t *testing.T, name string, events []models.AuditEvent, eraseIdx map[int]bool) vecChain {
	t.Helper()
	secret := []byte(vecSecret)
	c := vecChain{Name: name, ChainKey: ChainKey(events[0])}
	head := ChainHead{}
	var crows []ChainRow
	for i, e := range events {
		entry, err := BuildChainEntry(e, secret, head)
		if err != nil {
			t.Fatal(err)
		}
		pl := entry.Payload
		pl.V = ChainHashVersion
		raw, _ := json.Marshal(pl)
		erase := eraseIdx[i]
		c.Rows = append(c.Rows, vecRow{Row: exportRow(t, e, entry, erase), Payload: string(raw), Hash: entry.Hash})
		cr := ChainRow{Payload: entry.Payload, Hash: entry.Hash, RawActorUser: "", RawSubject: e.SubjectID,
			RawActor: e.ActorID, RawApprover: e.ApproverID, RawOrg: c.ChainKey}
		if e.ActorUserID != nil {
			cr.RawActorUser = e.ActorUserID.String()
		}
		if e.ActorSessionID != nil {
			cr.RawSession = e.ActorSessionID.String()
		}
		if erase {
			cr.RawActorUser, cr.RawSubject, cr.RawActor, cr.RawApprover = "", "", "", ""
		}
		crows = append(crows, cr)
		head = ChainHead{Seq: entry.Payload.Seq, Hash: entry.Hash}
	}
	i := 0
	res, err := VerifyChainRows(func() (ChainRow, bool, error) {
		if i >= len(crows) {
			return ChainRow{}, false, nil
		}
		i++
		return crows[i-1], true, nil
	}, secret, 0)
	if err != nil || !res.OK || res.Checked != len(events) {
		t.Fatalf("go verifier rejected chain %s: %+v %v", name, res, err)
	}
	return c
}

func TestGenerateGoChainVectors(t *testing.T) {
	out := os.Getenv("GEN_OUT")
	if out == "" {
		t.Skip("GEN_OUT not set")
	}
	base := time.UnixMicro(1760000000000000) // exact second boundary
	org1, org2 := vid("01JC", 1), vid("01JC", 2)
	ev := func(n int, org *models.ULID, action string, us int64) models.AuditEvent {
		return models.AuditEvent{ID: vid("01JB", n), OrganizationID: org, Action: action,
			CreatedAt: time.UnixMicro(base.UnixMicro() + us)}
	}

	// Chain A: org 1, rich rows.
	a1 := ev(1, ptr(org1), "agent.authorize", 0) // second boundary, minimal row (seq 1)
	a2 := ev(2, ptr(org1), "agent.authorize", 123456)
	a2.TargetType, a2.TargetID, a2.IP, a2.UserAgent = "tool", "t1", "203.0.113.7", "golden"
	a2.Metadata = map[string]any{"b": 2, "a": "x", "n": map[string]any{"z": 1, "y": []any{3, "<k>"}}}
	a2.SubjectID, a2.ActorID, a2.ApproverID, a2.PolicyVersion = "user_1", "agent_9", "user_2", "v7"
	a2.ActorUserID, a2.ActorSessionID = ptr(vid("01JD", 1)), ptr(vid("01JE", 1))
	a2.DelegationChain = []string{"agent_1", "agent_9"}
	a2.InputProvenance = map[string]any{"source": "tool_output", "chain": map[string]any{"b": 1, "a": 2}}
	a3 := ev(3, ptr(org1), "policy.decision", 999999)
	a3.Metadata = map[string]any{"html": "<b>&</b>", "uni": "café \U0001F600     \u007f", "ctl": "a\tb\nc\x01\x08\x0c\"\\"}
	a3.SubjectID, a3.ActorID = "user_é", "agent_😀"
	a4 := ev(4, ptr(org1), "agent.authorize_denied", 1000000)
	a4.Metadata = map[string]any{}
	a4.DelegationChain = []string{}
	a4.InputProvenance = map[string]any{}
	a5 := ev(5, ptr(org1), "vault.token.issued", 2500000)
	a5.Metadata = map[string]any{"max": int64(9007199254740991), "neg": -5, "f1": 1.5, "f2": 0.000001, "f3": 1e-7, "f4": 1e21, "f5": 100.0, "big": 123456789012345680000.0, "t": true, "nil": nil}
	a5.SubjectID, a5.ActorID = "user_1", "agent_9"
	a5.ActorUserID = ptr(vid("01JD", 2))
	a6 := ev(6, ptr(org1), "tool_approval.approved", 3000001)
	a6.SubjectID, a6.ActorID, a6.ApproverID = "user_3", "agent_3", "user_4"
	chainA := buildChain(t, "org1-rich", []models.AuditEvent{a1, a2, a3, a4, a5, a6}, map[int]bool{4: true, 5: true})

	// Chain B: org 2, short.
	b1 := ev(11, ptr(org2), "agent.created", 10)
	b1.ActorID = "agent_b"
	b2 := ev(12, ptr(org2), "agent.revoked", 20)
	b2.ActorID, b2.Metadata = "agent_b", map[string]any{"reason": "rotated"}
	b3 := ev(13, ptr(org2), "delegation.granted", 30)
	b3.DelegationChain = []string{"agent_b"}
	chainB := buildChain(t, "org2-short", []models.AuditEvent{b1, b2, b3}, nil)

	// Chain G: global chain (no organization, chain key "").
	g1 := ev(21, nil, "audit.events_dropped", 5)
	g1.Metadata = map[string]any{"dropped": 3}
	g2 := ev(22, nil, "agent.created", 6)
	g2.ActorID = "agent_g"
	chainG := buildChain(t, "global", []models.AuditEvent{g1, g2}, nil)

	doc := map[string]any{
		"format":             "theauth.audit.go-chain-vectors",
		"formatVersion":      1,
		"producer":           os.Getenv("GEN_PRODUCER"),
		"hashFormat":         "go-v1",
		"chainHashVersion":   ChainHashVersion,
		"pseudonymSecretHex": fmt.Sprintf("%x", []byte(vecSecret)),
		"chains":             []vecChain{chainA, chainB, chainG},
		"negative": []map[string]any{
			{"name": "tamper_metadata", "chain": 0, "mutate": map[string]any{"kind": "set_field", "row": 1, "field": "metadata", "value": map[string]any{"a": "y"}}, "expect": "hash_mismatch", "failsAtRow": 1},
			{"name": "tamper_action", "chain": 0, "mutate": map[string]any{"kind": "set_field", "row": 2, "field": "action", "value": "policy.other"}, "expect": "hash_mismatch", "failsAtRow": 2},
			{"name": "tamper_created_at_one_micro", "chain": 0, "mutate": map[string]any{"kind": "set_field", "row": 2, "field": "createdAt", "value": "2025-10-09T08:53:20.999998Z"}, "expect": "hash_mismatch", "failsAtRow": 2},
			{"name": "reorder_rows", "chain": 0, "mutate": map[string]any{"kind": "swap_rows", "a": 1, "b": 2}, "expect": "seq_gap", "failsAtRow": 1},
			{"name": "drop_middle_row", "chain": 0, "mutate": map[string]any{"kind": "drop_row", "row": 2}, "expect": "seq_gap", "failsAtRow": 2},
			{"name": "duplicate_row", "chain": 0, "mutate": map[string]any{"kind": "dup_row", "row": 1}, "expect": "seq_duplicate", "failsAtRow": 2},
			{"name": "wrong_prev", "chain": 0, "mutate": map[string]any{"kind": "set_field", "row": 3, "field": "prevHash", "value": "00"}, "expect": "prev_hash_mismatch", "failsAtRow": 3},
			{"name": "prev_not_empty_at_seq1", "chain": 1, "mutate": map[string]any{"kind": "set_field", "row": 0, "field": "prevHash", "value": "ab"}, "expect": "prev_hash_mismatch", "failsAtRow": 0},
			{"name": "version_2_unsupported", "chain": 1, "mutate": map[string]any{"kind": "set_field", "row": 1, "field": "hashVersion", "value": 2}, "expect": "unsupported_hash_version", "failsAtRow": 1},
			{"name": "raw_actor_edited", "chain": 0, "mutate": map[string]any{"kind": "set_field", "row": 1, "field": "actorId", "value": "agent_evil"}, "expect": "pseudonym_mismatch", "failsAtRow": 1},
			{"name": "org_moved_to_other_chain", "chain": 1, "mutate": map[string]any{"kind": "set_field", "row": 1, "field": "organizationId", "value": org1.String()}, "expect": "seq_gap", "failsAtRow": 1},
			{"name": "hash_edited", "chain": 2, "mutate": map[string]any{"kind": "set_field", "row": 0, "field": "hash", "value": "00"}, "expect": "hash_mismatch", "failsAtRow": 0},
			{"name": "malformed_missing_id", "chain": 2, "mutate": map[string]any{"kind": "set_field", "row": 1, "field": "id", "value": nil}, "expect": "malformed_row", "failsAtRow": 1},
		},
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
