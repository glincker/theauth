package checkpoint

// Throwaway generator for packages/core/tests/fixtures/go-e2e-head-vectors.json in the TypeScript
// SDK repo. It is NOT part of theauth-go. Copy it into audit/checkpoint of a scratch copy of
// theauth-go (see README.md next to this file), then run:
//
//	GEN_OUT=/abs/go-e2e-head-vectors.json go test -count=1 -run TestGenerateE2EVectors ./audit/checkpoint
//
// It writes real chains with the real BuildChainEntryWith (stable and rotating pseudonyms, one
// erased row, one shredded period), signs the heads with the real CreateHeadCheckpoint, and records
// what the real VerifyChainRowsKeys and CheckHeadCheckpoint say. The TypeScript test then runs
// verifyGoAuditChain and verifyGoHeadCheckpoint over the same exported rows.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/models"
	oklog "github.com/oklog/ulid/v2"
)

const (
	e2eSeed   = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	e2eStable = "0123456789abcdef0123456789abcdef"
)

func e2eID(prefix string, n int) oklog.ULID {
	u, err := oklog.Parse(fmt.Sprintf("%s%022d", prefix, n))
	if err != nil {
		panic(err)
	}
	return u
}

type e2eExpected struct {
	Valid    bool   `json:"valid"`
	Reason   string `json:"reason,omitempty"`
	ChainKey string `json:"chainKey,omitempty"`
}

type e2eChain struct {
	key    string
	events []models.AuditEvent
	rows   []map[string]any
}

func TestGenerateE2EVectors(t *testing.T) {
	out := os.Getenv("GEN_OUT")
	if out == "" {
		t.Skip("GEN_OUT not set")
	}
	stable := []byte(e2eStable)
	// Three daily periods. Period secrets are distinct 32 byte values. The oldest is shredded.
	day := time.Date(2025, 10, 9, 8, 0, 0, 0, time.UTC)
	p0 := audit.PeriodOf(day, 1)
	secrets := map[int64][]byte{}
	for i := int64(0); i < 3; i++ {
		b := make([]byte, 32)
		for j := range b {
			b[j] = byte(int(i)*40 + j + 1)
		}
		secrets[p0+i] = b
	}
	rot := audit.Pseudonymizer{Stable: stable, Rotation: &audit.Rotation{PeriodDays: 1}, Periods: secrets}
	plain := audit.Pseudonymizer{Stable: stable}

	org1, org2 := e2eID("01JC", 1), e2eID("01JC", 2)
	mk := func(n int, org *models.ULID, action string, offsetHours int, subj, actor string) models.AuditEvent {
		return models.AuditEvent{ID: e2eID("01JB", n), OrganizationID: org, Action: action, SubjectID: subj, ActorID: actor,
			CreatedAt: day.Add(time.Duration(offsetHours)*time.Hour + time.Duration(n)*time.Microsecond)}
	}
	u1 := e2eID("01JD", 1)
	build := func(name string, evs []models.AuditEvent, ps func(i int) audit.Pseudonymizer, erase map[int]bool) e2eChain {
		c := e2eChain{key: audit.ChainKey(evs[0])}
		head := audit.ChainHead{}
		var rows []audit.ChainRow
		for i, e := range evs {
			entry, err := audit.BuildChainEntryWith(e, ps(i), head)
			if err != nil {
				t.Fatal(err)
			}
			e.ChainSeq, e.PrevHash, e.Hash = uint64(entry.Payload.Seq), entry.Payload.Prev, entry.Hash
			raw := e
			if erase[i] {
				raw.ActorUserID, raw.SubjectID, raw.ActorID, raw.ApproverID = nil, "", "", ""
			}
			js, _ := json.Marshal(raw)
			m := map[string]any{}
			_ = json.Unmarshal(js, &m)
			m["actorUserPseudonym"] = entry.Payload.ActorUserPseudo
			m["subjectPseudonym"] = entry.Payload.SubjectPseudo
			m["actorPseudonym"] = entry.Payload.ActorPseudo
			m["approverPseudonym"] = entry.Payload.ApproverPseudo
			c.rows = append(c.rows, m)
			c.events = append(c.events, e)
			cr := audit.ChainRow{Payload: entry.Payload, Hash: entry.Hash, RawSubject: raw.SubjectID, RawActor: raw.ActorID, RawOrg: c.key}
			if raw.ActorUserID != nil {
				cr.RawActorUser = raw.ActorUserID.String()
			}
			rows = append(rows, cr)
			head = audit.ChainHead{Seq: entry.Payload.Seq, Hash: entry.Hash}
		}
		i := 0
		res, err := audit.VerifyChainRowsKeys(func() (audit.ChainRow, bool, error) {
			if i >= len(rows) {
				return audit.ChainRow{}, false, nil
			}
			i++
			return rows[i-1], true, nil
		}, audit.PseudonymKeys{Stable: stable, Periods: secrets}, 0)
		if err != nil || !res.OK {
			t.Fatalf("go verifier rejected %s: %+v %v", name, res, err)
		}
		return c
	}
	// org1: seq 1 written before rotation (stable pseudonym), then rotated rows in 3 periods, row 5 erased.
	e1 := []models.AuditEvent{
		mk(1, &org1, "agent.created", 0, "user_1", "agent_a"),
		mk(2, &org1, "agent.authorize", 1, "user_1", "agent_a"),
		mk(3, &org1, "agent.authorize", 25, "user_2", "agent_a"),
		mk(4, &org1, "tool_approval.approved", 26, "user_2", "agent_b"),
		mk(5, &org1, "agent.authorize", 50, "user_3", "agent_c"),
		mk(6, &org1, "agent.revoked", 51, "user_3", "agent_c"),
	}
	e1[3].ApproverID = "user_9"
	e1[1].ActorUserID = &u1
	c1 := build("org1", e1, func(i int) audit.Pseudonymizer {
		if i == 0 {
			return plain
		}
		return rot
	}, map[int]bool{4: true})
	// org2: all stable.
	e2 := []models.AuditEvent{
		mk(11, &org2, "agent.created", 2, "user_7", "agent_x"),
		mk(12, &org2, "agent.authorize", 3, "user_7", "agent_x"),
		mk(13, &org2, "agent.revoked", 4, "user_7", "agent_x"),
	}
	c2 := build("org2", e2, func(int) audit.Pseudonymizer { return plain }, nil)
	// global chain: all rotated, period 2.
	e3 := []models.AuditEvent{
		mk(21, nil, "audit.events_dropped", 49, "", "agent_g"),
		mk(22, nil, "agent.created", 50, "user_5", "agent_g"),
	}
	c3 := build("global", e3, func(int) audit.Pseudonymizer { return rot }, nil)
	chains := []e2eChain{c1, c2, c3}

	seed, _ := hex.DecodeString(e2eSeed)
	signer, err := NewEd25519Signer(ed25519.NewKeyFromSeed(seed), "rfc8032-1")
	if err != nil {
		t.Fatal(err)
	}
	var all fakeEvents
	for _, c := range chains {
		all = append(all, c.events...)
	}
	ctx := context.Background()
	head, err := CreateHeadCheckpoint(ctx, all, HeadOptions{Signer: signer, Now: time.UnixMilli(1760000000000)})
	if err != nil {
		t.Fatal(err)
	}
	keys := []PublicKey{signer.PublicKey()}

	type cut struct {
		Name     string           `json:"name"`
		Keep     map[string]int64 `json:"keep"`
		Expected e2eExpected      `json:"expected"`
	}
	headCut := func(name string, keep map[string]int64) cut {
		var evs fakeEvents
		for _, e := range all {
			if k, ok := keep[audit.ChainKey(e)]; ok && int64(e.ChainSeq) <= k {
				evs = append(evs, e)
			}
		}
		res, err := CheckHeadCheckpoint(ctx, evs, head, keys...)
		if err != nil {
			t.Fatal(err)
		}
		return cut{Name: name, Keep: keep, Expected: e2eExpected{Valid: res.Valid, Reason: string(res.Reason), ChainKey: res.ChainKey}}
	}
	full := map[string]int64{c1.key: 6, c2.key: 3, c3.key: 2}
	cuts := []cut{
		headCut("full", full),
		headCut("org1_tail_cut", map[string]int64{c1.key: 5, c2.key: 3, c3.key: 2}),
		headCut("global_tail_cut", map[string]int64{c1.key: 6, c2.key: 3, c3.key: 1}),
		headCut("org2_chain_missing", map[string]int64{c1.key: 6, c3.key: 2}),
	}
	periods := map[string]string{}
	for p, s := range secrets {
		periods[strconv.FormatInt(p, 10)] = hex.EncodeToString(s)
	}
	doc := map[string]any{
		"producer":           "theauth-go internal/audit BuildChainEntryWith + audit/checkpoint CreateHeadCheckpoint",
		"pseudonymSecretHex": hex.EncodeToString(stable),
		"periodSecretsHex":   periods,
		"shreddedPeriod":     strconv.FormatInt(p0, 10),
		"keys":               keys,
		"head":               head,
		"chains":             []any{map[string]any{"chainKey": c1.key, "rows": c1.rows}, map[string]any{"chainKey": c2.key, "rows": c2.rows}, map[string]any{"chainKey": c3.key, "rows": c3.rows}},
		"cuts":               cuts,
	}
	b, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
