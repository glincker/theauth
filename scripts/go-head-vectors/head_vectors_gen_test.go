package checkpoint

// Throwaway generator for packages/core/tests/fixtures/go-head-checkpoint-vectors.json in the
// TypeScript SDK repo. It is NOT part of theauth-go. Copy it into audit/checkpoint of a scratch copy
// of theauth-go (see README.md next to this file), then run:
//
//	GEN_OUT=/abs/path/go-head-checkpoint-vectors.json go test -run TestGenerateHeadVectors ./audit/checkpoint
//
// Heads are signed with the real headSignedBytes. Every expected result comes from the real
// VerifyHeadCheckpoint and CheckHeadCheckpoint, never from the TypeScript side.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/glincker/theauth-go/v2/internal/models"
	oklog "github.com/oklog/ulid/v2"
)

// RFC 8032 section 7.1 test 1 secret key (seed).
const rfc8032Seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

type vecExpected struct {
	Valid    bool   `json:"valid"`
	Reason   string `json:"reason,omitempty"`
	ChainKey string `json:"chainKey,omitempty"`
}

type vecRow struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	ChainSeq       int64  `json:"chainSeq"`
	Hash           string `json:"hash"`
}

type vecCase struct {
	Name     string          `json:"name"`
	Mode     string          `json:"mode"`
	Head     json.RawMessage `json:"head"`
	Rows     []vecRow        `json:"rows,omitempty"`
	Keys     []PublicKey     `json:"keys"`
	Expected vecExpected     `json:"expected"`
}

func hx(n int) string {
	const d = "0123456789abcdef"
	b := make([]byte, 64)
	for i := range b {
		b[i] = d[(n*7+i)%16]
	}
	return string(b)
}

func TestGenerateHeadVectors(t *testing.T) {
	out := os.Getenv("GEN_OUT")
	if out == "" {
		t.Skip("GEN_OUT not set")
	}
	seed, _ := hex.DecodeString(rfc8032Seed)
	priv := ed25519.NewKeyFromSeed(seed)
	signer, err := NewEd25519Signer(priv, "rfc8032-1")
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()
	otherSeed := make([]byte, 32)
	for i := range otherSeed {
		otherSeed[i] = byte(i)
	}
	other, _ := NewEd25519Signer(ed25519.NewKeyFromSeed(otherSeed), "other")
	orgA := oklog.MustParse("01JA0000000000000000000A00").String()
	orgB := oklog.MustParse("01JB0000000000000000000B00").String()

	sign := func(h HeadCheckpoint, s *Ed25519Signer) HeadCheckpoint {
		h.KeyID = s.KeyID()
		msg, err := headSignedBytes(h)
		if err != nil {
			t.Fatal(err)
		}
		sig, _ := s.Sign(msg)
		h.Signature = base64.RawURLEncoding.EncodeToString(sig)
		return h
	}
	base := func(heads ...ChainHead) HeadCheckpoint {
		return HeadCheckpoint{Version: 1, Alg: "Ed25519", Timestamp: 1760000000000, Heads: append([]ChainHead{}, heads...)}
	}
	rowsFor := func(chain string, from, to int, hashSeed int) []vecRow {
		var r []vecRow
		for s := from; s <= to; s++ {
			r = append(r, vecRow{ID: oklog.MustNew(uint64(1000+s), nil).String(), OrganizationID: chain, ChainSeq: int64(s), Hash: hx(hashSeed + s)})
		}
		return r
	}
	cat := func(parts ...[]vecRow) []vecRow {
		var r []vecRow
		for _, p := range parts {
			r = append(r, p...)
		}
		return r
	}
	toEvents := func(rows []vecRow) fakeEvents {
		ev := fakeEvents{}
		for _, r := range rows {
			e := models.AuditEvent{ChainSeq: uint64(r.ChainSeq), Hash: r.Hash}
			if r.OrganizationID != "" {
				id := oklog.MustParse(r.OrganizationID)
				e.OrganizationID = &id
			}
			ev = append(ev, e)
		}
		return ev
	}
	var cases []vecCase
	add := func(name string, h HeadCheckpoint, rows []vecRow, keys ...PublicKey) {
		raw, _ := json.Marshal(h)
		c := vecCase{Name: name, Head: raw, Rows: rows, Keys: keys}
		if rows == nil {
			c.Mode = "signature"
			o := VerifyHeadCheckpoint(h, keys...)
			c.Expected = vecExpected{Valid: o.Valid, Reason: string(o.Reason)}
		} else {
			c.Mode = "live"
			res, err := CheckHeadCheckpoint(context.Background(), toEvents(rows), h, keys...)
			if err != nil {
				t.Fatal(err)
			}
			c.Expected = vecExpected{Valid: res.Valid, Reason: string(res.Reason), ChainKey: res.ChainKey}
		}
		cases = append(cases, c)
	}
	glob := func(seq, n int) ChainHead { return ChainHead{ChainKey: "", Seq: int64(seq), Hash: hx(n + seq)} }
	org := func(k string, seq, n int) ChainHead {
		return ChainHead{ChainKey: k, Seq: int64(seq), Hash: hx(n + seq)}
	}

	good := sign(base(glob(3, 0), org(orgA, 2, 100), org(orgB, 4, 200)), signer)
	goodRows := cat(rowsFor("", 1, 3, 0), rowsFor(orgA, 1, 2, 100), rowsFor(orgB, 1, 4, 200))
	add("ok_three_chains", good, goodRows, pub)
	add("ok_signature_only", good, nil, pub)
	add("ok_rows_appended_after_signing", good, cat(goodRows, rowsFor("", 4, 6, 0), rowsFor(orgA, 3, 3, 100)), pub)
	add("ok_new_chain_after_signing", good, cat(goodRows, rowsFor("01JC0000000000000000000C00", 1, 2, 300)), pub)
	add("ok_empty_heads", sign(base(), signer), cat(rowsFor("", 1, 2, 0)), pub)
	add("ok_rotated_key_list", good, goodRows, other.PublicKey(), pub)
	big := sign(base(ChainHead{ChainKey: "", Seq: 9007199254740991, Hash: hx(9)}), signer)
	add("ok_max_safe_seq_signature_only", big, nil, pub)

	add("chain_truncated_tail_cut", good, cat(rowsFor("", 1, 2, 0), rowsFor(orgA, 1, 2, 100), rowsFor(orgB, 1, 4, 200)), pub)
	add("chain_truncated_org_chain_missing", good, cat(rowsFor("", 1, 3, 0), rowsFor(orgA, 1, 2, 100)), pub)
	add("chain_truncated_no_rows_at_all", good, []vecRow{}, pub)
	add("chain_truncated_second_chain_reported", good, cat(rowsFor("", 1, 3, 0), rowsFor(orgA, 1, 1, 100), rowsFor(orgB, 1, 4, 200)), pub)
	rewritten := cat(rowsFor("", 1, 3, 0), rowsFor(orgA, 1, 2, 100), rowsFor(orgB, 1, 4, 200))
	rewritten[0].Hash = hx(77)
	rewritten[2].Hash = hx(78)
	add("head_mismatch_rewritten_tail", good, rewritten, pub)
	add("head_mismatch_seq_skipped", good, cat(rowsFor("", 1, 2, 0), rowsFor("", 4, 4, 0), rowsFor(orgA, 1, 2, 100), rowsFor(orgB, 1, 4, 200)), pub)

	tamper := good
	tamper.Heads = append([]ChainHead(nil), good.Heads...)
	tamper.Heads[0].Seq = 2
	add("bad_signature_head_edited", tamper, goodRows, pub)
	add("bad_signature_wrong_key", sign(base(glob(1, 0)), other), nil, PublicKey{KeyID: "other", PublicKey: pub.PublicKey})
	add("unknown_key", sign(base(glob(1, 0)), other), nil, pub)
	alg := good
	alg.Alg = "RS256"
	add("unsupported_alg", alg, nil, pub)
	ver := base(glob(1, 0))
	ver.Version = 2
	add("malformed_version_2", sign(ver, signer), nil, pub)
	add("malformed_seq_zero", sign(base(ChainHead{Seq: 0, Hash: hx(1)}), signer), nil, pub)
	add("malformed_uppercase_hash", sign(base(ChainHead{Seq: 1, Hash: "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"}), signer), nil, pub)
	add("malformed_unsorted_heads", sign(base(org(orgB, 1, 0), org(orgA, 1, 1)), signer), nil, pub)
	add("malformed_duplicate_chain", sign(base(org(orgA, 1, 0), org(orgA, 2, 1)), signer), nil, pub)
	// Go sorts chain keys by UTF-8 bytes: U+FFFF (ef bf bf) sorts before U+1F600 (f0 9f 98 80),
	// the opposite of UTF-16 code unit order.
	add("ok_utf8_byte_order_of_keys", sign(base(org("￿", 1, 0), org("\U0001F600", 1, 1)), signer), nil, pub)
	add("malformed_utf16_order_of_keys", sign(base(org("\U0001F600", 1, 0), org("￿", 1, 1)), signer), nil, pub)
	nonce := good
	nonce.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	add("bad_signature_zero_signature", nonce, nil, pub)

	doc := map[string]any{
		"producer": "theauth-go audit/checkpoint HeadCheckpoint (headSignDomain theauth.audit.head.v1)",
		"note":     "Signed with the RFC 8032 section 7.1 test 1 secret key. Expected results come from the Go VerifyHeadCheckpoint and CheckHeadCheckpoint.",
		"keyId":    "rfc8032-1",
		"cases":    cases,
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
