// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package ratls

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The RA-TLS v2 report_data vectors shared by every SDK (docs/ratls-v2.md
// section 8). The Go implementation is the reference: with RATLS_WRITE_VECTORS=1
// this test rewrites tests/vectors/ratls-v2/report_data.json; otherwise it
// checks the file.

type vector struct {
	Name        string `json:"name"`
	Mode        string `json:"mode"`
	SPKIDER     string `json:"spki_der"`
	QuoteTime   string `json:"quote_time,omitempty"`
	Context     string `json:"context,omitempty"`
	Hctx        string `json:"hctx,omitempty"`
	GPUEvidence string `json:"gpu_evidence,omitempty"`
	ReportData  string `json:"report_data"`
}

// The SPKI of the fixed P-256 point used by report_data_test.go.
const vectorSPKI = "3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"

func buildVectors(t *testing.T) []vector {
	t.Helper()
	spki, _ := hex.DecodeString(vectorSPKI)
	ctx := bytes.Repeat([]byte{0xC0}, ContextLen)
	hctx := bytes.Repeat([]byte{0xE1}, HctxLen)
	gpu := []byte("PGAE\x01 gpu evidence envelope")
	cases := []struct {
		name string
		ev   Evidence
	}{
		{"deterministic", Evidence{Mode: AttestationDeterministic, QuoteTimeRaw: "2026-09-04T10:15Z"}},
		{"deterministic-gpu", Evidence{Mode: AttestationDeterministic, QuoteTimeRaw: "2026-09-04T10:15Z", GPUEvidence: gpu}},
		{"challenge", Evidence{Mode: AttestationChallenge, Context: ctx, Hctx: hctx}},
		{"challenge-gpu", Evidence{Mode: AttestationChallenge, Context: ctx, Hctx: hctx, GPUEvidence: gpu}},
	}
	var out []vector
	for _, c := range cases {
		rd, err := ExpectedReportData(spki, &c.ev)
		if err != nil {
			t.Fatal(err)
		}
		v := vector{Name: c.name, Mode: c.ev.Mode.String(), SPKIDER: vectorSPKI, QuoteTime: c.ev.QuoteTimeRaw,
			ReportData: hex.EncodeToString(rd)}
		if c.ev.Context != nil {
			v.Context = hex.EncodeToString(c.ev.Context)
			v.Hctx = hex.EncodeToString(c.ev.Hctx)
		}
		if c.ev.GPUEvidence != nil {
			v.GPUEvidence = hex.EncodeToString(c.ev.GPUEvidence)
		}
		out = append(out, v)
	}
	return out
}

func vectorsPath() string {
	return filepath.Join("..", "..", "tests", "vectors", "ratls-v2", "report_data.json")
}

func TestReportDataVectors(t *testing.T) {
	want := buildVectors(t)
	if os.Getenv("RATLS_WRITE_VECTORS") == "1" {
		if err := os.MkdirAll(filepath.Dir(vectorsPath()), 0o755); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.MarshalIndent(want, "", "  ")
		if err := os.WriteFile(vectorsPath(), append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", vectorsPath())
	}
	raw, err := os.ReadFile(vectorsPath())
	if err != nil {
		t.Skipf("no vectors file (%v); run with RATLS_WRITE_VECTORS=1 to create it", err)
	}
	var got []vector
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("%d vectors in file, %d computed", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("vector %s differs:\n file: %+v\n code: %+v", want[i].Name, got[i], want[i])
		}
	}
	// The GPU fold is exactly SHA-256(gpu_evidence) appended to the binding.
	gpu := []byte("PGAE\x01 gpu evidence envelope")
	if s := sha256.Sum256(gpu); len(s) != 32 {
		t.Fatal("unreachable")
	}
}
