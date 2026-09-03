package ratls

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"hash"
	"os"
	"path/filepath"
	"testing"
)

// The exporter vectors pin the RFC 8446 section 7.5 computation for the RA-TLS
// v2 labels, independently of any TLS stack: a stack that returns the expected
// hctx for the recorded exporter_master_secret derives the same binding as
// every other SDK. The values were produced by OpenSSL and Go crypto/tls on a
// live connection (see the description in the file).
type exporterVector struct {
	Name                 string `json:"name"`
	Hash                 string `json:"hash"`
	ExporterMasterSecret string `json:"exporter_master_secret"`
	Label                string `json:"label"`
	Context              string `json:"context"`
	Length               int    `json:"length"`
	Hctx                 string `json:"hctx"`
	ClientLabel          string `json:"client_label"`
	ClientHctx           string `json:"client_hctx"`
}

// hkdfExpandLabel is HKDF-Expand-Label from RFC 8446 section 7.1.
func hkdfExpandLabel(h func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1+len(context))
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	// HKDF-Expand with a single or several blocks.
	var out, prev []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(h, secret)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{counter})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

// tlsExporter is the RFC 8446 section 7.5 exporter:
// HKDF-Expand-Label(Derive-Secret(secret, label, ""), "exporter", Hash(context), length).
func tlsExporter(h func() hash.Hash, ems []byte, label string, context []byte, length int) []byte {
	empty := h()
	derived := hkdfExpandLabel(h, ems, label, empty.Sum(nil), empty.Size())
	ctxHash := h()
	ctxHash.Write(context)
	return hkdfExpandLabel(h, derived, "exporter", ctxHash.Sum(nil), length)
}

func TestExporterVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "ratls-v2", "exporter.json"))
	if err != nil {
		t.Fatalf("read exporter vectors: %v", err)
	}
	var file struct {
		Vectors []exporterVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse exporter vectors: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no exporter vectors")
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var h func() hash.Hash
			switch v.Hash {
			case "sha256":
				h = sha256.New
			case "sha384":
				h = sha512.New384
			default:
				t.Fatalf("unknown hash %q", v.Hash)
			}
			if v.Label != ExporterLabelServer || v.ClientLabel != ExporterLabelClient {
				t.Fatalf("vector labels %q/%q do not match the SDK labels", v.Label, v.ClientLabel)
			}
			ems := mustHex(t, v.ExporterMasterSecret)
			ctx := mustHex(t, v.Context)
			if got := hex.EncodeToString(tlsExporter(h, ems, v.Label, ctx, v.Length)); got != v.Hctx {
				t.Fatalf("server hctx = %s, want %s", got, v.Hctx)
			}
			if got := hex.EncodeToString(tlsExporter(h, ems, v.ClientLabel, ctx, v.Length)); got != v.ClientHctx {
				t.Fatalf("client hctx = %s, want %s", got, v.ClientHctx)
			}
		})
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}
