package ratls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func testLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "enclave.example.invalid"},
		DNSNames:     []string{"enclave.example.invalid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestPrivasysTrustAnchorsAreTwoCertificates(t *testing.T) {
	n := 0
	for _, p := range [][]byte{privasysIntermediateCAPEM, privasysIntermediateCADevPEM} {
		block, _ := pem.Decode(p)
		if block == nil {
			t.Fatal("embedded anchor is not PEM")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if !c.IsCA {
			t.Fatalf("embedded anchor %q is not a CA certificate", c.Subject.CommonName)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("expected 2 embedded anchors, got %d", n)
	}
	if _, err := PrivasysTrustAnchors(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFleetChainRejectsForeignCA(t *testing.T) {
	ca, key := testCA(t, "Not Privasys CA")
	leaf := testLeaf(t, ca, key)
	anchors, err := PrivasysTrustAnchors()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFleetChain(anchors)([][]byte{leaf, ca.Raw}, nil); err == nil {
		t.Fatal("a chain to a foreign CA must be rejected by the Privasys anchors")
	}
}

func TestVerifyFleetChainAcceptsCustomAnchorWithoutHostname(t *testing.T) {
	ca, key := testCA(t, "Customer CA")
	leaf := testLeaf(t, ca, key)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	anchors, err := trustAnchorsFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The leaf names enclave.example.invalid; the chain check must pass
	// regardless of the dialled name, and must not need the CA in the
	// presented chain when it is an anchor.
	if err := verifyFleetChain(anchors)([][]byte{leaf}, nil); err != nil {
		t.Fatalf("custom anchor chain should verify: %v", err)
	}
	if err := verifyFleetChain(anchors)(nil, nil); err == nil {
		t.Fatal("an empty chain must be rejected")
	}
}
