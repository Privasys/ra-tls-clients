package ratls

import (
	"crypto/x509"
	"strings"
	"testing"
)

func TestResolveTrust(t *testing.T) {
	cases := []struct {
		name          string
		opts          Options
		fleet, public bool
		wantErr       bool
	}{
		{"auto attested", Options{}, true, false, false},
		{"auto none", Options{Attestation: AttestationNone}, true, true, false},
		{"auto none with CA", Options{Attestation: AttestationNone, CACertPath: "x.pem"}, true, true, false},
		{"fleet none", Options{Attestation: AttestationNone, Trust: TrustFleet}, true, false, false},
		{"public none", Options{Attestation: AttestationNone, Trust: TrustPublic}, false, true, false},
		{"public attested", Options{Trust: TrustPublic}, false, false, true},
	}
	for _, c := range cases {
		fleet, public, err := resolveTrust(&c.opts)
		if (err != nil) != c.wantErr {
			t.Fatalf("%s: err = %v", c.name, err)
		}
		if err == nil && (fleet != c.fleet || public != c.public) {
			t.Fatalf("%s: fleet=%v public=%v", c.name, fleet, public)
		}
	}
}

func TestVerifyServerChainFleetOrPublic(t *testing.T) {
	ca, caKey := testCA(t, "Test Fleet CA")
	leaf := testLeaf(t, ca, caKey)
	anchors := x509.NewCertPool()
	anchors.AddCert(ca)
	foreignCA, foreignKey := testCA(t, "Foreign CA")
	foreign := testLeaf(t, foreignCA, foreignKey)

	// A fleet leaf passes whether or not the public PKI is also accepted.
	for _, public := range []bool{false, true} {
		if err := verifyServerChain(anchors, true, public, "example.invalid")([][]byte{leaf, ca.Raw}, nil); err != nil {
			t.Fatalf("fleet leaf rejected (public=%v): %v", public, err)
		}
	}
	// A foreign leaf fails the fleet-only policy and, since no public root
	// signs it either, the either policy too; the error names both checks.
	if err := verifyServerChain(anchors, true, false, "example.invalid")([][]byte{foreign, foreignCA.Raw}, nil); err == nil {
		t.Fatal("foreign leaf accepted by the fleet-only policy")
	}
	err := verifyServerChain(anchors, true, true, "example.invalid")([][]byte{foreign, foreignCA.Raw}, nil)
	if err == nil || !strings.Contains(err.Error(), "fleet anchor") || !strings.Contains(err.Error(), "public PKI") {
		t.Fatalf("either policy: unexpected error %v", err)
	}
	// Public-only never accepts a fleet leaf.
	if err := verifyServerChain(anchors, false, true, "example.invalid")([][]byte{leaf, ca.Raw}, nil); err == nil {
		t.Fatal("fleet leaf accepted by the public-only policy")
	}
}
