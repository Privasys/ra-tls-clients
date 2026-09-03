package ratls

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"os"
)

// Privasys fleet trust anchors.
//
// Every enclave enrolled on the Privasys platform serves an RA-TLS leaf
// certificate issued by the Privasys Intermediate CA of its environment
// (production or development), which is staged into the enclave at
// approval time. Requiring the presented chain to reach one of these
// anchors confines acceptance to enclaves Privasys provisioned: a genuine
// TEE elsewhere running the same measured image, or one whose attestation
// key has leaked, cannot present a leaf that chains here. The quote checks
// (measurements, OIDs, ReportData, channel binder) are unchanged; the
// chain check is a fleet-membership check layered on top of them.
//
// Hostname verification is deliberately not part of the chain check:
// RA-TLS peers are commonly dialled by IP, and the identity a relying party
// cares about is the quote and the app identity in the certificate, not the
// DNS name.

//go:embed anchors/privasys-intermediate-ca.pem
var privasysIntermediateCAPEM []byte

//go:embed anchors/privasys-intermediate-ca-dev.pem
var privasysIntermediateCADevPEM []byte

// PrivasysTrustAnchors returns the embedded Privasys production and
// development intermediate CA certificates.
func PrivasysTrustAnchors() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, p := range [][]byte{privasysIntermediateCAPEM, privasysIntermediateCADevPEM} {
		if !pool.AppendCertsFromPEM(p) {
			return nil, fmt.Errorf("embedded Privasys trust anchor is not a valid PEM certificate")
		}
	}
	return pool, nil
}

// trustAnchorsFromFile loads every certificate in a PEM file as a trust
// anchor (a root or an intermediate CA).
func trustAnchorsFromFile(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	n := 0
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse CA cert: %w", err)
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("no PEM certificate in CA cert file %s", path)
	}
	return pool, nil
}

// verifyFleetChain returns a VerifyPeerCertificate callback that requires
// the presented certificate chain to reach one of the trust anchors,
// without hostname verification. It is used with InsecureSkipVerify=true,
// which only disables the standard library's own verification so that this
// callback can perform the chain check instead.
func verifyFleetChain(anchors *x509.CertPool) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("RA-TLS: server presented no certificate")
		}
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for i, raw := range rawCerts {
			c, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("RA-TLS: parse peer certificate %d: %w", i, err)
			}
			certs = append(certs, c)
		}
		intermediates := x509.NewCertPool()
		for _, c := range certs[1:] {
			intermediates.AddCert(c)
		}
		_, err := certs[0].Verify(x509.VerifyOptions{
			Roots:         anchors,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			return fmt.Errorf("RA-TLS: certificate chain does not reach a trusted Privasys fleet anchor: %w", err)
		}
		return nil
	}
}
