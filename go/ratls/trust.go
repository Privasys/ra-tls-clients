package ratls

import (
	"crypto/x509"
	"fmt"
)

// TrustSelection chooses which anchors the server chain must reach.
//
// An attested connection (deterministic or challenge mode) must chain to the
// Privasys fleet anchors, or to the certificates in Options.CACertPath: the
// evidence proves the key, the chain proves the key was minted for a member of
// the fleet, and a valid public-PKI certificate for the same name (the
// gateway's terminate path, or any CA) must not be able to stand in. A
// connection that asks for no evidence (AttestationNone) is an ordinary TLS
// connection as far as the chain is concerned: hosts that are not enclaves,
// such as the identity provider, present public-PKI certificates and never
// chain to the fleet.
type TrustSelection int

const (
	// TrustAuto (the zero value): fleet anchors for attested modes; for
	// AttestationNone the chain is accepted when it reaches the fleet anchors
	// (no hostname check, as for enclaves) or verifies against the system
	// roots with hostname verification.
	TrustAuto TrustSelection = iota
	// TrustFleet forces the fleet anchors (or CACertPath) in every mode.
	TrustFleet
	// TrustPublic forces the system roots with hostname verification. It is
	// refused together with an attested mode.
	TrustPublic
)

func (t TrustSelection) String() string {
	switch t {
	case TrustFleet:
		return "fleet"
	case TrustPublic:
		return "public"
	default:
		return "auto"
	}
}

// resolveTrust turns the options into the effective chain policy: whether
// the fleet anchors are accepted and whether the public PKI is accepted.
func resolveTrust(opts *Options) (fleet, public bool, err error) {
	switch opts.Trust {
	case TrustFleet:
		return true, false, nil
	case TrustPublic:
		if opts.Attestation != AttestationNone {
			return false, false, fmt.Errorf("ratls: Trust=public is only valid with Attestation=none (an attested connection must chain to the fleet)")
		}
		return false, true, nil
	default:
		if opts.Attestation == AttestationNone && opts.CACertPath == "" {
			return true, true, nil
		}
		return true, false, nil
	}
}

// verifyServerChain returns the VerifyPeerCertificate callback for the
// resolved trust: the fleet check (no hostname), the public-PKI check (system
// roots, hostname = serverName), or either.
func verifyServerChain(fleetAnchors *x509.CertPool, acceptFleet, acceptPublic bool, serverName string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	fleetCheck := verifyFleetChain(fleetAnchors)
	return func(rawCerts [][]byte, verified [][]*x509.Certificate) error {
		var fleetErr error
		if acceptFleet {
			if fleetErr = fleetCheck(rawCerts, verified); fleetErr == nil {
				return nil
			}
			if !acceptPublic {
				return fleetErr
			}
		}
		if err := verifyPublicChain(rawCerts, serverName); err != nil {
			if fleetErr != nil {
				return fmt.Errorf("%w; and %v", fleetErr, err)
			}
			return err
		}
		return nil
	}
}

// verifyPublicChain verifies the presented chain against the system roots
// with hostname verification, as the standard library would.
func verifyPublicChain(rawCerts [][]byte, serverName string) error {
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
		Intermediates: intermediates,
		DNSName:       serverName,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("RA-TLS: certificate chain does not verify against the public PKI for %q: %w", serverName, err)
	}
	return nil
}
