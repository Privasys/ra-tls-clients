// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//go:build !ratls

// This file is compiled with standard Go (without the Privasys/go fork).
// App-to-app mutual RA-TLS requires the fork's
// tls.CertificateRequestInfo.RATLSChannelBinder, so EgressClientCert is a stub
// that returns an error.
//
// Build with: GOROOT=~/go-ratls go build -tags ratls

package ratls

import (
	"crypto/tls"
	"errors"
)

// EgressClientCert is unavailable without the Privasys/go fork: the caller
// cannot read the per-session channel binder, so it cannot mint a
// session-bound client identity. Build with -tags ratls and the fork.
func EgressClientCert(managerURL, containerToken string) (challenge []byte, getCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error), err error) {
	return nil, nil, errors.New("ratls: EgressClientCert requires the Privasys/go fork " +
		"(https://github.com/Privasys/go/tree/release-branch.go1.26); build with -tags ratls")
}
