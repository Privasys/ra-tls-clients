// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//go:build !ratls

// This file is compiled with standard Go (without the Privasys/go fork).
// Challenge support is not available — calling Connect with a non-empty
// Options.Challenge will panic.

package ratls

import "crypto/tls"

// setRATLSChallenge panics because the RA-TLS challenge extension requires
// the Privasys/go fork (https://github.com/Privasys/go/tree/ratls).
//
// Build with: GOROOT=~/go-ratls go build -tags ratls
func setRATLSChallenge(_ *tls.Config, _ []byte) {
	panic("ratls: ClientHello challenge requires the Privasys/go fork; " +
		"build with GOROOT=~/go-ratls and -tags ratls")
}
