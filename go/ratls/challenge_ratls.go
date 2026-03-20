// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//go:build ratls

// This file is compiled only with the Privasys/go fork which adds
// tls.Config.RATLSChallenge for sending a challenge nonce in ClientHello.
//
// Build with:
//   GOROOT=~/go-ratls go build -tags ratls

package ratls

import "crypto/tls"

// setRATLSChallenge sets the RA-TLS challenge nonce on the TLS config.
// The nonce will be sent as TLS extension 0xFFBB in the ClientHello.
func setRATLSChallenge(config *tls.Config, nonce []byte) error {
	config.RATLSChallenge = nonce
	return nil
}
