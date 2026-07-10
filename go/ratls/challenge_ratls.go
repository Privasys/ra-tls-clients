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

// getRATLSChannelBinder returns the 32-byte RA-TLS channel binder this client
// derived from the shared TLS 1.3 handshake key schedule. Challenge-mode
// verification folds it into the expected report_data so the attestation is
// bound to this exact TLS session.
func getRATLSChannelBinder(conn *tls.Conn) []byte {
	return conn.ConnectionState().RATLSChannelBinder
}
