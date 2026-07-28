// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package ratls

import "crypto/tls"

// SetClientHelloChallenge arms challenge-mode RA-TLS on a caller-built
// tls.Config: the nonce travels in the ClientHello as extension 0xFFBB, the
// enclave binds it (together with the session channel binder) into the quote's
// report_data, and both peers derive the binder from the TLS 1.3 key schedule.
//
// Connect() does this for callers that can use it. This exists for the ones
// that cannot: a client needing its own net.Conn — an http.Transport with a
// custom DialTLSContext, for instance — has to build the tls.Config itself,
// and previously had no way to reach the fork field. Without the challenge the
// server derives NO binder, so a callee running ingress mutual RA-TLS rejects
// the connection ("missing or undecodable channel binder") and any attempt to
// mint an egress client certificate fails for want of one.
//
// Returns an error on a build without the Privasys Go fork, where the
// extension does not exist. Callers must treat that as fatal rather than
// dialling on: a connection without the challenge cannot satisfy
// ReportDataChallengeResponse verification.
//
// Pair it with ChannelBinder() after the handshake and verify with
// VerifyRaTlsCertBound(cert, policy{ReportData: ReportDataChallengeResponse,
// Nonce: nonce}, binder).
func SetClientHelloChallenge(config *tls.Config, nonce []byte) error {
	return setRATLSChallenge(config, nonce)
}

// ChannelBinder returns the 32-byte RA-TLS channel binder a completed TLS 1.3
// handshake derived, or nil when unavailable (TLS 1.2, no fork, or the peer
// never drove the RA-TLS extension).
//
// This is the binder to pass to VerifyRaTlsCertBound so a relayed or
// co-located quote — one that cannot commit to THIS session — fails closed.
// (*Client).ChannelBinder() is the same value for Connect-based callers.
func ChannelBinder(conn *tls.Conn) []byte {
	if conn == nil {
		return nil
	}
	return getRATLSChannelBinder(conn)
}
