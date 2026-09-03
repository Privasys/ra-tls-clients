// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// test_challenge connects to an RA-TLS v2 server in challenge mode: after the
// handshake it requests evidence bound to this connection's TLS exporter and a
// fresh context, verifies report_data against the leaf key, optionally verifies
// the quote via an attestation server, and sends a health probe over the
// attested connection.
//
// Build:
//
//	go build -o test_challenge ./cmd/test_challenge
//
// Run:
//
//	./test_challenge <host> <port> [--attestation-server-url <url>] [--attestation-server-bearer-token <token>]
//	./test_challenge 127.0.0.1 8443
//	./test_challenge 127.0.0.1 8443 --attestation-server-url https://as.privasys.org --attestation-server-bearer-token eyJ...
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"enclave-os-mini/clients/go/ratls"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <host> <port> [--attestation-server-url <url>] [--attestation-server-bearer-token <token>]\n", os.Args[0])
		os.Exit(1)
	}
	host := os.Args[1]
	port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid port: %s\n", os.Args[2])
		os.Exit(1)
	}

	// Parse optional flags
	var attestationURL, attestationToken string
	for i := 3; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--attestation-server-url":
			if i+1 < len(os.Args) {
				attestationURL = os.Args[i+1]
				i++
			}
		case "--attestation-server-bearer-token":
			if i+1 < len(os.Args) {
				attestationToken = os.Args[i+1]
				i++
			}
		}
	}

	// Connect in challenge mode: the evidence exchange runs inside Connect.
	fmt.Printf("[*] Connecting to %s:%d with RA-TLS v2 challenge attestation...\n", host, port)
	client, err := ratls.Connect(host, port, &ratls.Options{
		Attestation: ratls.AttestationChallenge,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()
	fmt.Println("[+] TLS handshake and evidence exchange complete.")

	ev := client.Evidence()
	fmt.Printf("[*] Context : %s\n", hex.EncodeToString(ev.Context))
	fmt.Printf("[*] Evidence: %s, %d-byte quote, quote_time %s\n", ev.TEE, len(ev.Quote), ev.QuoteTimeRaw)

	// Inspect certificate
	fmt.Println("\n=== Server Certificate ===")
	info := client.InspectCert()
	ratls.PrintCertInfo(info)

	// TEE family from the evidence
	tee := ratls.TeeTypeSGX
	if strings.HasPrefix(ev.TEE, "tdx") {
		tee = ratls.TeeTypeTDX
	}

	// Build verification policy
	policy := &ratls.VerificationPolicy{
		TEE: tee,
	}

	// Optional quote verification
	if attestationURL != "" {
		fmt.Println("\n=== Quote Verification ===")
		fmt.Printf("[*] Endpoint: %s\n", attestationURL)
		policy.QuoteVerification = &ratls.QuoteVerificationConfig{
			Endpoint:    attestationURL,
			Token:       attestationToken,
			TimeoutSecs: 30,
		}
	}

	// Verify
	fmt.Println("\n=== Verification ===")
	verified, err := client.VerifyCertificate(policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] RA-TLS verification FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] RA-TLS verification PASSED (evidence bound to this connection's exporter)")

	if verified.QuoteVerification != nil {
		qv := verified.QuoteVerification
		fmt.Printf("[+] Quote verification: %s\n", qv.Status)
		if qv.TcbDate != "" {
			fmt.Printf("    TCB Date   : %s\n", qv.TcbDate)
		}
		if len(qv.AdvisoryIDs) > 0 {
			fmt.Printf("    Advisories : %s\n", strings.Join(qv.AdvisoryIDs, ", "))
		}
	}

	// Ping test
	fmt.Println("\n=== Ping Test ===")
	ok, err := client.Ping()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Ping failed: %v\n", err)
		os.Exit(1)
	}
	if ok {
		fmt.Println("[+] Ping -> Pong OK")
	} else {
		fmt.Println("[-] Ping: unexpected response")
		os.Exit(1)
	}

	fmt.Println("\n[+] All tests PASSED.")
}
