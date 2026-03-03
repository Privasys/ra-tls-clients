// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// test_challenge connects to an RA-TLS server with a random challenge nonce
// in the TLS ClientHello (extension 0xFFBB), inspects the server certificate,
// verifies that the ReportData binds the certificate's public key to the
// challenge nonce, optionally verifies the raw quote via a DCAP verification
// service, and sends a Ping to confirm application-level connectivity.
//
// Requires the Privasys/go fork (https://github.com/Privasys/go/tree/ratls).
//
// Build:
//
//	GOROOT=~/go-ratls go build -tags ratls -o test_challenge ./cmd/test_challenge
//
// Run:
//
//	./test_challenge <host> <port> [--dcap-url <url>] [--dcap-key <jwt>]
//	./test_challenge 127.0.0.1 8443
//	./test_challenge 127.0.0.1 8443 --dcap-url https://gcp-lon-1.dcap.privasys.org/api/verify --dcap-key eyJ...
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"enclave-os-mini/clients/go/ratls"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <host> <port> [--dcap-url <url>] [--dcap-key <jwt>]\n", os.Args[0])
		os.Exit(1)
	}
	host := os.Args[1]
	port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid port: %s\n", os.Args[2])
		os.Exit(1)
	}

	// Parse optional flags
	var dcapURL, dcapKey string
	for i := 3; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--dcap-url":
			if i+1 < len(os.Args) {
				dcapURL = os.Args[i+1]
				i++
			}
		case "--dcap-key":
			if i+1 < len(os.Args) {
				dcapKey = os.Args[i+1]
				i++
			}
		}
	}

	// Generate random 32-byte challenge nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate nonce: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[*] Challenge nonce: %s\n", hex.EncodeToString(nonce))

	// Connect with challenge
	fmt.Printf("[*] Connecting to %s:%d with RA-TLS challenge...\n", host, port)
	client, err := ratls.Connect(host, port, &ratls.Options{
		Challenge: nonce,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()
	fmt.Println("[+] TLS handshake complete.")

	// Inspect certificate
	fmt.Println("\n=== Server Certificate ===")
	info := client.InspectCert()
	ratls.PrintCertInfo(info)

	// Detect TEE type
	tee := ratls.TeeTypeSGX
	if info.Quote != nil && info.Quote.OID == ratls.OidTDXQuote {
		tee = ratls.TeeTypeTDX
	}

	// Build verification policy
	policy := &ratls.VerificationPolicy{
		TEE:        tee,
		ReportData: ratls.ReportDataChallengeResponse,
		Nonce:      nonce,
	}

	// Optional DCAP quote verification
	if dcapURL != "" {
		fmt.Println("\n=== DCAP Quote Verification ===")
		fmt.Printf("[*] Endpoint: %s\n", dcapURL)
		policy.QuoteVerification = &ratls.QuoteVerificationConfig{
			Endpoint:    dcapURL,
			APIKey:      dcapKey,
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
	fmt.Println("[+] RA-TLS verification PASSED (challenge-response binding OK)")

	if verified.QuoteVerification != nil {
		qv := verified.QuoteVerification
		fmt.Printf("[+] DCAP quote verification: %s\n", qv.Status)
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
