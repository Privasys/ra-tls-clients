// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// ratls-cli connects to an RA-TLS server, inspects the attestation certificate,
// and verifies the embedded quote via an attestation verification endpoint.
//
// Run interactively (prompts for each setting, press Enter to accept defaults):
//
//	go run .
//
// Or pass flags directly to skip the interactive prompts:
//
//	go run . --host machine-id.privasys.org
//	go run . --host 10.0.0.5 --port 443 --ca-cert /path/to/ca.pem
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"enclave-os-mini/clients/go/ratls"
)

// Default values for the Privasys dev environment.
const (
	defaultHost             = "machine-id.privasys.org"
	defaultPort             = 443
	defaultCACert           = "../tests/certificates/privasys.root-ca.dev.crt"
	defaultAttestationURL   = "https://as.privasys.org"
	defaultAttestationToken = ""
)

// prompt prints a label with its default and reads a line from stdin.
// If the user just presses Enter, the default is returned.
func prompt(reader *bufio.Reader, label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("  %s [%s]: ", label, defaultVal)
	} else {
		fmt.Printf("  %s: ", label)
	}
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal
	}
	return line
}

func main() {
	// If any flags are provided, use non-interactive mode.
	host := flag.String("host", "", "Server host")
	port := flag.Int("port", 0, "Server port")
	caCert := flag.String("ca-cert", "", "PEM CA certificate for chain verification (empty to skip)")
	attestationURL := flag.String("attestation-server-url", "", "Quote verification endpoint URL (empty to skip)")
	attestationToken := flag.String("attestation-server-bearer-token", "", "Bearer token for attestation server authentication")
	flag.Parse()

	// Detect whether the user passed any flags at all.
	flagsPassed := false
	flag.Visit(func(_ *flag.Flag) { flagsPassed = true })

	if !flagsPassed {
		// Interactive mode: prompt for each value with defaults.
		fmt.Println("--- RA-TLS Client Configuration ---")
		fmt.Println("Press Enter to accept the default value shown in brackets.\n")
		reader := bufio.NewReader(os.Stdin)

		*host = prompt(reader, "Host", defaultHost)
		portStr := prompt(reader, "Port", strconv.Itoa(defaultPort))
		if p, err := strconv.Atoi(portStr); err == nil {
			*port = p
		} else {
			*port = defaultPort
		}
		*caCert = prompt(reader, "CA certificate path (empty to skip)", defaultCACert)
		*attestationURL = prompt(reader, "Attestation server URL (empty to skip)", defaultAttestationURL)
		if *attestationURL != "" {
			*attestationToken = prompt(reader, "Attestation server bearer token", defaultAttestationToken)
		}

		fmt.Println()
	} else {
		// Non-interactive: apply defaults for any unset flags.
		if *host == "" {
			*host = defaultHost
		}
		if *port == 0 {
			*port = defaultPort
		}
		flag.Visit(func(_ *flag.Flag) {}) // no-op, just to keep flagsPassed used
		// Only set defaults for ca-cert, attestation-server-url, attestation-server-bearer-token if not explicitly provided.
		caCertSet, attestationURLSet, attestationTokenSet := false, false, false
		flag.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "ca-cert":
				caCertSet = true
			case "attestation-server-url":
				attestationURLSet = true
			case "attestation-server-bearer-token":
				attestationTokenSet = true
			}
		})
		if !caCertSet {
			*caCert = defaultCACert
		}
		if !attestationURLSet {
			*attestationURL = defaultAttestationURL
		}
		if !attestationTokenSet {
			*attestationToken = defaultAttestationToken
		}
	}

	// ---- Connection ----
	fmt.Printf("Connecting to %s:%d ...\n", *host, *port)
	if *caCert != "" {
		fmt.Printf("CA certificate: %s\n", *caCert)
	}
	if *attestationURL != "" {
		fmt.Printf("Attestation server: %s\n", *attestationURL)
	}

	opts := &ratls.Options{}
	if *caCert != "" {
		opts.CACertPath = *caCert
	}

	client, err := ratls.Connect(*host, *port, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	fmt.Printf("TLS handshake complete: %s\n", client.TLSVersion())
	fmt.Printf("Cipher: %s\n", client.CipherSuite())

	// ---- Certificate inspection ----
	fmt.Println("\n--- Certificate inspection (RA-TLS) ---")
	info := client.InspectCert()
	ratls.PrintCertInfo(info)

	// ---- Build verification policy ----
	tee := ratls.TeeTypeSGX
	if info.Quote != nil && info.Quote.OID == ratls.OidTDXQuote {
		tee = ratls.TeeTypeTDX
	}

	policy := &ratls.VerificationPolicy{
		TEE:        tee,
		ReportData: ratls.ReportDataDeterministic,
	}

	if *attestationURL != "" {
		policy.QuoteVerification = &ratls.QuoteVerificationConfig{
			Endpoint:    *attestationURL,
			Token:       *attestationToken,
			TimeoutSecs: 30,
		}
	}

	// ---- Quote Verification ----
	fmt.Println("\n--- Quote Verification ---")
	fmt.Println("  ReportData: Deterministic (pubkey + NotBefore binding)")

	verified, err := client.VerifyCertificate(policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Verification FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("  ReportData: PASSED")

	if verified.QuoteVerification != nil {
		qv := verified.QuoteVerification
		fmt.Printf("  Attestation: %s\n", qv.Status)
		if qv.TcbDate != "" {
			fmt.Printf("  TCB Date   : %s\n", qv.TcbDate)
		}
		if len(qv.AdvisoryIDs) > 0 {
			fmt.Printf("  Advisories : %s\n", strings.Join(qv.AdvisoryIDs, ", "))
		}
		fmt.Println("  Attestation: PASSED")
	}

	fmt.Println("\nDone.")
}
