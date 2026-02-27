// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// Test script for enclave-os-mini: connect, inspect cert, send HelloWorld.
//
// Usage:
//
//	go run . [--host HOST] [--port PORT] [--ca-cert CA.pem]
//
// Examples:
//
//	go run . --host 141.94.219.130
//	go run . --host 141.94.219.130 --ca-cert /path/to/ca.pem
package main

import (
	"flag"
	"fmt"
	"os"

	"enclave-os-mini/clients/go/ratls"
)

func main() {
	host := flag.String("host", "127.0.0.1", "Server host")
	port := flag.Int("port", 443, "Server port")
	caCert := flag.String("ca-cert", "", "PEM CA certificate for chain verification")
	flag.Parse()

	fmt.Printf("Connecting to %s:%d ...\n", *host, *port)
	if *caCert != "" {
		fmt.Printf("CA certificate: %s\n", *caCert)
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

	// ---- HelloWorld test ----
	fmt.Println("\n--- HelloWorld RPC test ---")
	resp, err := client.SendData([]byte("hello"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "SendData failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Sent: Data(hello)")
	fmt.Printf("Received: Data(%s)\n", string(resp))

	if string(resp) == "world" {
		fmt.Println("\nSUCCESS: HelloWorld module responded correctly!")
		os.Exit(0)
	} else {
		fmt.Printf("\nUNEXPECTED: got %q\n", string(resp))
		os.Exit(1)
	}
}
