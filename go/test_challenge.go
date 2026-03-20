package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"enclave-os-mini/clients/go/ratls"
)

func main() {
	challenge, _ := hex.DecodeString("deadbeefcafebabe0102030405060708090a0b0c0d0e0f101112131415161718")
	fmt.Printf("Sending challenge: %x\n", challenge)
	fmt.Printf("Challenge length: %d bytes\n", len(challenge))

	client, err := ratls.Connect("m-fr-1.privasys.org", 8446, &ratls.Options{
		Challenge: challenge,
	})
	if err != nil {
		log.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	info := client.InspectCert()
	fmt.Printf("PubKey SHA-256: %s\n", info.PubKeySHA256)
	if info.Quote != nil && len(info.Quote.ReportData) > 0 {
		fmt.Printf("ReportData:    %x\n", info.Quote.ReportData)
	}
	fmt.Printf("Not Before: %s\n", info.NotBefore)
	fmt.Printf("Not After:  %s\n", info.NotAfter)
}
