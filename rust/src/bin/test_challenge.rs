// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Integration test: challenged RA-TLS connection to enclave-os-mini.
//!
//! Usage:
//!   test_challenge <host> <port> [--verify-mrenclave <hex>]
//!
//! 1. Generates a random 32-byte nonce.
//! 2. Connects to the server with the nonce in ClientHello (ext 0xFFBB).
//! 3. Inspects the server's RA-TLS certificate.
//! 4. Verifies the quote's ReportData contains SHA-512(SHA-256(pubkey) || nonce).
//! 5. Sends a Ping, expects Pong.

use std::io;

use ratls_client::{
    print_cert_info, ReportDataMode, RaTlsClient, TeeType, VerificationPolicy,
};

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <host> <port> [--verify-mrenclave <hex>]", args[0]);
        std::process::exit(1);
    }

    let host = &args[1];
    let port: u16 = args[2].parse().expect("invalid port");

    let mut mr_enclave: Option<[u8; 32]> = None;
    let mut i = 3;
    while i < args.len() {
        if args[i] == "--verify-mrenclave" && i + 1 < args.len() {
            let bytes = hex::decode(&args[i + 1]).expect("invalid hex for MRENCLAVE");
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&bytes);
            mr_enclave = Some(buf);
            i += 2;
        } else {
            i += 1;
        }
    }

    // 1. Generate a random 32-byte nonce
    let nonce = {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut buf = vec![0u8; 32];
        rng.fill(&mut buf).expect("RNG failed");
        buf
    };
    println!("[*] Challenge nonce: {}", hex::encode(&nonce));

    // 2. Connect with challenge
    println!("[*] Connecting to {}:{} with RA-TLS challenge...", host, port);
    let mut client = RaTlsClient::connect_challenged(host, port, None, nonce.clone())?;
    println!("[+] TLS handshake complete.");

    // 3. Inspect certificate
    println!();
    println!("=== Server Certificate ===");
    let info = client.inspect_certificate();
    print_cert_info(&info);

    // 4. Verify with challenge-response
    println!();
    println!("=== Verification ===");
    let policy = VerificationPolicy {
        tee: TeeType::Sgx,
        mr_enclave,
        mr_signer: None,
        mr_td: None,
        report_data: ReportDataMode::ChallengeResponse { nonce },
        expected_oids: vec![],
        quote_verification: None,
    };
    match client.verify_certificate(&policy) {
        Ok(_info) => println!("[+] RA-TLS verification PASSED (challenge-response binding OK)"),
        Err(e) => {
            eprintln!("[-] RA-TLS verification FAILED: {}", e);
            std::process::exit(2);
        }
    }

    // 5. Ping
    println!();
    println!("=== Ping Test ===");
    match client.ping() {
        Ok(true) => println!("[+] Ping -> Pong OK"),
        Ok(false) => {
            eprintln!("[-] Ping did not return Pong");
            std::process::exit(3);
        }
        Err(e) => {
            eprintln!("[-] Ping failed: {}", e);
            std::process::exit(3);
        }
    }

    println!();
    println!("[+] All tests PASSED.");
    Ok(())
}
