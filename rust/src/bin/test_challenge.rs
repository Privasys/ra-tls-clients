// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Integration test: challenge-mode RA-TLS v2 connection to an enclave.
//!
//! Usage:
//!   test_challenge <host> <port> [--verify-mrenclave <hex>] [--attestation-server-url <url>] [--attestation-server-bearer-token <token>]
//!
//! 1. Connects; after the handshake, requests evidence bound to this
//!    connection's TLS exporter and a fresh context.
//! 2. Inspects the server's certificate (leaf, chain, OIDs, no evidence).
//! 3. Verifies the quote's report_data against the leaf key, the context and
//!    the exporter value.
//! 4. Optionally verifies the raw quote via an attestation server.
//! 5. Sends a health probe over the attested connection.

use std::io;

use ratls_client::{
    print_cert_info, QuoteVerificationConfig, RaTlsClient, TeeType, VerificationPolicy,
};

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} <host> <port> [--verify-mrenclave <hex>] [--attestation-server-url <url>] [--attestation-server-bearer-token <token>]",
            args[0]
        );
        std::process::exit(1);
    }

    let host = &args[1];
    let port: u16 = args[2].parse().expect("invalid port");

    let mut mr_enclave: Option<[u8; 32]> = None;
    let mut attestation_url: Option<String> = None;
    let mut attestation_token: Option<String> = None;

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--verify-mrenclave" if i + 1 < args.len() => {
                let bytes = hex::decode(&args[i + 1]).expect("invalid hex for MRENCLAVE");
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&bytes);
                mr_enclave = Some(buf);
                i += 2;
            }
            "--attestation-server-url" if i + 1 < args.len() => {
                attestation_url = Some(args[i + 1].clone());
                i += 2;
            }
            "--attestation-server-bearer-token" if i + 1 < args.len() => {
                attestation_token = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }

    // 1. Connect in challenge mode; the evidence exchange runs inside connect.
    println!(
        "[*] Connecting to {}:{} with RA-TLS v2 challenge attestation...",
        host, port
    );
    let mut client = RaTlsClient::connect(host, port, None)?;
    println!("[+] TLS handshake and evidence exchange complete.");
    let (tee, quote_len, quote_time, context) = {
        let ev = client
            .evidence()
            .expect("challenge mode always carries evidence");
        (
            ev.tee.clone(),
            ev.quote.len(),
            ev.quote_time.clone(),
            hex::encode(ev.context.unwrap_or_default()),
        )
    };
    println!("[*] Context : {}", context);
    println!(
        "[*] Evidence: {}, {}-byte quote, quote_time {}",
        tee, quote_len, quote_time
    );

    // 2. Inspect certificate
    println!();
    println!("=== Server Certificate ===");
    let info = client.inspect_certificate();
    print_cert_info(&info);

    // 3. Build verification policy
    let quote_verification = attestation_url.map(|url| {
        println!();
        println!("=== Quote Verification ===");
        println!("[*] Endpoint: {}", url);
        QuoteVerificationConfig {
            endpoint: url,
            token: attestation_token,
            accepted_statuses: vec![],
            enforce_tcb_status: false,
            acceptable_tcb_statuses: vec![],
            timeout_secs: 30,
        }
    });

    println!();
    println!("=== Verification ===");
    let policy = VerificationPolicy {
        tee: if tee.starts_with("tdx") {
            TeeType::Tdx
        } else {
            TeeType::Sgx
        },
        mr_enclave,
        mr_signer: None,
        mr_td: None,
        measurement: None,
        host_data: None,
        expected_oids: vec![],
        quote_verification,
        allow_debug_images: false,
    };
    match client.verify_certificate(&policy) {
        Ok(info) => {
            println!(
                "[+] RA-TLS verification PASSED (evidence bound to this connection's exporter)"
            );
            if let Some(ref qv) = info.quote_verification {
                println!("[+] Quote verification: {:?}", qv.status);
                if let Some(ref date) = qv.tcb_date {
                    println!("    TCB Date   : {}", date);
                }
                if !qv.advisory_ids.is_empty() {
                    println!("    Advisories : {}", qv.advisory_ids.join(", "));
                }
            }
        }
        Err(e) => {
            eprintln!("[-] RA-TLS verification FAILED: {}", e);
            std::process::exit(2);
        }
    }

    // 4. Health probe over the attested connection
    println!();
    println!("=== Health probe ===");
    match client.healthz() {
        Ok(v) => println!("[+] healthz: {}", v),
        Err(e) => {
            eprintln!("[-] healthz failed: {}", e);
            std::process::exit(3);
        }
    }

    println!();
    println!("[+] All tests PASSED.");
    Ok(())
}
