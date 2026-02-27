// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Test script for enclave-os-mini: connect, inspect cert, send HelloWorld.
//!
//! Usage:
//!   cargo run -- [--host HOST] [--port PORT] [--ca-cert CA.pem]
//!
//! Examples:
//!   cargo run -- --host 141.94.219.130
//!   cargo run -- --host 141.94.219.130 --ca-cert /path/to/ca.pem

mod ratls_client;

use ratls_client::{print_cert_info, RaTlsClient};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut host = "127.0.0.1".to_string();
    let mut port: u16 = 443;
    let mut ca_cert: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                i += 1;
                host = args[i].clone();
            }
            "--port" => {
                i += 1;
                port = args[i].parse().expect("invalid port");
            }
            "--ca-cert" => {
                i += 1;
                ca_cert = Some(args[i].clone());
            }
            _ => {}
        }
        i += 1;
    }

    println!("Connecting to {}:{} ...", host, port);
    if let Some(ref ca) = ca_cert {
        println!("CA certificate: {}", ca);
    }

    let mut client = RaTlsClient::connect(&host, port, ca_cert.as_deref())
        .expect("Failed to connect");

    // ---- Certificate inspection ----
    println!("\n--- Certificate inspection (RA-TLS) ---");
    let info = client.inspect_certificate();
    print_cert_info(&info);

    // ---- HelloWorld test ----
    println!("\n--- HelloWorld RPC test ---");
    let resp = client.send_data(b"hello").expect("send_data failed");
    println!("Sent: Data(hello)");
    println!("Received: Data({})", String::from_utf8_lossy(&resp));

    if resp == b"world" {
        println!("\nSUCCESS: HelloWorld module responded correctly!");
    } else {
        eprintln!("\nUNEXPECTED: got {:?}", String::from_utf8_lossy(&resp));
        std::process::exit(1);
    }
}
