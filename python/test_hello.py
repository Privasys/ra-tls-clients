#!/usr/bin/env python3
# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

"""Test script for enclave-os-mini: connect, inspect cert, send HelloWorld.

Usage:
    python test_hello.py [--host HOST] [--port PORT] [--ca-cert CA.pem]

Examples:
    python test_hello.py --host 141.94.219.130
    python test_hello.py --host 141.94.219.130 --ca-cert /path/to/ca.pem
"""
import argparse
import sys

from ratls_client import RaTlsClient, print_cert_info


def main():
    parser = argparse.ArgumentParser(description="RA-TLS HelloWorld test")
    parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=443, help="Server port (default: 443)")
    parser.add_argument("--ca-cert", default=None, help="PEM CA certificate for chain verification")
    args = parser.parse_args()

    print(f"Connecting to {args.host}:{args.port} ...")
    if args.ca_cert:
        print(f"CA certificate: {args.ca_cert}")

    with RaTlsClient(args.host, args.port, ca_cert=args.ca_cert) as client:
        print(f"TLS handshake complete: {client.tls_version}")
        cipher = client.cipher
        if cipher:
            print(f"Cipher: {cipher[0]}  ({cipher[1]}, {cipher[2]} bits)")

        # ---- Certificate inspection ----
        print("\n--- Certificate inspection (RA-TLS) ---")
        info = client.inspect_certificate()
        print_cert_info(info)

        # ---- HelloWorld test ----
        print("\n--- HelloWorld RPC test ---")
        resp = client.send_data(b"hello")
        print(f"Sent: Data(hello)")
        print(f"Received: Data({resp!r})")

        if resp == b"world":
            print("\nSUCCESS: HelloWorld module responded correctly!")
            sys.exit(0)
        else:
            print(f"\nUNEXPECTED: got {resp!r}")
            sys.exit(1)


if __name__ == "__main__":
    main()
