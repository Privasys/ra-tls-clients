@echo off
REM Test Rust RA-TLS client connection
cargo run --manifest-path rust/Cargo.toml -- --host [yourserver].com --port 443 --ca-cert tests/certificates/[yourname].root-ca.dev.crt