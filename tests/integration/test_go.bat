@echo off
REM Test Go RA-TLS client connection
go run go/main.go --host [yourserver].com --port 443 --ca-cert tests/certificates/[yourname].root-ca.dev.crt