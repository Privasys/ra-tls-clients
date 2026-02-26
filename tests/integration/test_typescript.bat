@echo off
REM Test TypeScript RA-TLS client connection
npx ts-node typescript/test_hello.ts --host [yourserver].com --port 443 --ca-cert tests/certificates/[yourname].root-ca.dev.crt