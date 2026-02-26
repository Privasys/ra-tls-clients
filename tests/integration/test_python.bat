@echo off
REM Test Python RA-TLS client connection
python python/test_hello.py --host [yourserver].com --port 443 --ca-cert tests/certificates/[yourname].root-ca.dev.crt