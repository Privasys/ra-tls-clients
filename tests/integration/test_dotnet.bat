@echo off
REM Test .NET RA-TLS client connection
dotnet run --project dotnet/RaTlsClient.csproj -- --host [yourserver].com --port 443 --ca-cert tests/certificates/[yourname].root-ca.dev.crt