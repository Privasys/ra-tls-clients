// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// Privasys fleet trust anchors (mirrors go/ratls/anchors.go).
//
// Every enclave enrolled on the Privasys platform serves an RA-TLS leaf issued
// by the Privasys Intermediate CA of its environment (production or
// development). Requiring the presented chain to reach one of these anchors
// confines acceptance to enclaves Privasys provisioned: a genuine TEE elsewhere
// running the same measured image cannot present a leaf that chains here. The
// evidence checks are layered on top of this fleet-membership check.
//
// Hostname verification is deliberately not part of the chain check: RA-TLS
// peers are commonly dialled by IP, and the identity a relying party cares
// about is the evidence and the app identity in the certificate.

using System.Security.Cryptography.X509Certificates;

namespace Privasys.RaTls;

public static class PrivasysTrustAnchors
{
    /// <summary>Privasys Intermediate CA (production), PEM.</summary>
    public const string IntermediateCaPem = """
        -----BEGIN CERTIFICATE-----
        MIICXTCCAgSgAwIBAgIUGsQj8zdQMALqzHSJSJsxaKuTDuUwCgYIKoZIzj0EAwIw
        dzELMAkGA1UEBhMCR0IxEDAOBgNVBAgMB0VuZ2xhbmQxDzANBgNVBAcMBkxvbmRv
        bjEVMBMGA1UECgwMUHJpdmFzeXMgTHRkMRMwEQYDVQQLDApPcGVyYXRpb25zMRkw
        FwYDVQQDDBBQcml2YXN5cyBSb290IENBMB4XDTI2MDMwMzA5NDcxN1oXDTMxMDMw
        MjA5NDcxN1owfzELMAkGA1UEBhMCR0IxEDAOBgNVBAgMB0VuZ2xhbmQxDzANBgNV
        BAcMBkxvbmRvbjEVMBMGA1UECgwMUHJpdmFzeXMgTHRkMRMwEQYDVQQLDApPcGVy
        YXRpb25zMSEwHwYDVQQDDBhQcml2YXN5cyBJbnRlcm1lZGlhdGUgQ0EwWTATBgcq
        hkjOPQIBBggqhkjOPQMBBwNCAATs+4bGevjmiUiepVQbr22WKGqR42SK8Z4qk9gs
        LxiJbUhJEO0tY1UlsoSBTrsBwb1Mq+ngoeSotFyLz1RTk4Gpo2YwZDASBgNVHRMB
        Af8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUPFvb0C4gBRiY
        Cg2vQpP8MqpG9CswHwYDVR0jBBgwFoAUs86NsnKlGHspTjvFY6gglLqc/4IwCgYI
        KoZIzj0EAwIDRwAwRAIgHsQ73+XHYbDrXtY/tGPfwnWxGYa7OyFvKPzM52uFGh8C
        IDO6Kd6Oajs9XXnRz7OKtlCNrJ7phZNIYFN6zPOqMxgB
        -----END CERTIFICATE-----
        """;

    /// <summary>Privasys Ltd Intermediate CA (DEV), PEM.</summary>
    public const string IntermediateCaDevPem = """
        -----BEGIN CERTIFICATE-----
        MIICdTCCAhqgAwIBAgIUJ/m03RGr3dAeXDmZ1C4izRK0SGAwCgYIKoZIzj0EAwIw
        gYExCzAJBgNVBAYTAlVLMRcwFQYDVQQIDA5Vbml0ZWQgS2luZ2RvbTEPMA0GA1UE
        BwwGTG9uZG9uMRUwEwYDVQQKDAxQcml2YXN5cyBMdGQxDDAKBgNVBAsMA0RldjEj
        MCEGA1UEAwwaUHJpdmFzeXMgTHRkIFJvb3QgQ0EgKERFVikwHhcNMjYwMjE4MTUx
        NzA3WhcNMzEwMjE3MTUxNzA3WjCBiTELMAkGA1UEBhMCVUsxFzAVBgNVBAgMDlVu
        aXRlZCBLaW5nZG9tMQ8wDQYDVQQHDAZMb25kb24xFTATBgNVBAoMDFByaXZhc3lz
        IEx0ZDEMMAoGA1UECwwDRGV2MSswKQYDVQQDDCJQcml2YXN5cyBMdGQgSW50ZXJt
        ZWRpYXRlIENBIChERVYpMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzCEGY7ay
        05+Ve/GUgdXgoVTl1qgaaKkuTUDQMERuyG3gbvGHiYizSQf8zJE+MI27oEjcotsG
        xgx/90RgIGKwuaNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMC
        AQYwHQYDVR0OBBYEFL/qhK4lcNDWws+Q9c/hpU2vMqu3MB8GA1UdIwQYMBaAFIPx
        pxnvfgvw7iKj270kVlKeS2CBMAoGCCqGSM49BAMCA0kAMEYCIQDVhFpKwDBmgxrd
        B2BlsOpVecxntcrFm4ltr8KQrtS5OwIhAMs7bI9w7HD2eYIaEpkxaxFyH4ENYbG4
        D3EbYsQKbQUs
        -----END CERTIFICATE-----
        """;

    /// <summary>The embedded production and development intermediate CAs.</summary>
    public static X509Certificate2Collection Load()
    {
        var anchors = new X509Certificate2Collection();
        anchors.ImportFromPem(IntermediateCaPem);
        anchors.ImportFromPem(IntermediateCaDevPem);
        if (anchors.Count != 2)
            throw new RaTlsException("embedded Privasys trust anchor is not a valid PEM certificate");
        return anchors;
    }

    /// <summary>Every certificate of a PEM file, as trust anchors (roots or intermediates).</summary>
    public static X509Certificate2Collection FromPemFile(string path)
    {
        var anchors = new X509Certificate2Collection();
        anchors.ImportFromPem(File.ReadAllText(path));
        if (anchors.Count == 0)
            throw new RaTlsException($"no PEM certificate in CA cert file {path}");
        return anchors;
    }
}
