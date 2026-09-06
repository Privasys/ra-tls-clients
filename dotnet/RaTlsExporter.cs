// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

using System.Security.Cryptography;
using System.Text;

namespace Privasys.RaTls;

/// <summary>
/// The TLS 1.3 exporter (RFC 8446 section 7.5) over a raw exporter_master_secret, for a
/// TLS stack that hands out the secret rather than the exporter:
/// <c>TLS-Exporter(label, context, length) = HKDF-Expand-Label(Derive-Secret(EMS, label, ""), "exporter", Hash(context), length)</c>.
/// <paramref name="hash"/> is the cipher suite's hash, "sha256" or "sha384". Checked against
/// the shared vectors in tests/vectors/ratls-v2/exporter.json.
/// </summary>
public static class Tls13Exporter
{
    public static byte[] Export(string hash, byte[] exporterMasterSecret, string label, byte[] context, int length)
    {
        var derived = HkdfExpandLabel(hash, exporterMasterSecret, label, HashOf(hash, Array.Empty<byte>()), HashLength(hash));
        return HkdfExpandLabel(hash, derived, "exporter", HashOf(hash, context), length);
    }

    /// <summary>HKDF-Expand-Label(Secret, Label, Context, Length) with the "tls13 " prefix (RFC 8446 section 7.1).</summary>
    public static byte[] HkdfExpandLabel(string hash, byte[] secret, string label, byte[] context, int length)
    {
        var fullLabel = Encoding.ASCII.GetBytes("tls13 " + label);
        var info = new byte[2 + 1 + fullLabel.Length + 1 + context.Length];
        info[0] = (byte)(length >> 8);
        info[1] = (byte)length;
        info[2] = (byte)fullLabel.Length;
        fullLabel.CopyTo(info, 3);
        info[3 + fullLabel.Length] = (byte)context.Length;
        context.CopyTo(info, 4 + fullLabel.Length);
        return HkdfExpand(hash, secret, info, length);
    }

    /// <summary>HKDF-Expand (RFC 5869): T(i) = HMAC(PRK, T(i-1) || info || i).</summary>
    public static byte[] HkdfExpand(string hash, byte[] prk, byte[] info, int length)
    {
        using HMAC hmac = hash == "sha384" ? new HMACSHA384(prk) : new HMACSHA256(prk);
        var output = new byte[length];
        var previous = Array.Empty<byte>();
        var written = 0;
        for (byte counter = 1; written < length; counter++)
        {
            var block = hmac.ComputeHash(previous.Concat(info).Append(counter).ToArray());
            var take = Math.Min(block.Length, length - written);
            Array.Copy(block, 0, output, written, take);
            written += take;
            previous = block;
        }
        return output;
    }

    private static byte[] HashOf(string hash, byte[] data) => hash == "sha384" ? SHA384.HashData(data) : SHA256.HashData(data);
    private static int HashLength(string hash) => hash == "sha384" ? 48 : 32;
}
