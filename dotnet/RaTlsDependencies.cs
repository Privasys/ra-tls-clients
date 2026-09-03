// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// Attested cross-enclave dependencies (mirrors go/ratls/dependencies.go).
//
// A workload that depends on other enclaves is pinned to a fixed set of
// dependency identities. The runtime carries that set in the certificate
// extension AttestedDependencySet (7.1) and refuses, fail-closed, to complete an
// RA-TLS handshake with a peer that does not match the pinned identity for the
// dependency being dialled. A dependency identity is the same tuple used to
// verify any app: measurement registers plus required OID values (code digest
// 4.2, app id 4.1), so verification reuses the ordinary matcher.
//
// Depth soundness comes from the identity fold: an entry commits to the
// dependency's own dependency set via FoldedIdentity, so a change deep in the
// tree changes the identity a dependent is pinned to.

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Privasys.RaTls;

/// <summary>A TDX measurement triple (lowercase hex).</summary>
public sealed record DepTdxMeasurement(string MrTd, string Rtmr1, string Rtmr2);

/// <summary>One allowed measurement for a dependency. Exactly one of Sgx / Tdx is set.</summary>
public sealed record DepMeasurement(string? Sgx = null, DepTdxMeasurement? Tdx = null)
{
    /// <summary>Stable string form used for sorting and for the fold preimage; identical across SDKs.</summary>
    public string Canonical() => Tdx is not null
        ? "tdx:" + Tdx.MrTd.ToLowerInvariant() + ":" + Tdx.Rtmr1.ToLowerInvariant() + ":" + Tdx.Rtmr2.ToLowerInvariant()
        : "sgx:" + (Sgx ?? "").ToLowerInvariant();

    internal static DepMeasurement FromCanonical(string s)
    {
        if (s.StartsWith("tdx:", StringComparison.Ordinal))
        {
            var parts = s.Substring(4).Split(':');
            return new DepMeasurement(Tdx: new DepTdxMeasurement(
                parts.Length > 0 ? parts[0] : "", parts.Length > 1 ? parts[1] : "", parts.Length > 2 ? parts[2] : ""));
        }
        return new DepMeasurement(Sgx: s.StartsWith("sgx:", StringComparison.Ordinal) ? s.Substring(4) : s);
    }
}

/// <summary>Pins one direct dependency: the identity a dependent enclave may talk to for that app.</summary>
public sealed record DependencyEntry(
    /// <summary>Management app id of the dependency, lowercase hex of the peer's OID 4.1 value.</summary>
    string AppId,
    /// <summary>Any-of set of allowed measurements; a peer matches when it satisfies at least one.</summary>
    IReadOnlyList<DepMeasurement> Measurements,
    /// <summary>OID values the peer's certificate must carry verbatim.</summary>
    IReadOnlyList<ExpectedOid>? RequiredOids = null,
    /// <summary>Lowercase-hex commitment to this dependency's own transitive subtree (its FoldIdentity), empty for a leaf.</summary>
    string FoldedIdentity = "");

/// <summary>A workload's set of direct attested dependencies.</summary>
public sealed record DependencySet(IReadOnlyList<DependencyEntry> Entries)
{
    public static readonly DependencySet Empty = new(Array.Empty<DependencyEntry>());
}

public static class DependencySets
{
    private const string DomainFoldIdentity = "privasys-app-identity-v1";

    /// <summary>The canonical byte encoding placed in the AttestedDependencySet extension; independent of declaration order.</summary>
    public static byte[] Encode(DependencySet set)
    {
        var w = new CanonicalWriter();
        WriteCanonical(set, w);
        return w.ToArray();
    }

    /// <summary>Parses the canonical encoding (for inspection and round trips).</summary>
    public static DependencySet Decode(byte[] encoded)
    {
        var r = new CanonicalReader(encoded);
        var n = r.U32();
        var entries = new List<DependencyEntry>();
        for (uint i = 0; i < n; i++)
        {
            var appId = r.Str();
            var mc = r.U32();
            var ms = new List<DepMeasurement>();
            for (uint j = 0; j < mc; j++) ms.Add(DepMeasurement.FromCanonical(r.Str()));
            var oc = r.U32();
            var os = new List<ExpectedOid>();
            for (uint j = 0; j < oc; j++)
            {
                var oid = r.Str();
                os.Add(new ExpectedOid(oid, r.Bytes()));
            }
            entries.Add(new DependencyEntry(appId, ms, os, r.Str()));
        }
        if (!r.AtEnd) throw new RaTlsException("trailing bytes in dependency-set encoding");
        return new DependencySet(entries);
    }

    /// <summary>
    /// identity(X) = SHA-256( domain || measurements(X) || requiredOids(X) || encode(deps(X)) ).
    /// <paramref name="ownMeasurements"/> are canonical forms (DepMeasurement.Canonical()).
    /// </summary>
    public static byte[] FoldIdentity(IEnumerable<string> ownMeasurements, IEnumerable<ExpectedOid> ownRequiredOids, DependencySet deps)
    {
        var w = new CanonicalWriter();
        w.Str(DomainFoldIdentity);
        var ms = ownMeasurements.Select(m => m.ToLowerInvariant()).ToList();
        ms.Sort(string.CompareOrdinal);
        w.U32(ms.Count);
        foreach (var m in ms) w.Str(m);
        var os = SortOids(ownRequiredOids);
        w.U32(os.Count);
        foreach (var o in os) { w.Str(o.Oid); w.Bytes(o.ExpectedValue); }
        WriteCanonical(deps, w);
        return SHA256.HashData(w.ToArray());
    }

    /// <summary>FoldIdentity as lowercase hex, the form stored in DependencyEntry.FoldedIdentity.</summary>
    public static string FoldIdentityHex(IEnumerable<string> ownMeasurements, IEnumerable<ExpectedOid> ownRequiredOids, DependencySet deps)
        => Convert.ToHexString(FoldIdentity(ownMeasurements, ownRequiredOids, deps)).ToLowerInvariant();

    /// <summary>The peer's app id (OID 4.1) as lowercase hex, or null when absent.</summary>
    public static string? AppIdFromCert(CertInfo peer)
    {
        var ext = peer.CustomOids?.FirstOrDefault(o => o.Oid == Oids.WorkloadAppID);
        return ext is null ? null : Convert.ToHexString(ext.Value).ToLowerInvariant();
    }

    /// <summary>
    /// Fail-closed check that a peer satisfies one entry: its quoted measurements match at least one
    /// allowed measurement and every required OID is present verbatim. The peer's CertInfo must
    /// carry the evidence of the connection (VerifyEvidence or RaTlsClient.InspectCertificate).
    /// </summary>
    public static void MatchDependency(CertInfo peer, TeeType tee, DependencyEntry entry)
    {
        if (peer.Quote is null || peer.Quote.Raw.Length == 0)
            throw new RaTlsException($"dependency {entry.AppId}: peer carries no quote (fail closed)");
        if (entry.Measurements.Count == 0)
            throw new RaTlsException($"dependency {entry.AppId}: entry pins no measurement (fail closed)");

        Exception? last = null;
        var matched = false;
        foreach (var m in entry.Measurements)
        {
            try
            {
                RaTlsVerifier.VerifyMeasurements(peer.Quote.Raw, MeasurementPolicy(tee, m));
                matched = true;
                break;
            }
            catch (RaTlsException e) { last = e; }
        }
        if (!matched)
            throw new RaTlsException($"dependency {entry.AppId}: peer matches no pinned measurement (fail closed): {last?.Message}");
        try { RaTlsVerifier.VerifyExpectedOids(peer.CustomOids, entry.RequiredOids); }
        catch (RaTlsException e) { throw new RaTlsException($"dependency {entry.AppId}: {e.Message}", e); }
    }

    /// <summary>
    /// Enforces the whole set: selects the entry whose AppId matches the peer's OID 4.1 and requires
    /// the peer to match it. A peer whose app id is not a declared dependency is rejected.
    /// </summary>
    public static void VerifyPeerIsDependency(CertInfo peer, TeeType tee, DependencySet set)
    {
        var appId = AppIdFromCert(peer)
            ?? throw new RaTlsException($"peer certificate carries no app id (OID {Oids.WorkloadAppID}); cannot match a declared dependency (fail closed)");
        var entry = set.Entries.FirstOrDefault(e => e.AppId == appId)
            ?? throw new RaTlsException($"peer app id {appId} is not a declared dependency (fail closed)");
        MatchDependency(peer, tee, entry);
    }

    private static VerificationPolicy MeasurementPolicy(TeeType tee, DepMeasurement m)
    {
        switch (tee)
        {
            case TeeType.Sgx:
                var mre = HexOrNull(m.Sgx, 32) ?? throw new RaTlsException($"invalid SGX MRENCLAVE \"{m.Sgx}\"");
                return new VerificationPolicy(TeeType.Sgx, MrEnclave: mre);
            case TeeType.Tdx:
                if (m.Tdx is null) throw new RaTlsException("TDX measurement missing MRTD triple");
                // A TDX dependency pins the full triple: MRTD alone (the TD firmware) does not identify the guest build.
                var mrtd = HexOrNull(m.Tdx.MrTd, 48) ?? throw new RaTlsException($"invalid TDX MRTD \"{m.Tdx.MrTd}\"");
                var rtmr1 = HexOrNull(m.Tdx.Rtmr1, 48) ?? throw new RaTlsException($"invalid TDX RTMR1 \"{m.Tdx.Rtmr1}\"");
                var rtmr2 = HexOrNull(m.Tdx.Rtmr2, 48) ?? throw new RaTlsException($"invalid TDX RTMR2 \"{m.Tdx.Rtmr2}\"");
                return new VerificationPolicy(TeeType.Tdx, MrTd: mrtd, Rtmr1: rtmr1, Rtmr2: rtmr2);
            default:
                throw new RaTlsException("unsupported TEE type for dependency measurement");
        }
    }

    private static byte[]? HexOrNull(string? hex, int length)
    {
        if (hex is null || hex.Length != length * 2) return null;
        try { return Convert.FromHexString(hex); } catch (FormatException) { return null; }
    }

    // -- canonical grammar ------------------------------------------------

    private static List<ExpectedOid> SortOids(IEnumerable<ExpectedOid> oids)
    {
        var list = oids.ToList();
        list.Sort((a, b) =>
        {
            var c = string.CompareOrdinal(a.Oid, b.Oid);
            return c != 0 ? c : a.ExpectedValue.AsSpan().SequenceCompareTo(b.ExpectedValue);
        });
        return list;
    }

    private static void WriteCanonical(DependencySet set, CanonicalWriter w)
    {
        var entries = set.Entries.OrderBy(e => e.AppId, StringComparer.Ordinal).ToList();
        w.U32(entries.Count);
        foreach (var e in entries)
        {
            w.Str(e.AppId);
            var ms = e.Measurements.Select(m => m.Canonical()).ToList();
            ms.Sort(string.CompareOrdinal);
            w.U32(ms.Count);
            foreach (var m in ms) w.Str(m);
            var os = SortOids(e.RequiredOids ?? Array.Empty<ExpectedOid>());
            w.U32(os.Count);
            foreach (var o in os) { w.Str(o.Oid); w.Bytes(o.ExpectedValue); }
            w.Str(e.FoldedIdentity.ToLowerInvariant());
        }
    }

    private sealed class CanonicalWriter
    {
        private readonly MemoryStream _ms = new();
        public void U32(int n)
        {
            Span<byte> b = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(b, (uint)n);
            _ms.Write(b);
        }
        public void Bytes(ReadOnlySpan<byte> b) { U32(b.Length); _ms.Write(b); }
        public void Str(string s) => Bytes(Encoding.UTF8.GetBytes(s));
        public byte[] ToArray() => _ms.ToArray();
    }

    private sealed class CanonicalReader
    {
        private readonly byte[] _buf;
        private int _off;
        public CanonicalReader(byte[] buf) => _buf = buf;
        public bool AtEnd => _off == _buf.Length;
        public uint U32()
        {
            if (_off + 4 > _buf.Length) throw new RaTlsException("dependency-set encoding truncated");
            var n = BinaryPrimitives.ReadUInt32BigEndian(_buf.AsSpan(_off, 4));
            _off += 4;
            return n;
        }
        public byte[] Bytes()
        {
            var n = U32();
            if (n > (uint)(_buf.Length - _off)) throw new RaTlsException("dependency-set encoding truncated");
            var b = _buf.AsSpan(_off, (int)n).ToArray();
            _off += (int)n;
            return b;
        }
        public string Str() => Encoding.UTF8.GetString(Bytes());
    }
}
