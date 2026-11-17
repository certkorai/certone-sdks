using System.Security.Cryptography;

namespace Certkor.CertOne;

/// <summary>
/// Computes the <c>input_digest</c> (<c>sha256:&lt;lowercase hex&gt;</c>) that binds a run-at-source
/// attestation to the exact artifact a report covers.
/// </summary>
public static class InputDigest
{
    /// <summary>The digest prefix.</summary>
    public const string Prefix = "sha256:";

    /// <summary>Digest of an in-memory artifact.</summary>
    public static string Compute(ReadOnlySpan<byte> data) => Format(SHA256.HashData(data));

    /// <summary>Digest of a stream, read from its current position to the end. The stream is not disposed.</summary>
    public static async Task<string> ComputeAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Format(hash);
    }

    /// <summary>Digest of a file.</summary>
    public static async Task<string> ComputeFileAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
        await using (stream.ConfigureAwait(false))
        {
            return await ComputeAsync(stream, cancellationToken).ConfigureAwait(false);
        }
    }

    private static string Format(byte[] hash) => Prefix + Convert.ToHexString(hash).ToLowerInvariant();
}
