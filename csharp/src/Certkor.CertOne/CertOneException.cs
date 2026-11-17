using System.Net;

namespace Certkor.CertOne;

/// <summary>
/// A CertOne API call failed: the control plane answered with an HTTP status of 400 or above, the
/// request could not be sent or timed out, the response was not valid JSON, or a scan awaited by
/// <see cref="ICertOneClient.WaitForReportAsync"/> failed or did not finish in time.
/// </summary>
public sealed class CertOneException : Exception
{
    /// <summary>Creates an exception without an HTTP status (network, timeout or scan failure).</summary>
    public CertOneException(string message)
        : this(message, statusCode: null, detail: message)
    {
    }

    /// <summary>Creates an exception wrapping a lower-level failure.</summary>
    public CertOneException(string message, Exception innerException)
        : base(message, innerException)
    {
        Detail = message;
    }

    /// <summary>Creates an exception for an API response.</summary>
    /// <param name="message">Human-readable message.</param>
    /// <param name="statusCode">HTTP status, or <see langword="null"/> when no response was received.</param>
    /// <param name="detail">The API's <c>detail</c> message.</param>
    /// <param name="scan">The failed scan, for scan failures.</param>
    /// <param name="innerException">The underlying exception, if any.</param>
    public CertOneException(
        string message,
        HttpStatusCode? statusCode,
        string detail,
        ScanRun? scan = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        StatusCode = statusCode;
        Detail = detail;
        Scan = scan;
    }

    /// <summary>Creates an exception with a default message.</summary>
    public CertOneException()
        : this("CertOne API call failed.")
    {
    }

    /// <summary>HTTP status code, or <see langword="null"/> when no HTTP response was received.</summary>
    public HttpStatusCode? StatusCode { get; }

    /// <summary>The API's <c>detail</c> message (or the failure description when there was no response).</summary>
    public string Detail { get; } = string.Empty;

    /// <summary>The scan, when the failure is a scan that ended in <c>failed</c> or did not finish in time.</summary>
    public ScanRun? Scan { get; }
}
