using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Certkor.CertOne;

/// <summary>Body of <c>POST /v1/checks/report</c>.</summary>
internal sealed record IngestRequest(
    JsonElement Report,
    string? Asset,
    string? Environment,
    string? CountryCode,
    string? SnapshotRef,
    string? InputDigest,
    string? Repo,
    string? CommitHash);

/// <summary>
/// Source-generated (reflection-free, trimming and AOT safe) JSON metadata for every wire type.
/// The control plane uses snake_case names and may return timestamps without an offset, which are UTC.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    NumberHandling = JsonNumberHandling.AllowReadingFromString,
    Converters = [typeof(UtcDateTimeOffsetConverter)])]
[JsonSerializable(typeof(ScanRun))]
[JsonSerializable(typeof(Report))]
[JsonSerializable(typeof(CheckResult))]
[JsonSerializable(typeof(List<AiSystem>))]
[JsonSerializable(typeof(IngestRequest))]
[JsonSerializable(typeof(JsonElement))]
internal sealed partial class CertOneJsonContext : JsonSerializerContext
{
}

/// <summary>
/// Reads ISO-8601 timestamps; a timestamp without an offset is interpreted as UTC (the control plane
/// stores naive UTC datetimes). Writes round-trip ISO-8601.
/// </summary>
internal sealed class UtcDateTimeOffsetConverter : JsonConverter<DateTimeOffset>
{
    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException($"Expected an ISO-8601 timestamp string, got {reader.TokenType}.");
        }

        var text = reader.GetString();
        if (DateTimeOffset.TryParse(
                text,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var value))
        {
            return value;
        }

        throw new JsonException($"Invalid ISO-8601 timestamp '{text}'.");
    }

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
}
