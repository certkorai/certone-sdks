using System.Net;
using System.Text;

namespace Certkor.CertOne.Tests;

/// <summary>A request as the stub handler saw it, with its body captured before the SDK disposes it.</summary>
internal sealed record CapturedRequest(
    HttpMethod Method,
    Uri Uri,
    string? Authorization,
    string? ContentType,
    byte[] Body,
    IReadOnlyList<CapturedPart> Parts);

/// <summary>One part of a multipart/form-data request.</summary>
internal sealed record CapturedPart(string Name, string? FileName, string? ContentType, byte[] Body)
{
    public string Text => Encoding.UTF8.GetString(Body);
}

/// <summary>An offline <see cref="HttpMessageHandler"/> that records requests and replays canned responses.</summary>
internal sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<CapturedRequest, CancellationToken, Task<HttpResponseMessage>> _respond;

    public StubHttpMessageHandler(Func<CapturedRequest, CancellationToken, Task<HttpResponseMessage>> respond) => _respond = respond;

    public List<CapturedRequest> Requests { get; } = [];

    public static StubHttpMessageHandler Json(HttpStatusCode status, string body) =>
        new((_, _) => Task.FromResult(JsonResponse(status, body)));

    public static StubHttpMessageHandler Sequence(params (HttpStatusCode Status, string Body)[] responses)
    {
        var index = 0;
        return new((_, _) =>
        {
            var (status, body) = responses[Math.Min(index++, responses.Length - 1)];
            return Task.FromResult(JsonResponse(status, body));
        });
    }

    public static HttpResponseMessage JsonResponse(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var parts = new List<CapturedPart>();
        byte[] body = [];
        if (request.Content is MultipartFormDataContent multipart)
        {
            foreach (var part in multipart)
            {
                var disposition = part.Headers.ContentDisposition;
                parts.Add(new CapturedPart(
                    Unquote(disposition?.Name) ?? string.Empty,
                    Unquote(disposition?.FileName),
                    part.Headers.ContentType?.MediaType,
                    await part.ReadAsByteArrayAsync(cancellationToken)));
            }

            body = await multipart.ReadAsByteArrayAsync(cancellationToken);
        }
        else if (request.Content is not null)
        {
            body = await request.Content.ReadAsByteArrayAsync(cancellationToken);
        }

        var captured = new CapturedRequest(
            request.Method,
            request.RequestUri!,
            request.Headers.Authorization?.ToString(),
            request.Content?.Headers.ContentType?.ToString(),
            body,
            parts);
        Requests.Add(captured);
        return await _respond(captured, cancellationToken);
    }

    private static string? Unquote(string? value) => value?.Trim('"');
}
