using System.Net;
using Microsoft.Extensions.DependencyInjection;

namespace Certkor.CertOne.Tests;

public sealed class DependencyInjectionTests
{
    [Fact]
    public async Task Client_resolves_as_an_IHttpClientFactory_typed_client()
    {
        var handler = StubHttpMessageHandler.Json(HttpStatusCode.OK, Fixtures.Read("systems.json"));
        var services = new ServiceCollection();
        services.AddSingleton(new CertOneClientOptions { BaseUrl = new Uri("https://cp.test"), ApiKey = "ck_di_key" });
        services.AddHttpClient<ICertOneClient, CertOneClient>().ConfigurePrimaryHttpMessageHandler(() => handler);

        await using var provider = services.BuildServiceProvider();
        var client = provider.GetRequiredService<ICertOneClient>();
        var systems = await client.ListSystemsAsync();

        Assert.IsType<CertOneClient>(client);
        Assert.Equal(3, systems.Count);
        var request = Assert.Single(handler.Requests);
        Assert.Equal("https://cp.test/v1/systems", request.Uri.AbsoluteUri);
        Assert.Equal("Bearer ck_di_key", request.Authorization);
    }
}
