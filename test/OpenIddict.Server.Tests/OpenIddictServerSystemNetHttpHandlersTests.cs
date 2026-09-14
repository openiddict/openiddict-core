/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net;
using System.Net.Http;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OpenIddict.Server.SystemNetHttp;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.SystemNetHttp.OpenIddictServerSystemNetHttpHandlers;

namespace OpenIddict.Server.Tests;

public class OpenIddictServerSystemNetHttpHandlersTests
{
    [Fact]
    public async Task SendHttpBackchannelNotification_PostsJsonPayloadWithBearerToken()
    {
        // Arrange
        HttpRequestMessage? captured = null;
        string? body = null;

        var handler = new StubHandler(async request =>
        {
            captured = request;
            body = await request.Content!.ReadAsStringAsync();

            return new HttpResponseMessage(HttpStatusCode.NoContent);
        });

        var (provider, context) = CreateContext(handler);

        // Act
        await provider.GetRequiredService<SendHttpBackchannelNotification>().HandleAsync(context);

        // Assert
        Assert.True(context.IsRequestHandled);
        Assert.NotNull(captured);
        Assert.Equal(HttpMethod.Post, captured.Method);
        Assert.Equal(new Uri("https://fabrikam.com/ciba/notify"), captured.RequestUri);
        Assert.Equal("Bearer", captured.Headers.Authorization?.Scheme);
        Assert.Equal("8C3C7A6D", captured.Headers.Authorization?.Parameter);
        Assert.Equal("application/json", captured.Content!.Headers.ContentType?.MediaType);

        using var document = JsonDocument.Parse(body!);
        Assert.Equal("F6B3B1E4", document.RootElement.GetProperty(Parameters.AuthReqId).GetString());
    }

    [Theory]
    [InlineData(HttpStatusCode.Found)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task SendHttpBackchannelNotification_RejectsContextForUnsuccessfulStatusCodes(HttpStatusCode status)
    {
        // Arrange
        var handler = new StubHandler(_ => Task.FromResult(new HttpResponseMessage(status)));
        var (provider, context) = CreateContext(handler);

        // Act
        await provider.GetRequiredService<SendHttpBackchannelNotification>().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(Errors.ServerError, context.Error);
        Assert.Equal(SR.FormatID2307((int) status), context.ErrorDescription);
    }

    [Fact]
    public async Task SendHttpBackchannelNotification_RejectsContextWhenEndpointIsUnreachable()
    {
        // Arrange
        var handler = new StubHandler(_ => throw new HttpRequestException("unreachable"));
        var (provider, context) = CreateContext(handler);

        // Act
        await provider.GetRequiredService<SendHttpBackchannelNotification>().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.GetResourceString(SR.ID2308), context.ErrorDescription);
    }

    private static (ServiceProvider Provider, SendBackchannelNotificationContext Context) CreateContext(HttpMessageHandler handler)
    {
        var services = new ServiceCollection();
        services.AddSingleton<ILoggerFactory>(NullLoggerFactory.Instance);
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));

        services.AddOpenIddict()
            .AddServer(options => options.UseSystemNetHttp());

        services.AddHttpClient(OpenIddictServerSystemNetHttpConfiguration.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => handler);

        services.AddSingleton<SendHttpBackchannelNotification>();

        var provider = services.BuildServiceProvider();

        var context = new SendBackchannelNotificationContext(new OpenIddictServerTransaction
        {
            CancellationToken = CancellationToken.None,
            Options = new OpenIddictServerOptions(),
            ServiceProvider = provider
        })
        {
            ClientId = "Fabrikam",
            ClientNotificationEndpoint = new Uri("https://fabrikam.com/ciba/notify"),
            ClientNotificationToken = "8C3C7A6D",
            Notification = new OpenIddictResponse { AuthReqId = "F6B3B1E4" },
            TokenDeliveryMode = BackchannelTokenDeliveryModes.Ping
        };

        return (provider, context);
    }

    private sealed class StubHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> callback) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => callback(request);
    }
}
