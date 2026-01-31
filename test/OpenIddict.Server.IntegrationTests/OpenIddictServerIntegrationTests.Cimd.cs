/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    [Fact]
    public async Task HandleConfigurationRequest_AdvertisesCimdSupport_WhenEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableClientIdMetadataDocumentSupport();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.True((bool?) response[Metadata.ClientIdMetadataDocumentSupported]);
    }

    [Fact]
    public async Task HandleConfigurationRequest_DoesNotAdvertiseCimdSupport_WhenDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync();
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Null(response[Metadata.ClientIdMetadataDocumentSupported]);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RejectsUrlClientId_WhenCimdDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("https://example.com/client", It.IsAny<CancellationToken>()))
                    .ReturnsAsync((OpenIddictApplication?) null);
            }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "https://example.com/client",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert — CIMD is disabled, so URL client_id is just treated as unknown client
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2052(Parameters.ClientId), response.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_SetsTransactionFlag_WhenCimdEnabledAndClientIdIsHttpsUrl()
    {
        // Arrange
        var flagWasSet = false;

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableClientIdMetadataDocumentSupport();

            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("https://example.com/client", It.IsAny<CancellationToken>()))
                    .ReturnsAsync((OpenIddictApplication?) null);
            }));

            // Add an inline handler that runs after ValidateClientId to inspect the transaction flag.
            options.AddEventHandler<ProcessAuthenticationContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    if (context.Transaction.Properties.TryGetValue(
                        ".ClientIdMetadataDocumentFetchRequired", out var value) &&
                        value is true)
                    {
                        flagWasSet = true;
                    }

                    // Reject to stop further processing (we don't have CIMD HTTP infrastructure here).
                    context.Reject(
                        error: Errors.InvalidClient,
                        description: "Test completed.");

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateClientId.Descriptor.Order + 1);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "https://example.com/client",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.True(flagWasSet);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RejectsHttpUrl_WhenCimdEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableClientIdMetadataDocumentSupport();

            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("http://example.com/client", It.IsAny<CancellationToken>()))
                    .ReturnsAsync((OpenIddictApplication?) null);
            }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "http://example.com/client",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert — HTTP URL should be rejected even with CIMD enabled (requires HTTPS)
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2052(Parameters.ClientId), response.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RejectsUrlWithFragment_WhenCimdEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableClientIdMetadataDocumentSupport();

            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("https://example.com/client#fragment", It.IsAny<CancellationToken>()))
                    .ReturnsAsync((OpenIddictApplication?) null);
            }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "https://example.com/client#fragment",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert — URL with fragment should be rejected
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2052(Parameters.ClientId), response.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RejectsUrlWithUserInfo_WhenCimdEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableClientIdMetadataDocumentSupport();

            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("https://user:pass@example.com/client", It.IsAny<CancellationToken>()))
                    .ReturnsAsync((OpenIddictApplication?) null);
            }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "https://user:pass@example.com/client",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert — URL with userinfo should be rejected
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2052(Parameters.ClientId), response.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RejectsRootPathUrl_WhenCimdEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableClientIdMetadataDocumentSupport();

            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("https://example.com/", It.IsAny<CancellationToken>()))
                    .ReturnsAsync((OpenIddictApplication?) null);
            }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "https://example.com/",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert — Root path URL should be rejected
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2052(Parameters.ClientId), response.ErrorDescription);
    }
}
