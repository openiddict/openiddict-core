/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OpenIddict.Server.IntegrationTests;
using Xunit;

namespace OpenIddict.Server.AspNetCore.IntegrationTests;

public partial class OpenIddictServerAspNetCoreIntegrationTests : OpenIddictServerIntegrationTests
{
    [Fact]
    public async Task HandleRegistrationRequest_PassthroughModeAllowsApprovingRegistrationsUsingSignIn()
    {
        // Arrange
        OpenIddictApplicationDescriptor? descriptor = null;

        await using var server = await CreateServerAsync(options =>
        {
            options.SetRegistrationEndpointUris("/signin")
                   .EnableDynamicClientRegistration()
                   .AllowAnonymousClientRegistration();

            options.UseAspNetCore().EnableRegistrationEndpointPassthrough();

            options.Services.AddSingleton(CreateApplicationManager(mock =>
                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
                    .Callback((OpenIddictApplicationDescriptor value, CancellationToken _) => descriptor = value)
                    .ReturnsAsync(new OpenIddictApplication())));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Post, "/signin", """{"grant_types":["client_credentials"]}""");

        // Assert
        Assert.Equal(HttpStatusCode.Created, client.ResponseStatusCode);
        Assert.NotNull(descriptor);
        Assert.Equal(descriptor.ClientId, (string?) response[ClientMetadata.ClientId]);
        Assert.NotNull((string?) response[ClientMetadata.RegistrationAccessToken]);
    }

    [Fact]
    public async Task HandleRegistrationRequest_PassthroughModeAllowsRejectingRegistrationsUsingChallenge()
    {
        // Arrange
        var manager = CreateApplicationManager();

        await using var server = await CreateServerAsync(options =>
        {
            options.SetRegistrationEndpointUris("/challenge")
                   .EnableDynamicClientRegistration()
                   .AllowAnonymousClientRegistration();

            options.UseAspNetCore().EnableRegistrationEndpointPassthrough();

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Post, "/challenge", """{"grant_types":["client_credentials"]}""");

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, client.ResponseStatusCode);
        Assert.Equal(Errors.AccessDenied, response.Error);

        Mock.Get(manager).Verify(mock => mock.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()), Times.Never());
    }
}