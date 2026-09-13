/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OpenIddict.Core;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    [Theory]
    [InlineData(nameof(HttpMethod.Delete))]
    [InlineData(nameof(HttpMethod.Get))]
    [InlineData(nameof(HttpMethod.Head))]
    [InlineData(nameof(HttpMethod.Options))]
    [InlineData(nameof(HttpMethod.Put))]
    [InlineData(nameof(HttpMethod.Trace))]
    public async Task ExtractBackchannelAuthenticationRequest_UnexpectedMethodReturnsAnError(string method)
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureBackchannelAuthentication);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendAsync(method, "/connect/ciba", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2084), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2084), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateBackchannelAuthenticationRequest_MissingOpenIdScopeCausesAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureBackchannelAuthentication);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/ciba", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            LoginHint = "bob@fabrikam.com",
            Scope = Scopes.Profile
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2215), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2215), response.ErrorUri);
    }

    [Theory]
    [InlineData(null, null, null)]
    [InlineData("bob@fabrikam.com", "token", null)]
    [InlineData("bob@fabrikam.com", null, "id_token")]
    [InlineData(null, "token", "id_token")]
    public async Task ValidateBackchannelAuthenticationRequest_InvalidHintsCauseAnError(string? hint, string? token, string? identity)
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureBackchannelAuthentication);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/ciba", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            IdTokenHint = identity,
            LoginHint = hint,
            LoginHintToken = token,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2214), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2214), response.ErrorUri);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-10")]
    [InlineData("value")]
    public async Task ValidateBackchannelAuthenticationRequest_InvalidRequestedExpiryCausesAnError(string expiry)
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureBackchannelAuthentication);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/ciba", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            LoginHint = "bob@fabrikam.com",
            Scope = Scopes.OpenId,
            [Parameters.RequestedExpiry] = expiry
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2052(Parameters.RequestedExpiry), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2052), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateBackchannelAuthenticationRequest_RequestParameterCausesAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureBackchannelAuthentication);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/ciba", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Request = "eyJhbGciOiJub25lIn0.e30.",
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.RequestNotSupported, response.Error);
        Assert.Equal(SR.FormatID2028(Parameters.Request), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2028), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateBackchannelAuthenticationRequest_MissingClientIdCausesAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureBackchannelAuthentication);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/ciba", new OpenIddictRequest
        {
            LoginHint = "bob@fabrikam.com",
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidClient, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.ClientId), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Fact]
    public async Task HandleBackchannelAuthenticationRequest_ThrowsAnExceptionWhenNoPrincipalIsAttached()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureBackchannelAuthentication);
        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await client.PostAsync("/connect/ciba", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                LoginHint = "bob@fabrikam.com",
                Scope = Scopes.OpenId
            });
        });

        Assert.Equal(SR.GetResourceString(SR.ID0531), exception.Message);
    }

    [Fact]
    public async Task HandleBackchannelAuthenticationRequest_AllowsRejectingRequest()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureBackchannelAuthentication(options);

            options.AddEventHandler<HandleBackchannelAuthenticationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(Errors.UnknownUserId, "The user is unknown.");

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/ciba", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            LoginHint = "bob@fabrikam.com",
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnknownUserId, response.Error);
        Assert.Equal("The user is unknown.", response.ErrorDescription);
    }

    [Fact]
    public async Task HandleBackchannelAuthenticationRequest_ReturnsAuthenticationRequestIdentifier()
    {
        // Arrange
        var token = new OpenIddictToken();
        OpenIddictTokenDescriptor? created = null;

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureBackchannelAuthentication(options);

            options.Services.AddSingleton(CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .Callback((OpenIddictTokenDescriptor descriptor, CancellationToken _) => created = descriptor)
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);
            }));

            options.AddEventHandler<HandleBackchannelAuthenticationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("bob@fabrikam.com", context.Request.LoginHint);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/ciba", new OpenIddictRequest
        {
            BindingMessage = "W4SCT",
            ClientId = "Fabrikam",
            LoginHint = "bob@fabrikam.com",
            RequestedExpiry = 120,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(response.AuthReqId);
        Assert.InRange(response.ExpiresIn ?? 0, 115, 120);
        Assert.Equal(5, response.Interval);

        Assert.NotNull(created);
        Assert.Equal(Statuses.Inactive, created.Status);
        Assert.Equal("Bob le Magnifique", created.Subject);
        Assert.Equal(TokenTypeIdentifiers.Private.AuthenticationRequestId, created.Type);
        Assert.Equal("W4SCT", created.Principal?.GetClaim(Claims.Private.BindingMessage));
    }

    [Fact]
    public async Task ValidateTokenRequest_MissingAuthenticationRequestIdCausesAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureBackchannelAuthentication);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            GrantType = GrantTypes.Ciba
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2216(Parameters.AuthReqId), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2216), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateTokenRequest_MissingClientIdCausesAnErrorForCibaRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureBackchannelAuthentication);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            AuthReqId = "8C8F4F4B-6F0A-4E2B-B2D3-3A2DBA3C0B29",
            GrantType = GrantTypes.Ciba
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.ClientId), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Theory]
    [InlineData(null, Errors.AuthorizationPending)]
    [InlineData(-60, Errors.AuthorizationPending)]
    [InlineData(-2, Errors.SlowDown)]
    public async Task ValidateTokenRequest_PendingAuthenticationRequestCausesAnError(int? lastPolling, string error)
    {
        // Arrange
        var token = new OpenIddictToken();
        var properties = ImmutableDictionary.CreateBuilder<string, JsonElement>(StringComparer.Ordinal);

        if (lastPolling is not null)
        {
            properties.Add(Properties.LastPollingDate, JsonSerializer.SerializeToElement(
                (TimeProvider.System.GetUtcNow() + TimeSpan.FromSeconds(lastPolling.Value)).ToUnixTimeSeconds()));
        }

        var manager = CreateAuthenticationRequestTokenManager(token, Statuses.Inactive, properties.ToImmutable());

        await using var server = await CreateServerAsync(options => ConfigureAuthenticationRequestValidation(options, manager));
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            AuthReqId = "8C8F4F4B-6F0A-4E2B-B2D3-3A2DBA3C0B29",
            ClientId = "Fabrikam",
            GrantType = GrantTypes.Ciba
        });

        // Assert
        Assert.Equal(error, response.Error);

        Mock.Get(manager).Verify(manager => manager.UpdateAsync(token, It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()),
            error is Errors.SlowDown ? Times.Never() : Times.Once());
    }

    [Fact]
    public async Task ValidateTokenRequest_PollingIntervalIsNotEnforcedWhenDisabled()
    {
        // Arrange
        var token = new OpenIddictToken();
        var manager = CreateAuthenticationRequestTokenManager(token, Statuses.Inactive,
            ImmutableDictionary.Create<string, JsonElement>(StringComparer.Ordinal));

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureAuthenticationRequestValidation(options, manager);
            options.SetPollingInterval(null);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            AuthReqId = "8C8F4F4B-6F0A-4E2B-B2D3-3A2DBA3C0B29",
            ClientId = "Fabrikam",
            GrantType = GrantTypes.Ciba
        });

        // Assert
        Assert.Equal(Errors.AuthorizationPending, response.Error);

        Mock.Get(manager).Verify(manager => manager.GetPropertiesAsync(token, It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task ValidateTokenRequest_RejectedAuthenticationRequestCausesAnAccessDeniedError()
    {
        // Arrange
        var token = new OpenIddictToken();
        var manager = CreateAuthenticationRequestTokenManager(token, Statuses.Rejected,
            ImmutableDictionary.Create<string, JsonElement>(StringComparer.Ordinal));

        await using var server = await CreateServerAsync(options => ConfigureAuthenticationRequestValidation(options, manager));
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            AuthReqId = "8C8F4F4B-6F0A-4E2B-B2D3-3A2DBA3C0B29",
            ClientId = "Fabrikam",
            GrantType = GrantTypes.Ciba
        });

        // Assert
        Assert.Equal(Errors.AccessDenied, response.Error);
    }

    [Fact]
    public async Task ValidateTokenRequest_ExpiredAuthenticationRequestCausesAnExpiredTokenError()
    {
        // Arrange
        var token = new OpenIddictToken();
        var manager = CreateAuthenticationRequestTokenManager(token, Statuses.Inactive,
            ImmutableDictionary.Create<string, JsonElement>(StringComparer.Ordinal),
            expiration: TimeProvider.System.GetUtcNow() - TimeSpan.FromDays(1));

        await using var server = await CreateServerAsync(options => ConfigureAuthenticationRequestValidation(options, manager));
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            AuthReqId = "8C8F4F4B-6F0A-4E2B-B2D3-3A2DBA3C0B29",
            ClientId = "Fabrikam",
            GrantType = GrantTypes.Ciba
        });

        // Assert
        Assert.Equal(Errors.ExpiredToken, response.Error);
    }

    [Fact]
    public async Task HandleConfigurationRequest_BackchannelAuthenticationMetadataIsReturned()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureBackchannelAuthentication);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal("http://localhost/connect/ciba", (string?) response[Metadata.BackchannelAuthenticationEndpoint]);
        Assert.Equal([BackchannelTokenDeliveryModes.Poll], (ImmutableArray<string?>?) response[Metadata.BackchannelTokenDeliveryModesSupported]);
        Assert.False((bool) response[Metadata.BackchannelUserCodeParameterSupported]);
        Assert.Contains(GrantTypes.Ciba, (ImmutableArray<string?>?) response[Metadata.GrantTypesSupported] ?? [], StringComparer.Ordinal);
    }

    private void ConfigureBackchannelAuthentication(OpenIddictServerBuilder options)
    {
        options.SetBackchannelAuthenticationEndpointUris("/connect/ciba")
               .AllowClientInitiatedBackchannelAuthenticationFlow()
               .SetIssuer(new Uri("https://www.contoso.com/", UriKind.Absolute));

        options.DisableAuthorizationStorage();

        options.Services.AddSingleton(CreateApplicationManager(mock =>
        {
            var application = new OpenIddictApplication();

            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>(StringComparer.Ordinal));
        }));
    }

    private void ConfigureAuthenticationRequestValidation(OpenIddictServerBuilder options, OpenIddictTokenManager<OpenIddictToken> manager)
    {
        ConfigureBackchannelAuthentication(options);

        options.AddEventHandler<ValidateTokenContext>(builder =>
        {
            builder.UseInlineHandler(context =>
            {
                Assert.Equal([TokenTypeIdentifiers.Private.AuthenticationRequestId], context.ValidTokenTypes);

                context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                    .SetClaim(Claims.Subject, "Bob le Magnifique")
                    .SetPresenters("Fabrikam")
                    .SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                    .SetTokenType(TokenTypeIdentifiers.Private.AuthenticationRequestId);

                return ValueTask.CompletedTask;
            });

            builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
        });

        options.Services.AddSingleton(manager);
    }

    private OpenIddictTokenManager<OpenIddictToken> CreateAuthenticationRequestTokenManager(
        OpenIddictToken token, string status, ImmutableDictionary<string, JsonElement> properties, DateTimeOffset? expiration = null)
        => CreateTokenManager(mock =>
        {
            mock.Setup(manager => manager.FindByReferenceIdAsync("8C8F4F4B-6F0A-4E2B-B2D3-3A2DBA3C0B29", It.IsAny<CancellationToken>()))
                .ReturnsAsync(token);

            mock.Setup(manager => manager.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync(TokenTypeIdentifiers.Private.AuthenticationRequestId);

            mock.Setup(manager => manager.HasTypeAsync(token, TokenTypeIdentifiers.Private.AuthenticationRequestId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

            mock.Setup(manager => manager.GetPayloadAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync("payload");

            mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                .ReturnsAsync(token);

            mock.Setup(manager => manager.GetExpirationDateAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync(expiration ?? TimeProvider.System.GetUtcNow() + TimeSpan.FromMinutes(5));

            mock.Setup(manager => manager.HasStatusAsync(token, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync((object _, string value, CancellationToken _) => string.Equals(value, status, StringComparison.Ordinal));

            mock.Setup(manager => manager.GetPropertiesAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync(properties);
        });
}
