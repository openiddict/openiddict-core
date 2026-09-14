/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using OpenIddict.Core;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers.Registration;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    private const string RegistrationEndpoint = "/connect/register";

    [Fact]
    public async Task HandleConfigurationRequest_RegistrationEndpointIsReturned()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRegistration);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal("http://localhost/connect/register", (string?) response[Metadata.RegistrationEndpoint]);
    }

    [Theory]
    [InlineData("PATCH")]
    [InlineData("OPTIONS")]
    public async Task ExtractRegistrationRequest_UnexpectedMethodReturnsAnError(string method)
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRegistration);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(new HttpMethod(method), RegistrationEndpoint, "{}");

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2084), response.ErrorDescription);
    }

    [Fact]
    public async Task ExtractRegistrationRequest_InvalidPayloadReturnsAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRegistration);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Post, RegistrationEndpoint, "[1, 2]");

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2419), response.ErrorDescription);
    }

    [Fact]
    public async Task ExtractRegistrationRequest_FormPayloadReturnsAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRegistration);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync(RegistrationEndpoint, new OpenIddictRequest
        {
            ["client_name"] = "Fabrikam"
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2082("Content-Type"), response.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRegistrationRequest_MissingInitialAccessTokenIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options
            .SetRegistrationEndpointUris(RegistrationEndpoint)
            .EnableDynamicClientRegistration()
            .SetInitialAccessTokenScopes("dcr"));

        await using var client = await server.CreateClientAsync();

        // Act
        await client.SendJsonAsync(HttpMethod.Post, RegistrationEndpoint, """{"grant_types":["client_credentials"]}""");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, client.ResponseStatusCode);
        Assert.StartsWith(Schemes.Bearer, Assert.Single(client.ResponseHeaders["WWW-Authenticate"]), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ValidateRegistrationRequest_InvalidInitialAccessTokenIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options
            .SetRegistrationEndpointUris(RegistrationEndpoint)
            .EnableDynamicClientRegistration()
            .SetInitialAccessTokenScopes("dcr"));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Post, RegistrationEndpoint,
            """{"grant_types":["client_credentials"]}""", token: "invalid-token");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, client.ResponseStatusCode);
        Assert.Equal(Errors.InvalidToken, response.Error);
    }

    [Fact]
    public async Task ValidateRegistrationRequest_InitialAccessTokenWithoutDedicatedScopeIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.SetRegistrationEndpointUris(RegistrationEndpoint)
                   .EnableDynamicClientRegistration()
                   .SetInitialAccessTokenScopes("dcr");

            options.AddEventHandler<ValidateRegistrationRequestContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.InitialAccessTokenPrincipal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetScopes("api");

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateInitialAccessToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Post, RegistrationEndpoint, """{"grant_types":["client_credentials"]}""");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, client.ResponseStatusCode);
        Assert.Equal(Errors.InsufficientScope, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2402), response.ErrorDescription);
    }

    [Theory]
    [InlineData("""{"redirect_uris":["/relative"]}""", Errors.InvalidRedirectUri, SR.ID2405)]
    [InlineData("""{"redirect_uris":["https://fabrikam.com/#fragment"]}""", Errors.InvalidRedirectUri, SR.ID2405)]
    [InlineData("""{"grant_types":["authorization_code"]}""", Errors.InvalidRedirectUri, SR.ID2406)]
    [InlineData("""{"grant_types":["urn:custom"]}""", Errors.InvalidClientMetadata, SR.ID2404)]
    [InlineData("""{"grant_types":["client_credentials"],"response_types":["code"]}""", Errors.InvalidClientMetadata, SR.ID2407)]
    [InlineData("""{"grant_types":["client_credentials"],"token_endpoint_auth_method":"none"}""", Errors.InvalidClientMetadata, SR.ID2408)]
    [InlineData("""{"grant_types":["client_credentials"],"token_endpoint_auth_method":"client_secret_jwt"}""", Errors.InvalidClientMetadata, SR.ID2404)]
    [InlineData("""{"grant_types":["client_credentials"],"token_endpoint_auth_method":"private_key_jwt"}""", Errors.InvalidClientMetadata, SR.ID2417)]
    [InlineData("""{"grant_types":["client_credentials"],"jwks_uri":"https://fabrikam.com/jwks"}""", Errors.InvalidClientMetadata, SR.ID2404)]
    [InlineData("""{"grant_types":["client_credentials"],"jwks":{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}}""", Errors.InvalidClientMetadata, SR.ID2418)]
    [InlineData("""{"grant_types":["client_credentials"],"client_name":42}""", Errors.InvalidClientMetadata, SR.ID2403)]
    [InlineData("""{"grant_types":["client_credentials"],"logo_uri":"ftp://fabrikam.com/logo"}""", Errors.InvalidClientMetadata, SR.ID2403)]
    [InlineData("""{"grant_types":["client_credentials"],"subject_type":"pairwise"}""", Errors.InvalidClientMetadata, SR.ID2404)]
    public async Task ValidateRegistrationRequest_InvalidClientMetadataAreRejected(string payload, string error, string identifier)
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRegistration);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Post, RegistrationEndpoint, payload);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, client.ResponseStatusCode);
        Assert.Equal(error, response.Error);
        Assert.Equal(SR.FormatID8000(identifier), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateRegistrationRequest_UnregisteredScopeIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);

            options.Services.AddSingleton(CreateScopeManager(mock =>
                mock.Setup(manager => manager.FindByNamesAsync(It.IsAny<ImmutableArray<string>>(), It.IsAny<CancellationToken>()))
                    .Returns(AsyncEnumerable.Empty<OpenIddictScope>())));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Post, RegistrationEndpoint,
            """{"grant_types":["client_credentials"],"scope":"unregistered_scope"}""");

        // Assert
        Assert.Equal(Errors.InvalidClientMetadata, response.Error);
        Assert.Equal(SR.FormatID2404(ClientMetadata.Scope, "unregistered_scope"), response.ErrorDescription);
    }

    [Fact]
    public async Task HandleRegistrationRequest_ConfidentialClientIsRegistered()
    {
        // Arrange
        var application = new OpenIddictApplication();
        OpenIddictApplicationDescriptor? descriptor = null;
        OpenIddictTokenDescriptor? token = null;

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);

            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
                    .Callback((OpenIddictApplicationDescriptor value, CancellationToken _) => descriptor = value)
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.GetIdAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
            }));

            options.Services.AddSingleton(CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .Callback((OpenIddictTokenDescriptor value, CancellationToken _) => token = value)
                    .ReturnsAsync(new OpenIddictToken());
            }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Post, RegistrationEndpoint, """
            {
              "grant_types": ["client_credentials"],
              "client_name": "Fabrikam",
              "client_name#fr": "Fabrikam (FR)",
              "contacts": ["admin@fabrikam.com"],
              "software_id": "4NRB1-0XZABZI9E6-5SM3R",
              "backchannel_logout_uri": "https://fabrikam.com/logout",
              "unknown_metadata": "value"
            }
            """);

        // Assert
        Assert.Equal(HttpStatusCode.Created, client.ResponseStatusCode);
        Assert.NotNull(descriptor);
        Assert.NotNull(token);

        Assert.Equal(descriptor.ClientId, (string?) response[ClientMetadata.ClientId]);
        Assert.False(string.IsNullOrEmpty((string?) response[ClientMetadata.ClientSecret]));
        Assert.Equal(descriptor.ClientSecret, (string?) response[ClientMetadata.ClientSecret]);
        Assert.Equal(0, (long?) response[ClientMetadata.ClientSecretExpiresAt]);
        Assert.NotNull((long?) response[ClientMetadata.ClientIdIssuedAt]);
        Assert.Equal("Fabrikam", (string?) response[ClientMetadata.ClientName]);
        Assert.Equal(ClientAuthenticationMethods.ClientSecretBasic, (string?) response[ClientMetadata.TokenEndpointAuthMethod]);
        Assert.Equal<IEnumerable<string?>?>([GrantTypes.ClientCredentials], (ImmutableArray<string?>?) response[ClientMetadata.GrantTypes]);
        Assert.Null(response["unknown_metadata"]);
        Assert.Equal(token.ReferenceId, (string?) response[ClientMetadata.RegistrationAccessToken]);
        Assert.Equal("http://localhost/connect/register?client_id=" + Uri.EscapeDataString(descriptor.ClientId!),
            (string?) response[ClientMetadata.RegistrationClientUri]);

        Assert.Equal(ClientTypes.Confidential, descriptor.ClientType);
        Assert.Equal("Fabrikam", descriptor.DisplayName);
        Assert.Equal("Fabrikam (FR)", descriptor.DisplayNames[System.Globalization.CultureInfo.GetCultureInfo("fr")]);
        Assert.Contains(Permissions.GrantTypes.ClientCredentials, descriptor.Permissions);
        Assert.Contains(Permissions.Endpoints.Token, descriptor.Permissions);
        Assert.Contains(Permissions.Endpoints.Introspection, descriptor.Permissions);
        Assert.Contains(Permissions.Endpoints.Registration, descriptor.Permissions);
        Assert.DoesNotContain(Permissions.Endpoints.Authorization, descriptor.Permissions);
        Assert.Equal("https://fabrikam.com/logout", descriptor.Settings[Settings.Logout.BackchannelUri]);
        Assert.True(descriptor.Properties.ContainsKey(Properties.ClientMetadata));

        Assert.Equal("3E228451-1555-46F7-A471-951EFBA23A56", token.ApplicationId);
        Assert.Equal(TokenTypeIdentifiers.Private.RegistrationAccessToken, token.Type);
        Assert.Equal(Statuses.Valid, token.Status);
        Assert.Null(token.ExpirationDate);
    }

    [Fact]
    public async Task HandleRegistrationRequest_PublicClientIsRegistered()
    {
        // Arrange
        OpenIddictApplicationDescriptor? descriptor = null;

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);
            options.RegisterScopes("api");

            options.Services.AddSingleton(CreateApplicationManager(mock =>
                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
                    .Callback((OpenIddictApplicationDescriptor value, CancellationToken _) => descriptor = value)
                    .ReturnsAsync(new OpenIddictApplication())));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Post, RegistrationEndpoint, """
            {
              "redirect_uris": ["com.fabrikam.app:/callback"],
              "response_types": ["code"],
              "grant_types": ["authorization_code", "refresh_token"],
              "token_endpoint_auth_method": "none",
              "application_type": "native",
              "scope": "openid offline_access api",
              "require_pushed_authorization_requests": true
            }
            """);

        // Assert
        Assert.Equal(HttpStatusCode.Created, client.ResponseStatusCode);
        Assert.NotNull(descriptor);
        Assert.Null((string?) response[ClientMetadata.ClientSecret]);
        Assert.Null(response[ClientMetadata.ClientSecretExpiresAt]);

        Assert.Equal(ClientTypes.Public, descriptor.ClientType);
        Assert.Equal(ApplicationTypes.Native, descriptor.ApplicationType);
        Assert.Null(descriptor.ClientSecret);
        Assert.Contains(new Uri("com.fabrikam.app:/callback"), descriptor.RedirectUris);
        Assert.Contains(Permissions.Endpoints.Authorization, descriptor.Permissions);
        Assert.Contains(Permissions.Endpoints.Token, descriptor.Permissions);
        Assert.DoesNotContain(Permissions.Endpoints.Introspection, descriptor.Permissions);
        Assert.Contains(Permissions.GrantTypes.AuthorizationCode, descriptor.Permissions);
        Assert.Contains(Permissions.GrantTypes.RefreshToken, descriptor.Permissions);
        Assert.Contains(Permissions.ResponseTypes.Code, descriptor.Permissions);
        Assert.Contains(Permissions.Prefixes.Scope + "api", descriptor.Permissions);
        Assert.DoesNotContain(Permissions.Prefixes.Scope + Scopes.OpenId, descriptor.Permissions);
        Assert.Contains(Requirements.Features.PushedAuthorizationRequests, descriptor.Requirements);
    }

    [Fact]
    public async Task HandleRegistrationRequest_PolicyHandlerCanAmendTheDescriptor()
    {
        // Arrange
        OpenIddictApplicationDescriptor? descriptor = null;

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);

            options.AddEventHandler<ValidateRegistrationRequestContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.Descriptor.Permissions.Remove(Permissions.Endpoints.Introspection);
                    context.Descriptor.ConsentType = ConsentTypes.Explicit;

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(AttachApplicationDescriptor.Descriptor.Order + 500);
            });

            options.Services.AddSingleton(CreateApplicationManager(mock =>
                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
                    .Callback((OpenIddictApplicationDescriptor value, CancellationToken _) => descriptor = value)
                    .ReturnsAsync(new OpenIddictApplication())));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        await client.SendJsonAsync(HttpMethod.Post, RegistrationEndpoint, """{"grant_types":["client_credentials"]}""");

        // Assert
        Assert.Equal(HttpStatusCode.Created, client.ResponseStatusCode);
        Assert.NotNull(descriptor);
        Assert.DoesNotContain(Permissions.Endpoints.Introspection, descriptor.Permissions);
        Assert.Equal(ConsentTypes.Explicit, descriptor.ConsentType);
    }

    [Fact]
    public async Task HandleRegistrationRequest_PolicyHandlerCanRejectTheRequest()
    {
        // Arrange
        var manager = CreateApplicationManager();

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);

            options.AddEventHandler<ValidateRegistrationRequestContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.Reject(Errors.InvalidClientMetadata, "The client name is not allowed.");

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(AttachApplicationDescriptor.Descriptor.Order + 500);
            });

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Post, RegistrationEndpoint, """{"grant_types":["client_credentials"]}""");

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, client.ResponseStatusCode);
        Assert.Equal(Errors.InvalidClientMetadata, response.Error);
        Assert.Equal("The client name is not allowed.", response.ErrorDescription);

        Mock.Get(manager).Verify(mock => mock.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task HandleRegistrationRequest_ValidationExceptionIsReturnedAsInvalidClientMetadata()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);

            options.Services.AddSingleton(CreateApplicationManager(mock =>
                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
                    .ThrowsAsync(new OpenIddictExceptions.ValidationException("Invalid application.",
                        [new System.ComponentModel.DataAnnotations.ValidationResult(SR.GetResourceString(SR.ID2113))]))));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Post, RegistrationEndpoint, """{"grant_types":["client_credentials"]}""");

        // Assert
        Assert.Equal(Errors.InvalidClientMetadata, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2416), response.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRegistrationRequest_MissingSoftwareStatementIsRejectedWhenRequired()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);

            options.RequireSoftwareStatement()
                   .AddSoftwareStatementSigningKey(new RsaSecurityKey(RSA.Create(2048)));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Post, RegistrationEndpoint, """{"grant_types":["client_credentials"]}""");

        // Assert
        Assert.Equal(Errors.InvalidSoftwareStatement, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2411), response.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRegistrationRequest_UntrustedSoftwareStatementIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);
            options.AddSoftwareStatementSigningKey(new RsaSecurityKey(RSA.Create(2048)) { KeyId = "trusted" });
        });

        await using var client = await server.CreateClientAsync();

        var statement = CreateSoftwareStatement(new RsaSecurityKey(RSA.Create(2048)) { KeyId = "untrusted" }, "https://issuer.example.com/");

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Post, RegistrationEndpoint,
            $$"""{"grant_types":["client_credentials"],"software_statement":"{{statement}}"}""");

        // Assert
        Assert.Equal(Errors.UnapprovedSoftwareStatement, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2410), response.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRegistrationRequest_SoftwareStatementWithUntrustedIssuerIsRejected()
    {
        // Arrange
        var key = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "trusted" };

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);
            options.AddSoftwareStatementSigningKey(key, "https://issuer.example.com/");
        });

        await using var client = await server.CreateClientAsync();

        var statement = CreateSoftwareStatement(key, "https://attacker.example.com/");

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Post, RegistrationEndpoint,
            $$"""{"grant_types":["client_credentials"],"software_statement":"{{statement}}"}""");

        // Assert
        Assert.Equal(Errors.UnapprovedSoftwareStatement, response.Error);
    }

    [Fact]
    public async Task HandleRegistrationRequest_SoftwareStatementClaimsTakePrecedence()
    {
        // Arrange
        var key = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "trusted" };
        OpenIddictApplicationDescriptor? descriptor = null;

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);

            options.RequireSoftwareStatement()
                   .AddSoftwareStatementSigningKey(key, "https://issuer.example.com/");

            options.Services.AddSingleton(CreateApplicationManager(mock =>
                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
                    .Callback((OpenIddictApplicationDescriptor value, CancellationToken _) => descriptor = value)
                    .ReturnsAsync(new OpenIddictApplication())));
        });

        await using var client = await server.CreateClientAsync();

        var statement = CreateSoftwareStatement(key, "https://issuer.example.com/", new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [ClientMetadata.ClientName] = "Contoso",
            [ClientMetadata.SoftwareId] = "contoso-app"
        });

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Post, RegistrationEndpoint,
            $$"""{"grant_types":["client_credentials"],"client_name":"Fabrikam","software_statement":"{{statement}}"}""");

        // Assert
        Assert.Equal(HttpStatusCode.Created, client.ResponseStatusCode);
        Assert.NotNull(descriptor);
        Assert.Equal("Contoso", descriptor.DisplayName);
        Assert.Equal("contoso-app", (string?) response[ClientMetadata.SoftwareId]);
        Assert.Null(response[ClientMetadata.SoftwareStatement]);
    }

    [Fact]
    public async Task ValidateRegistrationRequest_ClientConfigurationRequestWithoutClientIdIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRegistration);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Get, RegistrationEndpoint, payload: null, token: "registration-token");

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.ClientId), response.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRegistrationRequest_MissingRegistrationAccessTokenIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRegistration);
        await using var client = await server.CreateClientAsync();

        // Act
        await client.SendJsonAsync(HttpMethod.Get, RegistrationEndpoint + "?client_id=Fabrikam", payload: null);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, client.ResponseStatusCode);
    }

    [Theory]
    [InlineData("unknown-token", "Fabrikam")]
    [InlineData("registration-token", "Contoso")]
    public async Task ValidateRegistrationRequest_InvalidRegistrationAccessTokenIsRejected(string token, string identifier)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);
            ConfigureRegisteredClient(options);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Get, RegistrationEndpoint + "?client_id=" + identifier, payload: null, token);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, client.ResponseStatusCode);
        Assert.Equal(Errors.InvalidToken, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2400), response.ErrorDescription);
    }

    [Fact]
    public async Task HandleRegistrationRequest_ClientIsReadAndRegistrationAccessTokenIsRotated()
    {
        // Arrange
        var (application, token) = (new OpenIddictApplication(), new OpenIddictToken());
        OpenIddictTokenDescriptor? rotated = null;
        var tokens = CreateTokenManager(mock =>
        {
            ConfigureRegistrationToken(mock, token);

            mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                .Callback((OpenIddictTokenDescriptor value, CancellationToken _) => rotated = value)
                .ReturnsAsync(new OpenIddictToken());

            mock.Setup(manager => manager.TryRevokeAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);
        });

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);
            options.SetRegistrationAccessTokenLifetime(TimeSpan.FromDays(30));

            options.Services.AddSingleton(CreateRegisteredApplicationManager(application));
            options.Services.AddSingleton(tokens);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Get, RegistrationEndpoint + "?client_id=Fabrikam", payload: null, "registration-token");

        // Assert
        Assert.Equal(HttpStatusCode.OK, client.ResponseStatusCode);
        Assert.Equal("Fabrikam", (string?) response[ClientMetadata.ClientId]);
        Assert.Equal("Fabrikam client", (string?) response[ClientMetadata.ClientName]);
        Assert.Equal(1700000000, (long?) response[ClientMetadata.ClientIdIssuedAt]);
        Assert.Null(response[ClientMetadata.ClientSecret]);
        Assert.Equal(0, (long?) response[ClientMetadata.ClientSecretExpiresAt]);
        Assert.NotNull(rotated);
        Assert.Equal(rotated.ReferenceId, (string?) response[ClientMetadata.RegistrationAccessToken]);
        Assert.NotEqual("registration-token", rotated.ReferenceId, StringComparer.Ordinal);
        Assert.NotNull(rotated.ExpirationDate);

        Mock.Get(tokens).Verify(manager => manager.TryRevokeAsync(token, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Theory]
    [InlineData(ClientMetadata.RegistrationAccessToken, "\"token\"")]
    [InlineData(ClientMetadata.RegistrationClientUri, "\"http://localhost/connect/register\"")]
    [InlineData(ClientMetadata.ClientIdIssuedAt, "1700000000")]
    [InlineData(ClientMetadata.ClientSecretExpiresAt, "0")]
    public async Task ValidateRegistrationRequest_ServerManagedMetadataAreRejectedForUpdates(string name, string value)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);
            ConfigureRegisteredClient(options);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Put, RegistrationEndpoint + "?client_id=Fabrikam",
            $$"""{"client_id":"Fabrikam","grant_types":["client_credentials"],"{{name}}":{{value}}}""", "registration-token");

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2412(name), response.ErrorDescription);
    }

    [Fact]
    public async Task ExtractRegistrationRequest_MismatchingClientIdIsRejectedForUpdates()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRegistration);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Put, RegistrationEndpoint + "?client_id=Fabrikam",
            """{"client_id":"Contoso","grant_types":["client_credentials"]}""", "registration-token");

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2413(Parameters.ClientId), response.ErrorDescription);
    }

    [Fact]
    public async Task HandleRegistrationRequest_ClientIsUpdatedWithFullReplaceSemantics()
    {
        // Arrange
        var (application, token) = (new OpenIddictApplication(), new OpenIddictToken());
        OpenIddictApplicationDescriptor? updated = null;

        var applications = CreateRegisteredApplicationManager(application, mock =>
            mock.Setup(manager => manager.UpdateAsync(application, It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
                .Callback((OpenIddictApplication _, OpenIddictApplicationDescriptor value, CancellationToken _) => updated = value)
                .Returns(ValueTask.CompletedTask));

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);

            options.Services.AddSingleton(applications);
            options.Services.AddSingleton(CreateTokenManager(mock => ConfigureRegistrationToken(mock, token)));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Put, RegistrationEndpoint + "?client_id=Fabrikam",
            """{"client_id":"Fabrikam","grant_types":["client_credentials"],"client_name":"Updated"}""", "registration-token");

        // Assert
        Assert.Equal(HttpStatusCode.OK, client.ResponseStatusCode);
        Assert.NotNull(updated);
        Assert.Equal("Fabrikam", updated.ClientId);
        Assert.Equal("Updated", updated.DisplayName);
        Assert.Equal("hashed-secret", updated.ClientSecret);
        Assert.Equal(ConsentTypes.Systematic, updated.ConsentType);
        Assert.Empty(updated.RedirectUris);
        Assert.Equal("Updated", (string?) response[ClientMetadata.ClientName]);
        Assert.Equal(1700000000, (long?) response[ClientMetadata.ClientIdIssuedAt]);
        Assert.Null(response[ClientMetadata.ClientSecret]);
    }

    [Fact]
    public async Task HandleRegistrationRequest_ClientIsDeleted()
    {
        // Arrange
        var (application, token) = (new OpenIddictApplication(), new OpenIddictToken());

        var applications = CreateRegisteredApplicationManager(application);
        var tokens = CreateTokenManager(mock => ConfigureRegistrationToken(mock, token));
        var authorizations = CreateAuthorizationManager();

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);

            options.Services.AddSingleton(applications);
            options.Services.AddSingleton(tokens);
            options.Services.AddSingleton(authorizations);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        await client.SendJsonAsync(HttpMethod.Delete, RegistrationEndpoint + "?client_id=Fabrikam", payload: null, "registration-token");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, client.ResponseStatusCode);

        Mock.Get(applications).Verify(manager => manager.DeleteAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        Mock.Get(tokens).Verify(manager => manager.RevokeByApplicationIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.Once());
        Mock.Get(authorizations).Verify(manager => manager.RevokeByApplicationIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateRegistrationRequest_ClientWithoutRegistrationPermissionIsRejected()
    {
        // Arrange
        var (application, token) = (new OpenIddictApplication(), new OpenIddictToken());

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRegistration(options);

            options.Configure(options => options.IgnoreEndpointPermissions = false);

            options.Services.AddSingleton(CreateRegisteredApplicationManager(application, mock =>
                mock.Setup(manager => manager.HasPermissionAsync(application, Permissions.Endpoints.Registration, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false)));

            options.Services.AddSingleton(CreateTokenManager(mock => ConfigureRegistrationToken(mock, token)));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendJsonAsync(HttpMethod.Get, RegistrationEndpoint + "?client_id=Fabrikam", payload: null, "registration-token");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, client.ResponseStatusCode);
        Assert.Equal(Errors.InsufficientAccess, response.Error);
    }

    private static void ConfigureRegistration(OpenIddictServerBuilder options)
        => options.SetRegistrationEndpointUris(RegistrationEndpoint)
                  .EnableDynamicClientRegistration()
                  .AllowAnonymousClientRegistration();

    private void ConfigureRegisteredClient(OpenIddictServerBuilder options)
    {
        var (application, token) = (new OpenIddictApplication(), new OpenIddictToken());

        options.Services.AddSingleton(CreateRegisteredApplicationManager(application));
        options.Services.AddSingleton(CreateTokenManager(mock => ConfigureRegistrationToken(mock, token)));
    }

    private OpenIddictApplicationManager<OpenIddictApplication> CreateRegisteredApplicationManager(
        OpenIddictApplication application, Action<Mock<OpenIddictApplicationManager<OpenIddictApplication>>>? configuration = null)
        => CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.GetIdAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

            mock.Setup(manager => manager.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync("Fabrikam");

            mock.Setup(manager => manager.HasPermissionAsync(application, Permissions.Endpoints.Registration, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetPropertiesAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.CreateRange(StringComparer.Ordinal, [
                    KeyValuePair.Create(Properties.ClientMetadata, JsonSerializer.Deserialize<JsonElement>("""
                        {
                          "client_name": "Fabrikam client",
                          "grant_types": ["client_credentials"],
                          "token_endpoint_auth_method": "client_secret_basic",
                          "client_id_issued_at": 1700000000
                        }
                        """))]));

            mock.Setup(manager => manager.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), application, It.IsAny<CancellationToken>()))
                .Callback((OpenIddictApplicationDescriptor descriptor, OpenIddictApplication _, CancellationToken _) =>
                {
                    descriptor.ClientId = "Fabrikam";
                    descriptor.ClientSecret = "hashed-secret";
                    descriptor.ClientType = ClientTypes.Confidential;
                    descriptor.ConsentType = ConsentTypes.Systematic;
                    descriptor.RedirectUris.Add(new Uri("https://fabrikam.com/callback"));
                    descriptor.Properties[Properties.ClientMetadata] = JsonSerializer.Deserialize<JsonElement>(
                        """{"client_id_issued_at":1700000000}""");
                })
                .Returns(ValueTask.CompletedTask);

            configuration?.Invoke(mock);
        });

    private static void ConfigureRegistrationToken(Mock<OpenIddictTokenManager<OpenIddictToken>> mock, OpenIddictToken token)
    {
        mock.Setup(manager => manager.FindByReferenceIdAsync("registration-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);

        mock.Setup(manager => manager.HasTypeAsync(token, TokenTypeIdentifiers.Private.RegistrationAccessToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        mock.Setup(manager => manager.GetApplicationIdAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
    }

    private static string CreateSoftwareStatement(SecurityKey key, string issuer, Dictionary<string, object>? claims = null)
        => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = claims,
            Expires = DateTime.UtcNow.AddMinutes(5),
            Issuer = issuer,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
        });
}
