/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.Server.IntegrationTests;
using Xunit;
using Xunit.Abstractions;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreHandlers;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

#if SUPPORTS_JSON_NODES
using System.Text.Json.Nodes;
#endif

namespace OpenIddict.Server.AspNetCore.IntegrationTests;

public partial class OpenIddictServerAspNetCoreIntegrationTests : OpenIddictServerIntegrationTests
{
    public OpenIddictServerAspNetCoreIntegrationTests(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task ProcessAuthentication_CreationDateIsMappedToIssuedUtc()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserinfoEndpointUris("/authenticate/properties");

            options.AddEventHandler<HandleUserinfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal(new[] { TokenTypeHints.AccessToken }, context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetCreationDate(new DateTimeOffset(2020, 01, 01, 00, 00, 00, TimeSpan.Zero));

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate/properties", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        var properties = new AuthenticationProperties(response.GetParameters()
            .ToDictionary(parameter => parameter.Key, parameter => (string?) parameter.Value));

        Assert.Equal(new DateTimeOffset(2020, 01, 01, 00, 00, 00, TimeSpan.Zero), properties.IssuedUtc);
    }

    [Fact]
    public async Task ProcessAuthentication_ExpirationDateIsMappedToIssuedUtc()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserinfoEndpointUris("/authenticate/properties");

            options.AddEventHandler<HandleUserinfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal(new[] { TokenTypeHints.AccessToken }, context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.AccessToken)
                        .SetExpirationDate(new DateTimeOffset(2120, 01, 01, 00, 00, 00, TimeSpan.Zero));

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate/properties", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        var properties = new AuthenticationProperties(response.GetParameters()
            .ToDictionary(parameter => parameter.Key, parameter => (string?) parameter.Value));

        Assert.Equal(new DateTimeOffset(2120, 01, 01, 00, 00, 00, TimeSpan.Zero), properties.ExpiresUtc);
    }

    [Fact]
    public async Task ProcessChallenge_ImportsAuthenticationProperties()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/challenge/custom");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessChallengeContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("value", context.Properties["custom_property"]);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/challenge/custom", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.NotEmpty(response.Error);
        Assert.NotEmpty(response.ErrorDescription);
        Assert.NotEmpty(response.ErrorUri);
    }

    [Fact]
    public async Task ProcessChallenge_ReturnsParametersFromAuthenticationProperties()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/challenge/custom");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/challenge/custom", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.True((bool) response["boolean_parameter"]);
        Assert.Equal(JsonValueKind.True, ((JsonElement) response["boolean_parameter"]).ValueKind);
        Assert.Equal(42, (long) response["integer_parameter"]);
        Assert.Equal(JsonValueKind.Number, ((JsonElement) response["integer_parameter"]).ValueKind);
        Assert.Equal("Bob l'Eponge", (string?) response["string_parameter"]);
        Assert.Equal(JsonValueKind.String, ((JsonElement) response["string_parameter"]).ValueKind);
        Assert.Equal(new[] { "Contoso", "Fabrikam" }, (string[]?) response["array_parameter"]);
        Assert.Equal(JsonValueKind.Array, ((JsonElement) response["array_parameter"]).ValueKind);
        Assert.Equal("value", (string?) response["object_parameter"]?["parameter"]);
        Assert.Equal(JsonValueKind.Object, ((JsonElement) response["object_parameter"]).ValueKind);

#if SUPPORTS_JSON_NODES
        Assert.Equal(new[] { "Contoso", "Fabrikam" }, (string[]?) response["node_array_parameter"]);
        Assert.IsType<JsonArray>((JsonNode?) response["node_array_parameter"]);
        Assert.Equal("value", (string?) response["node_object_parameter"]?["parameter"]);
        Assert.IsType<JsonObject>((JsonNode?) response["node_object_parameter"]);
#endif
    }

    [Fact]
    public async Task ProcessChallenge_ReturnsErrorFromAuthenticationProperties()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/challenge/custom");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/challenge/custom", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.Equal("custom_error", response.Error);
        Assert.Equal("custom_error_description", response.ErrorDescription);
        Assert.Equal("custom_error_uri", response.ErrorUri);
    }

    [Theory]
    [InlineData("/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/authorize", OpenIddictServerEndpointType.Authorization)]
    [InlineData("/CONNECT/AUTHORIZE", OpenIddictServerEndpointType.Authorization)]
    [InlineData("/connect/authorize/", OpenIddictServerEndpointType.Authorization)]
    [InlineData("/CONNECT/AUTHORIZE/", OpenIddictServerEndpointType.Authorization)]
    [InlineData("/connect/authorize/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/AUTHORIZE/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/authorize/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/AUTHORIZE/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.well-known/openid-configuration", OpenIddictServerEndpointType.Configuration)]
    [InlineData("/.WELL-KNOWN/OPENID-CONFIGURATION", OpenIddictServerEndpointType.Configuration)]
    [InlineData("/.well-known/openid-configuration/", OpenIddictServerEndpointType.Configuration)]
    [InlineData("/.WELL-KNOWN/OPENID-CONFIGURATION/", OpenIddictServerEndpointType.Configuration)]
    [InlineData("/.well-known/openid-configuration/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.WELL-KNOWN/OPENID-CONFIGURATION/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.well-known/openid-configuration/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.WELL-KNOWN/OPENID-CONFIGURATION/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.well-known/jwks", OpenIddictServerEndpointType.Cryptography)]
    [InlineData("/.WELL-KNOWN/JWKS", OpenIddictServerEndpointType.Cryptography)]
    [InlineData("/.well-known/jwks/", OpenIddictServerEndpointType.Cryptography)]
    [InlineData("/.WELL-KNOWN/JWKS/", OpenIddictServerEndpointType.Cryptography)]
    [InlineData("/.well-known/jwks/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.WELL-KNOWN/JWKS/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.well-known/jwks/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.WELL-KNOWN/JWKS/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/device", OpenIddictServerEndpointType.Device)]
    [InlineData("/CONNECT/DEVICE", OpenIddictServerEndpointType.Device)]
    [InlineData("/connect/device/", OpenIddictServerEndpointType.Device)]
    [InlineData("/CONNECT/DEVICE/", OpenIddictServerEndpointType.Device)]
    [InlineData("/connect/device/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/DEVICE/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/device/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/DEVICE/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/introspect", OpenIddictServerEndpointType.Introspection)]
    [InlineData("/CONNECT/INTROSPECT", OpenIddictServerEndpointType.Introspection)]
    [InlineData("/connect/introspect/", OpenIddictServerEndpointType.Introspection)]
    [InlineData("/CONNECT/INTROSPECT/", OpenIddictServerEndpointType.Introspection)]
    [InlineData("/connect/introspect/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/INTROSPECT/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/introspect/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/INTROSPECT/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/logout", OpenIddictServerEndpointType.Logout)]
    [InlineData("/CONNECT/LOGOUT", OpenIddictServerEndpointType.Logout)]
    [InlineData("/connect/logout/", OpenIddictServerEndpointType.Logout)]
    [InlineData("/CONNECT/LOGOUT/", OpenIddictServerEndpointType.Logout)]
    [InlineData("/connect/logout/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/LOGOUT/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/logout/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/LOGOUT/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/revoke", OpenIddictServerEndpointType.Revocation)]
    [InlineData("/CONNECT/REVOKE", OpenIddictServerEndpointType.Revocation)]
    [InlineData("/connect/revoke/", OpenIddictServerEndpointType.Revocation)]
    [InlineData("/CONNECT/REVOKE/", OpenIddictServerEndpointType.Revocation)]
    [InlineData("/connect/revoke/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/REVOKE/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/revoke/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/REVOKE/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/token", OpenIddictServerEndpointType.Token)]
    [InlineData("/CONNECT/TOKEN", OpenIddictServerEndpointType.Token)]
    [InlineData("/connect/token/", OpenIddictServerEndpointType.Token)]
    [InlineData("/CONNECT/TOKEN/", OpenIddictServerEndpointType.Token)]
    [InlineData("/connect/token/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/TOKEN/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/token/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/TOKEN/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/userinfo", OpenIddictServerEndpointType.Userinfo)]
    [InlineData("/CONNECT/USERINFO", OpenIddictServerEndpointType.Userinfo)]
    [InlineData("/connect/userinfo/", OpenIddictServerEndpointType.Userinfo)]
    [InlineData("/CONNECT/USERINFO/", OpenIddictServerEndpointType.Userinfo)]
    [InlineData("/connect/userinfo/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/USERINFO/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/userinfo/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/USERINFO/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/verification", OpenIddictServerEndpointType.Verification)]
    [InlineData("/CONNECT/VERIFICATION", OpenIddictServerEndpointType.Verification)]
    [InlineData("/connect/verification/", OpenIddictServerEndpointType.Verification)]
    [InlineData("/CONNECT/VERIFICATION/", OpenIddictServerEndpointType.Verification)]
    [InlineData("/connect/verification/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/VERIFICATION/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/verification/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/VERIFICATION/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    public async Task ProcessRequest_MatchesCorrespondingRelativeEndpoint(string path, OpenIddictServerEndpointType type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleLogoutRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<HandleVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    // Assert
                    Assert.Equal(type, context.EndpointType);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        await client.PostAsync(path, new OpenIddictRequest());
    }

    [Theory]
    [InlineData("https://localhost/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:443/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST/CONNECT", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:443/connect", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:443/connect/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/authorize", OpenIddictServerEndpointType.Authorization)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/AUTHORIZE", OpenIddictServerEndpointType.Authorization)]
    [InlineData("https://localhost/connect/authorize/", OpenIddictServerEndpointType.Authorization)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/AUTHORIZE/", OpenIddictServerEndpointType.Authorization)]
    [InlineData("https://localhost:443/connect/authorize", OpenIddictServerEndpointType.Authorization)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/AUTHORIZE", OpenIddictServerEndpointType.Authorization)]
    [InlineData("https://localhost:443/connect/authorize/", OpenIddictServerEndpointType.Authorization)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/AUTHORIZE/", OpenIddictServerEndpointType.Authorization)]
    [InlineData("https://fabrikam.com/connect/authorize", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/AUTHORIZE", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/authorize/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/AUTHORIZE/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/authorize", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/AUTHORIZE", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/authorize/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/AUTHORIZE/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/.well-known/openid-configuration", OpenIddictServerEndpointType.Configuration)]
    [InlineData("HTTPS://LOCALHOST/.WELL-KNOWN/OPENID-CONFIGURATION", OpenIddictServerEndpointType.Configuration)]
    [InlineData("https://localhost/.well-known/openid-configuration/", OpenIddictServerEndpointType.Configuration)]
    [InlineData("HTTPS://LOCALHOST/.WELL-KNOWN/OPENID-CONFIGURATION/", OpenIddictServerEndpointType.Configuration)]
    [InlineData("https://localhost:443/.well-known/openid-configuration", OpenIddictServerEndpointType.Configuration)]
    [InlineData("HTTPS://LOCALHOST:443/.WELL-KNOWN/OPENID-CONFIGURATION", OpenIddictServerEndpointType.Configuration)]
    [InlineData("https://localhost:443/.well-known/openid-configuration/", OpenIddictServerEndpointType.Configuration)]
    [InlineData("HTTPS://LOCALHOST:443/.WELL-KNOWN/OPENID-CONFIGURATION/", OpenIddictServerEndpointType.Configuration)]
    [InlineData("https://fabrikam.com/.well-known/openid-configuration", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/.WELL-KNOWN/OPENID-CONFIGURATION", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/.well-known/openid-configuration/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/.WELL-KNOWN/OPENID-CONFIGURATION/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/.well-known/openid-configuration", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/.WELL-KNOWN/OPENID-CONFIGURATION", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/.well-known/openid-configuration/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/.WELL-KNOWN/OPENID-CONFIGURATION/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/.well-known/jwks", OpenIddictServerEndpointType.Cryptography)]
    [InlineData("HTTPS://LOCALHOST/.WELL-KNOWN/JWKS", OpenIddictServerEndpointType.Cryptography)]
    [InlineData("https://localhost/.well-known/jwks/", OpenIddictServerEndpointType.Cryptography)]
    [InlineData("HTTPS://LOCALHOST/.WELL-KNOWN/JWKS/", OpenIddictServerEndpointType.Cryptography)]
    [InlineData("https://localhost:443/.well-known/jwks", OpenIddictServerEndpointType.Cryptography)]
    [InlineData("HTTPS://LOCALHOST:443/.WELL-KNOWN/JWKS", OpenIddictServerEndpointType.Cryptography)]
    [InlineData("https://localhost:443/.well-known/jwks/", OpenIddictServerEndpointType.Cryptography)]
    [InlineData("HTTPS://LOCALHOST:443/.WELL-KNOWN/JWKS/", OpenIddictServerEndpointType.Cryptography)]
    [InlineData("https://fabrikam.com/.well-known/jwks", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/.WELL-KNOWN/JWKS", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/.well-known/jwks/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/.WELL-KNOWN/JWKS/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/.well-known/jwks", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/.WELL-KNOWN/JWKS", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/.well-known/jwks/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/.WELL-KNOWN/JWKS/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/device", OpenIddictServerEndpointType.Device)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/DEVICE", OpenIddictServerEndpointType.Device)]
    [InlineData("https://localhost/connect/device/", OpenIddictServerEndpointType.Device)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/DEVICE/", OpenIddictServerEndpointType.Device)]
    [InlineData("https://localhost:443/connect/device", OpenIddictServerEndpointType.Device)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/DEVICE", OpenIddictServerEndpointType.Device)]
    [InlineData("https://localhost:443/connect/device/", OpenIddictServerEndpointType.Device)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/DEVICE/", OpenIddictServerEndpointType.Device)]
    [InlineData("https://fabrikam.com/connect/device", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/DEVICE", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/device/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/DEVICE/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/device", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/DEVICE", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/device/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/DEVICE/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/introspect", OpenIddictServerEndpointType.Introspection)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/INTROSPECT", OpenIddictServerEndpointType.Introspection)]
    [InlineData("https://localhost/connect/introspect/", OpenIddictServerEndpointType.Introspection)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/INTROSPECT/", OpenIddictServerEndpointType.Introspection)]
    [InlineData("https://localhost:443/connect/introspect", OpenIddictServerEndpointType.Introspection)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/INTROSPECT", OpenIddictServerEndpointType.Introspection)]
    [InlineData("https://localhost:443/connect/introspect/", OpenIddictServerEndpointType.Introspection)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/INTROSPECT/", OpenIddictServerEndpointType.Introspection)]
    [InlineData("https://fabrikam.com/connect/introspect", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/INTROSPECT", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/introspect/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/INTROSPECT/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/introspect", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/INTROSPECT", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/introspect/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/INTROSPECT/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/logout", OpenIddictServerEndpointType.Logout)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/LOGOUT", OpenIddictServerEndpointType.Logout)]
    [InlineData("https://localhost/connect/logout/", OpenIddictServerEndpointType.Logout)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/LOGOUT/", OpenIddictServerEndpointType.Logout)]
    [InlineData("https://localhost:443/connect/logout", OpenIddictServerEndpointType.Logout)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/LOGOUT", OpenIddictServerEndpointType.Logout)]
    [InlineData("https://localhost:443/connect/logout/", OpenIddictServerEndpointType.Logout)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/LOGOUT/", OpenIddictServerEndpointType.Logout)]
    [InlineData("https://fabrikam.com/connect/logout", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/LOGOUT", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/logout/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/LOGOUT/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/logout", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/LOGOUT", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/logout/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/LOGOUT/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/revoke", OpenIddictServerEndpointType.Revocation)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/REVOKE", OpenIddictServerEndpointType.Revocation)]
    [InlineData("https://localhost/connect/revoke/", OpenIddictServerEndpointType.Revocation)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/REVOKE/", OpenIddictServerEndpointType.Revocation)]
    [InlineData("https://localhost:443/connect/revoke", OpenIddictServerEndpointType.Revocation)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/REVOKE", OpenIddictServerEndpointType.Revocation)]
    [InlineData("https://localhost:443/connect/revoke/", OpenIddictServerEndpointType.Revocation)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/REVOKE/", OpenIddictServerEndpointType.Revocation)]
    [InlineData("https://fabrikam.com/connect/revoke", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/REVOKE", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/revoke/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/REVOKE/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/revoke", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/REVOKE", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/revoke/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/REVOKE/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/token", OpenIddictServerEndpointType.Token)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/TOKEN", OpenIddictServerEndpointType.Token)]
    [InlineData("https://localhost/connect/token/", OpenIddictServerEndpointType.Token)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/TOKEN/", OpenIddictServerEndpointType.Token)]
    [InlineData("https://localhost:443/connect/token", OpenIddictServerEndpointType.Token)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/TOKEN", OpenIddictServerEndpointType.Token)]
    [InlineData("https://localhost:443/connect/token/", OpenIddictServerEndpointType.Token)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/TOKEN/", OpenIddictServerEndpointType.Token)]
    [InlineData("https://fabrikam.com/connect/token", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/TOKEN", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/token/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/TOKEN/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/token", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/TOKEN", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/token/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/TOKEN/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/userinfo", OpenIddictServerEndpointType.Userinfo)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/USERINFO", OpenIddictServerEndpointType.Userinfo)]
    [InlineData("https://localhost/connect/userinfo/", OpenIddictServerEndpointType.Userinfo)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/USERINFO/", OpenIddictServerEndpointType.Userinfo)]
    [InlineData("https://localhost:443/connect/userinfo", OpenIddictServerEndpointType.Userinfo)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/USERINFO", OpenIddictServerEndpointType.Userinfo)]
    [InlineData("https://localhost:443/connect/userinfo/", OpenIddictServerEndpointType.Userinfo)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/USERINFO/", OpenIddictServerEndpointType.Userinfo)]
    [InlineData("https://fabrikam.com/connect/userinfo", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/USERINFO", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/userinfo/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/USERINFO/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/userinfo", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/USERINFO", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/userinfo/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/USERINFO/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/verification", OpenIddictServerEndpointType.Verification)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/VERIFICATION", OpenIddictServerEndpointType.Verification)]
    [InlineData("https://localhost/connect/verification/", OpenIddictServerEndpointType.Verification)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/VERIFICATION/", OpenIddictServerEndpointType.Verification)]
    [InlineData("https://localhost:443/connect/verification", OpenIddictServerEndpointType.Verification)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/VERIFICATION", OpenIddictServerEndpointType.Verification)]
    [InlineData("https://localhost:443/connect/verification/", OpenIddictServerEndpointType.Verification)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/VERIFICATION/", OpenIddictServerEndpointType.Verification)]
    [InlineData("https://fabrikam.com/connect/verification", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/VERIFICATION", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/verification/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/VERIFICATION/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/verification", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/VERIFICATION", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/verification/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/VERIFICATION/", OpenIddictServerEndpointType.Unknown)]
    public async Task ProcessRequest_MatchesCorrespondingAbsoluteEndpoint(string path, OpenIddictServerEndpointType type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.SetAuthorizationEndpointUris("https://localhost/connect/authorize")
                   .SetConfigurationEndpointUris("https://localhost/.well-known/openid-configuration")
                   .SetCryptographyEndpointUris("https://localhost/.well-known/jwks")
                   .SetDeviceEndpointUris("https://localhost/connect/device")
                   .SetIntrospectionEndpointUris("https://localhost/connect/introspect")
                   .SetLogoutEndpointUris("https://localhost/connect/logout")
                   .SetRevocationEndpointUris("https://localhost/connect/revoke")
                   .SetTokenEndpointUris("https://localhost/connect/token")
                   .SetUserinfoEndpointUris("https://localhost/connect/userinfo")
                   .SetVerificationEndpointUris("https://localhost/connect/verification");

            options.AddEventHandler<HandleLogoutRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<HandleVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    // Assert
                    Assert.Equal(type, context.EndpointType);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        await client.PostAsync(path, new OpenIddictRequest());
    }

    [Theory]
    [InlineData("/custom/connect/authorize", OpenIddictServerEndpointType.Authorization)]
    [InlineData("/custom/.well-known/openid-configuration", OpenIddictServerEndpointType.Configuration)]
    [InlineData("/custom/.well-known/jwks", OpenIddictServerEndpointType.Cryptography)]
    [InlineData("/custom/connect/device", OpenIddictServerEndpointType.Device)]
    [InlineData("/custom/connect/custom", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/custom/connect/introspect", OpenIddictServerEndpointType.Introspection)]
    [InlineData("/custom/connect/logout", OpenIddictServerEndpointType.Logout)]
    [InlineData("/custom/connect/revoke", OpenIddictServerEndpointType.Revocation)]
    [InlineData("/custom/connect/token", OpenIddictServerEndpointType.Token)]
    [InlineData("/custom/connect/userinfo", OpenIddictServerEndpointType.Userinfo)]
    [InlineData("/custom/connect/verification", OpenIddictServerEndpointType.Verification)]
    public async Task ProcessRequest_AllowsOverridingEndpoint(string address, OpenIddictServerEndpointType type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleLogoutRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<HandleVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessRequestContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    // Act
                    context.EndpointType = type;

                    // Assert
                    Assert.Equal(type, context.EndpointType);

                    return default;
                });

                builder.SetOrder(InferEndpointType.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        await client.PostAsync(address, new OpenIddictRequest());
    }

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    [InlineData("/connect/authorize")]
    [InlineData("/connect/device")]
    [InlineData("/connect/introspect")]
    [InlineData("/connect/logout")]
    [InlineData("/connect/revoke")]
    [InlineData("/connect/token")]
    [InlineData("/connect/userinfo")]
    [InlineData("/connect/verification")]
    public async Task ProcessRequest_RejectsInsecureHttpRequests(string address)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.UseAspNetCore()
                   .Configure(options => options.DisableTransportSecurityRequirement = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync(address, new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2083), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2083), response.ErrorUri);
    }

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    [InlineData("/custom")]
    [InlineData("/connect/authorize")]
    [InlineData("/connect/device")]
    [InlineData("/connect/introspect")]
    [InlineData("/connect/logout")]
    [InlineData("/connect/revoke")]
    [InlineData("/connect/token")]
    [InlineData("/connect/userinfo")]
    [InlineData("/connect/verification")]
    public async Task ProcessRequest_AllowsHandlingResponse(string address)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ProcessRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync(address, new OpenIddictRequest());

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    [InlineData("/custom")]
    [InlineData("/connect/authorize")]
    [InlineData("/connect/device")]
    [InlineData("/connect/introspect")]
    [InlineData("/connect/logout")]
    [InlineData("/connect/revoke")]
    [InlineData("/connect/token")]
    [InlineData("/connect/userinfo")]
    [InlineData("/connect/verification")]
    public async Task ProcessRequest_AllowsSkippingHandler(string address)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ProcessRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync(address, new OpenIddictRequest());

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Fact]
    public async Task ProcessSignIn_ImportsAuthenticationProperties()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/signin/custom");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("value", context.Properties["custom_property"]);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/signin/custom", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.NotEmpty(response.AccessToken);
    }

    [Fact]
    public async Task ProcessSignIn_ReturnsParametersFromAuthenticationProperties()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/signin/custom");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/signin/custom", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.True((bool) response["boolean_parameter"]);
        Assert.Equal(JsonValueKind.True, ((JsonElement) response["boolean_parameter"]).ValueKind);
        Assert.Equal(42, (long) response["integer_parameter"]);
        Assert.Equal(JsonValueKind.Number, ((JsonElement) response["integer_parameter"]).ValueKind);
        Assert.Equal("Bob l'Eponge", (string?) response["string_parameter"]);
        Assert.Equal(JsonValueKind.String, ((JsonElement) response["string_parameter"]).ValueKind);
        Assert.Equal(new[] { "Contoso", "Fabrikam" }, (string[]?) response["array_parameter"]);
        Assert.Equal(JsonValueKind.Array, ((JsonElement) response["array_parameter"]).ValueKind);
        Assert.Equal("value", (string?) response["object_parameter"]?["parameter"]);
        Assert.Equal(JsonValueKind.Object, ((JsonElement) response["object_parameter"]).ValueKind);

#if SUPPORTS_JSON_NODES
        Assert.Equal(new[] { "Contoso", "Fabrikam" }, (string[]?) response["node_array_parameter"]);
        Assert.IsType<JsonArray>((JsonNode?) response["node_array_parameter"]);
        Assert.Equal("value", (string?) response["node_object_parameter"]?["parameter"]);
        Assert.IsType<JsonObject>((JsonNode?) response["node_object_parameter"]);
#endif
    }

    [Fact]
    public async Task ProcessSignOut_ImportsAuthenticationProperties()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetLogoutEndpointUris("/signout/custom");

            options.AddEventHandler<HandleLogoutRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessSignOutContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("value", context.Properties["custom_property"]);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/signout/custom", new OpenIddictRequest
        {
            PostLogoutRedirectUri = "http://www.fabrikam.com/path",
            State = "af0ifjsldkj"
        });

        // Assert
        Assert.NotEmpty(response.State);
    }

    [Fact]
    public async Task ProcessSignOut_ReturnsParametersFromAuthenticationProperties()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetLogoutEndpointUris("/signout/custom");

            options.AddEventHandler<HandleLogoutRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/signout/custom", new OpenIddictRequest
        {
            PostLogoutRedirectUri = "http://www.fabrikam.com/path",
            State = "af0ifjsldkj"
        });

        // Assert
        Assert.True((bool) response["boolean_parameter"]);
        Assert.Equal(42, (long) response["integer_parameter"]);
        Assert.Equal("Bob l'Eponge", (string?) response["string_parameter"]);
    }

    protected override
#if SUPPORTS_GENERIC_HOST
        async
#endif
        ValueTask<OpenIddictServerIntegrationTestServer> CreateServerAsync(Action<OpenIddictServerBuilder>? configuration = null)
    {
#if SUPPORTS_GENERIC_HOST
        var builder = new HostBuilder();
#else
        var builder = new WebHostBuilder();
#endif
        builder.UseEnvironment("Testing");

        builder.ConfigureLogging(options => options.AddXUnit(OutputHelper));

        builder.ConfigureServices(ConfigureServices);
        builder.ConfigureServices(services =>
        {
            services.AddOpenIddict()
                .AddServer(options =>
                {
                    // Disable the transport security requirement during testing.
                    options.UseAspNetCore()
                           .DisableTransportSecurityRequirement();

                    configuration?.Invoke(options);
                });
        });

#if SUPPORTS_GENERIC_HOST
        builder.ConfigureWebHost(options =>
        {
            options.UseTestServer();
            options.Configure(ConfigurePipeline);
        });
#else
        builder.Configure(ConfigurePipeline);
#endif

#if SUPPORTS_GENERIC_HOST
        var host = await builder.StartAsync();

        return new OpenIddictServerAspNetCoreIntegrationTestServer(host);
#else
        var server = new TestServer(builder);

        return new(new OpenIddictServerAspNetCoreIntegrationTestServer(server));
#endif

        void ConfigurePipeline(IApplicationBuilder app)
        {
            app.Use(next => async context =>
            {
                await next(context);

                var feature = context.Features.Get<OpenIddictServerAspNetCoreFeature>();
                var response = feature?.Transaction?.GetProperty<object>("custom_response");
                if (response is not null)
                {
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(response));
                }
            });

            app.UseAuthentication();

            app.Use(next => async context =>
            {
                if (context.Request.Path == "/signin")
                {
                    var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    identity.AddClaim(Claims.Subject, "Bob le Bricoleur");

                    var principal = new ClaimsPrincipal(identity);

                    await context.SignInAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, principal);
                    return;
                }

                else if (context.Request.Path == "/signin/custom")
                {
                    var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    identity.AddClaim(Claims.Subject, "Bob le Bricoleur");

                    var principal = new ClaimsPrincipal(identity);

                    var properties = new AuthenticationProperties(
                        items: new Dictionary<string, string?>
                        {
                            ["custom_property"] = "value"
                        },
                        parameters: new Dictionary<string, object?>
                        {
                            ["boolean_parameter"] = true,
                            ["integer_parameter"] = 42,
                            ["string_parameter"] = "Bob l'Eponge",
                            ["array_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"[""Contoso"",""Fabrikam""]"),
                            ["object_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"),
#if SUPPORTS_JSON_NODES
                            ["node_array_parameter"] = new JsonArray("Contoso", "Fabrikam"),
                            ["node_object_parameter"] = new JsonObject { ["parameter"] = "value" }
#endif
                        });

                    await context.SignInAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, principal, properties);
                    return;
                }

                else if (context.Request.Path == "/signout")
                {
                    await context.SignOutAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    return;
                }

                else if (context.Request.Path == "/signout/custom")
                {
                    var properties = new AuthenticationProperties(
                        items: new Dictionary<string, string?>
                        {
                            ["custom_property"] = "value"
                        },
                        parameters: new Dictionary<string, object?>
                        {
                            ["boolean_parameter"] = true,
                            ["integer_parameter"] = 42,
                            ["string_parameter"] = "Bob l'Eponge"
                        });

                    await context.SignOutAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, properties);
                    return;
                }

                else if (context.Request.Path == "/challenge")
                {
                    await context.ChallengeAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    return;
                }

                else if (context.Request.Path == "/challenge/custom")
                {
                    var properties = new AuthenticationProperties(
                        items: new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = "custom_error",
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "custom_error_description",
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorUri] = "custom_error_uri",

                            ["custom_property"] = "value"
                        },
                        parameters: new Dictionary<string, object?>
                        {
                            ["boolean_parameter"] = true,
                            ["integer_parameter"] = 42,
                            ["string_parameter"] = "Bob l'Eponge",
                            ["array_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"[""Contoso"",""Fabrikam""]"),
                            ["object_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"),
#if SUPPORTS_JSON_NODES
                            ["node_array_parameter"] = new JsonArray("Contoso", "Fabrikam"),
                            ["node_object_parameter"] = new JsonObject { ["parameter"] = "value" }
#endif
                        });

                    await context.ChallengeAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, properties);
                    return;
                }

                else if (context.Request.Path == "/authenticate")
                {
                    var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    if (result?.Principal is null)
                    {
                        return;
                    }

                    var claims = result.Principal.Claims.GroupBy(claim => claim.Type)
                        .Select(group => new KeyValuePair<string, string?[]?>(
                            group.Key, group.Select(claim => claim.Value).ToArray()));

                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(new OpenIddictResponse(claims)));
                    return;
                }

                else if (context.Request.Path == "/authenticate/properties")
                {
                    var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    if (result?.Properties is null)
                    {
                        return;
                    }

                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(new OpenIddictResponse(result.Properties.Items)));
                    return;
                }

                await next(context);
            });

            app.Run(context =>
            {
                context.Response.ContentType = "application/json";
                return context.Response.WriteAsync(JsonSerializer.Serialize(new
                {
                    name = "Bob le Magnifique"
                }));
            });
        }
    }
}
