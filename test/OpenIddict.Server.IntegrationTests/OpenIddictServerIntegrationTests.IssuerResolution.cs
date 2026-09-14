/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    [Theory]
    [InlineData("http://localhost/tenant1/.well-known/openid-configuration", "http://localhost/tenant1/", "http://localhost/tenant1/")]
    [InlineData("http://localhost/TENANT2/.well-known/openid-configuration", "http://localhost/tenant2", "http://localhost/tenant2/")]
    [InlineData("http://localhost/tenant1/nested/.well-known/openid-configuration", "http://localhost/tenant1/nested/", "http://localhost/tenant1/nested/")]
    [InlineData("http://fabrikam.localhost/.well-known/openid-configuration", "http://fabrikam.localhost/", "http://fabrikam.localhost/")]
    public async Task IssuerResolution_DiscoveryDocumentIsSpecificToResolvedIssuer(string uri, string issuer, string root)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => ConfigureIssuerResolution(options,
            "http://localhost/tenant1/", "http://localhost/tenant2", "http://localhost/tenant1/nested/", "http://fabrikam.localhost/"));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync(uri);

        // Assert
        Assert.Equal(issuer, (string?) response[Metadata.Issuer]);
        Assert.Equal(root + "connect/token", (string?) response[Metadata.TokenEndpoint]);
        Assert.Equal(root + ".well-known/jwks", (string?) response[Metadata.JwksUri]);
    }

    [Theory]
    [InlineData("http://localhost/tenant10/.well-known/openid-configuration")]
    [InlineData("http://localhost/.well-known/openid-configuration")]
    [InlineData("http://contoso.localhost/.well-known/openid-configuration")]
    public async Task IssuerResolution_RequestIsNotHandledWhenNoIssuerCanBeResolved(string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => ConfigureIssuerResolution(options,
            "http://localhost/tenant1/", "http://fabrikam.localhost/"));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync(uri);

        // Assert
        Assert.Null(response[Metadata.Issuer]);
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Fact]
    public async Task IssuerResolution_TokensAreIssuedForResolvedIssuer()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureIssuerResolution(options, "http://localhost/tenant1/", "http://localhost/tenant2/");

            options.DisableAccessTokenEncryption();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("http://localhost/tenant2/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.NotNull(response.AccessToken);
        Assert.Equal("http://localhost/tenant2/", new JsonWebToken(response.AccessToken).Issuer);
    }

    [Fact]
    public async Task IssuerResolution_TokenIssuedForAnotherIssuerIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
            ConfigureIssuerResolution(options, "http://localhost/tenant1/", "http://localhost/tenant2/"));

        await using var client = await server.CreateClientAsync();

        var token = (await client.PostAsync("http://localhost/tenant1/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w",
            Scope = Scopes.OfflineAccess
        })).RefreshToken;

        Assert.NotNull(token);

        // Act
        var response = await client.PostAsync("http://localhost/tenant2/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = token
        });

        // Assert
        Assert.Equal(Errors.InvalidGrant, response.Error);
        Assert.Null(response.AccessToken);
    }

    [Fact]
    public async Task IssuerResolution_TokenIssuedForSameIssuerIsAccepted()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
            ConfigureIssuerResolution(options, "http://localhost/tenant1/", "http://localhost/tenant2/"));

        await using var client = await server.CreateClientAsync();

        var token = (await client.PostAsync("http://localhost/tenant1/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w",
            Scope = Scopes.OfflineAccess
        })).RefreshToken;

        // Act
        var response = await client.PostAsync("http://localhost/tenant1/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = token
        });

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(response.AccessToken);
    }

    [Theory]
    [InlineData("http://localhost/tenant1/", false)]
    [InlineData("http://localhost/tenant1", true)]
    [InlineData("http://localhost/tenant2/", true)]
    [InlineData(null, true)]
    public async Task IssuerResolution_TokenIssuerIsValidatedForNonJsonWebTokenFormats(string? issuer, bool rejected)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureIssuerResolution(options, "http://localhost/tenant1/", "http://localhost/tenant2/");

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    if (!string.Equals(context.Token, "8xLOxBtZp8", StringComparison.Ordinal))
                    {
                        return ValueTask.CompletedTask;
                    }

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.RefreshToken)
                        .SetClaim(Claims.Private.Issuer, issuer)
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("http://localhost/tenant1/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = "8xLOxBtZp8"
        });

        // Assert
        if (rejected)
        {
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID2464), response.ErrorDescription);
        }

        else
        {
            Assert.Null(response.Error);
            Assert.NotNull(response.AccessToken);
        }
    }

    [Fact]
    public async Task IssuerResolution_CustomResolverIsUsed()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureIssuerResolution(options);

            options.SetIssuerResolver<SegmentIssuerResolver>();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("http://localhost/t-contoso/.well-known/openid-configuration");
        var unknown = await client.GetAsync("http://localhost/contoso/.well-known/openid-configuration");

        // Assert
        Assert.Equal("http://localhost/t-contoso/", (string?) response[Metadata.Issuer]);
        Assert.Null(unknown[Metadata.Issuer]);
    }

    [Fact]
    public async Task IssuerResolution_InvalidIssuerReturnedByCustomResolverCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureIssuerResolution(options);

            options.SetIssuerResolver<SegmentIssuerResolver>();
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.GetAsync("http://localhost/invalid/.well-known/openid-configuration"));

        Assert.Equal(SR.GetResourceString(SR.ID0925), exception.Message);
    }

    [Fact]
    public async Task IssuerResolution_MissingIssuerSourceCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => ConfigureIssuerResolution(options));
        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.GetAsync("http://localhost/.well-known/openid-configuration"));

        Assert.Equal(SR.GetResourceString(SR.ID0929), exception.Message);
    }

    [Fact]
    public async Task IssuerResolution_IssuerSpecificCredentialsAreUsed()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureIssuerResolution(options, "http://localhost/tenant1/", "http://localhost/tenant2/");

            options.DisableAccessTokenEncryption();
            options.SetIssuerCredentialsProvider<TenantCredentialsProvider>();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var first = new JsonWebKeySet((await client.GetAsync("http://localhost/tenant1/.well-known/jwks")).ToString());
        var second = new JsonWebKeySet((await client.GetAsync("http://localhost/tenant2/.well-known/jwks")).ToString());

        var response = await client.PostAsync("http://localhost/tenant2/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w",
            Scope = Scopes.OfflineAccess
        });

        var refresh = await client.PostAsync("http://localhost/tenant2/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = response.RefreshToken
        });

        // Assert
        Assert.DoesNotContain(first.Keys, static key => key.Kid is TenantCredentialsProvider.KeyId);
        Assert.Equal(TenantCredentialsProvider.KeyId, Assert.Single(second.Keys).Kid);

        Assert.NotNull(response.AccessToken);
        Assert.Equal(TenantCredentialsProvider.KeyId, new JsonWebToken(response.AccessToken).Kid);

        Assert.Null(refresh.Error);
        Assert.NotNull(refresh.AccessToken);
    }

    private static void ConfigureIssuerResolution(OpenIddictServerBuilder options, params string[] issuers)
    {
        options.EnableDegradedMode();
        options.EnableIssuerResolution();

        if (issuers.Length is > 0)
        {
            options.AddIssuers(issuers);
        }

        options.SetAuthorizationEndpointUris("connect/authorize")
               .SetConfigurationEndpointUris(".well-known/openid-configuration")
               .SetJsonWebKeySetEndpointUris(".well-known/jwks")
               .SetDeviceAuthorizationEndpointUris("connect/device")
               .SetIntrospectionEndpointUris("connect/introspect")
               .SetEndSessionEndpointUris("connect/endsession")
               .SetPushedAuthorizationEndpointUris("connect/par")
               .SetRevocationEndpointUris("connect/revoke")
               .SetTokenEndpointUris("connect/token")
               .SetUserInfoEndpointUris("connect/userinfo")
               .SetEndUserVerificationEndpointUris("connect/verification");

        options.AddEventHandler<ValidateTokenRequestContext>(builder =>
            builder.UseInlineHandler(static context => ValueTask.CompletedTask));

        options.AddEventHandler<HandleTokenRequestContext>(builder =>
            builder.UseInlineHandler(static context =>
            {
                context.Principal = context.Principal ?? new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                    .SetClaim(Claims.Subject, "Bob le Magnifique")
                    .SetScopes(context.Request.GetScopes());

                return ValueTask.CompletedTask;
            }));
    }

    private sealed class SegmentIssuerResolver : IOpenIddictServerIssuerResolver
    {
        public ValueTask<Uri?> ResolveIssuerAsync(OpenIddictServerIssuerResolutionContext context)
        {
            // Resolve dynamic tenants (not known in advance) from the first path segment.
            var segment = context.RequestUri.AbsolutePath.Split(['/'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();

            return new(segment switch
            {
                "invalid" => new Uri("http://localhost/invalid/?query=value", UriKind.Absolute),
                { Length: > 2 } when segment.StartsWith("t-", StringComparison.Ordinal)
                    => new Uri(context.BaseUri, segment + "/"),

                _ => null
            });
        }
    }

    private sealed class TenantCredentialsProvider(IOptionsMonitor<OpenIddictServerOptions> monitor) : IOpenIddictServerIssuerCredentialsProvider
    {
        public const string KeyId = "tenant2-signing-key";

        private static readonly SigningCredentials Credentials = new(
            new RsaSecurityKey(RSA.Create(keySizeInBits: 2048)) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256);

        public ValueTask<OpenIddictServerCredentials?> GetCredentialsAsync(
            Uri issuer, IServiceProvider provider, CancellationToken cancellationToken)
            => new(issuer.AbsoluteUri is "http://localhost/tenant2/" ?
                new OpenIddictServerCredentials([Credentials], monitor.CurrentValue.EncryptionCredentials) : null);
    }
}
