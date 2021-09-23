

/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Security.Claims;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    [Fact]
    public async Task ValidateToken_IssuedAtIsMappedToCreationDate()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserinfoEndpointUris("/authenticate");

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

                    var identity = new ClaimsIdentity("Bearer");
                    identity.AddClaim(new Claim(Claims.IssuedAt, "1577836800", ClaimValueTypes.Integer64));

                    context.Principal = new ClaimsPrincipal(identity)
                        .SetTokenType(TokenTypeHints.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
        Assert.Equal(1577836800, (long) response[Claims.IssuedAt]);
        Assert.Equal("Wed, 01 Jan 2020 00:00:00 GMT", (string?) response[Claims.Private.CreationDate]);
    }

    [Fact]
    public async Task ValidateToken_ExpiresAtIsMappedToExpirationDate()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserinfoEndpointUris("/authenticate");

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

                    var identity = new ClaimsIdentity("Bearer");
                    identity.AddClaim(new Claim(Claims.ExpiresAt, "2524608000", ClaimValueTypes.Integer64));

                    context.Principal = new ClaimsPrincipal(identity)
                        .SetTokenType(TokenTypeHints.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
        Assert.Equal(2524608000, (long) response[Claims.ExpiresAt]);
        Assert.Equal("Sat, 01 Jan 2050 00:00:00 GMT", (string?) response[Claims.Private.ExpirationDate]);
    }

    [Fact]
    public async Task ValidateToken_AuthorizedPartyIsMappedToPresenter()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserinfoEndpointUris("/authenticate");

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
                        .SetClaim(Claims.AuthorizedParty, "Fabrikam");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
        Assert.Equal("Fabrikam", (string?) response[Claims.AuthorizedParty]);
        Assert.Equal("Fabrikam", (string?) response[Claims.Private.Presenter]);
    }

    [Fact]
    public async Task ValidateToken_ClientIdIsMappedToPresenter()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserinfoEndpointUris("/authenticate");

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
                        .SetClaim(Claims.ClientId, "Fabrikam");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
        Assert.Equal("Fabrikam", (string?) response[Claims.ClientId]);
        Assert.Equal("Fabrikam", (string?) response[Claims.Private.Presenter]);
    }

    [Fact]
    public async Task ValidateToken_SinglePublicAudienceIsMappedToPrivateClaims()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserinfoEndpointUris("/authenticate");

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
                        .SetClaim(Claims.Audience, "Fabrikam");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
        Assert.Equal("Fabrikam", (string?) response[Claims.Audience]);
        Assert.Equal("Fabrikam", (string?) response[Claims.Private.Audience]);
    }

    [Fact]
    public async Task ValidateToken_MultiplePublicAudiencesAreMappedToPrivateClaims()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserinfoEndpointUris("/authenticate");

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
                        .SetClaims(Claims.Audience, ImmutableArray.Create("Fabrikam", "Contoso"));

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
        Assert.Equal(new[] { "Fabrikam", "Contoso" }, (string[]?) response[Claims.Audience]);
        Assert.Equal(new[] { "Fabrikam", "Contoso" }, (string[]?) response[Claims.Private.Audience]);
    }

    [Fact]
    public async Task ValidateToken_MultiplePublicScopesAreNormalizedToSingleClaim()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserinfoEndpointUris("/authenticate");

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
                        .SetClaims(Claims.Scope, ImmutableArray.Create(Scopes.OpenId, Scopes.Profile));

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
        Assert.Equal("openid profile", (string?) response[Claims.Scope]);
    }

    [Fact]
    public async Task ValidateToken_SinglePublicScopeIsMappedToPrivateClaims()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserinfoEndpointUris("/authenticate");

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
                        .SetClaim(Claims.Scope, "openid profile");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
        Assert.Equal(new[] { Scopes.OpenId, Scopes.Profile }, (string[]?) response[Claims.Private.Scope]);
    }

    [Fact]
    public async Task ValidateToken_MultiplePublicScopesAreMappedToPrivateClaims()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserinfoEndpointUris("/authenticate");

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
                        .SetClaims(Claims.Scope, ImmutableArray.Create(Scopes.OpenId, Scopes.Profile));

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
        Assert.Equal(new[] { Scopes.OpenId, Scopes.Profile }, (string[]?) response[Claims.Private.Scope]);
    }

    [Fact]
    public async Task ValidateToken_MissingTokenTypeThrowsAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal(Array.Empty<string>(), context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(null)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.GetAsync("/connect/introspect", new OpenIddictRequest
            {
                Token = "access_token"
            });
        });

        // Assert
        Assert.Equal(SR.GetResourceString(SR.ID0004), exception.Message);
    }

    [Fact]
    public async Task ValidateToken_InvalidTokenTypeThrowsAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserinfoEndpointUris("/authenticate");

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
                        .SetTokenType(TokenTypeHints.AuthorizationCode)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.GetAsync("/authenticate", new OpenIddictRequest
            {
                AccessToken = "access_token"
            });
        });

        // Assert
        Assert.Equal(SR.FormatID0005(TokenTypeHints.AuthorizationCode, TokenTypeHints.AccessToken), exception.Message);
    }
}
