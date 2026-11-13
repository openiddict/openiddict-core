

/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    [Fact]
    public async Task ValidateToken_TokenIdentifiersAreRestoredFromClaims()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserInfoEndpointUris("/authenticate");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.AccessToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0")
                        .SetSessionId("D61DB5C2-235F-4755-9B6F-7D31404A4771")
                        .SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56");

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", context.Principal!.GetAuthorizationId());
                    Assert.Equal("D61DB5C2-235F-4755-9B6F-7D31404A4771", context.Principal!.GetSessionId());
                    Assert.Equal("3E228451-1555-46F7-A471-951EFBA23A56", context.Principal!.GetTokenId());

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(int.MaxValue);
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
    }

    [Fact]
    public async Task ValidateToken_TokenIdentifiersAreRestoredFromDatabaseEntry()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.SetUserInfoEndpointUris("/authenticate");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.AccessToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0")
                        .SetSessionId("D61DB5C2-235F-4755-9B6F-7D31404A4771")
                        .SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56");

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("0EB8CC35-F389-4F06-A156-9220B79C2101", context.Principal!.GetAuthorizationId());
                    Assert.Equal("563D96CC-9758-4D3E-AC4C-A0253D9DE192", context.Principal!.GetSessionId());
                    Assert.Equal("92A7963F-ECAF-4A3E-8A47-3A62DAFDF466", context.Principal!.GetTokenId());

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(int.MaxValue);
            });

            options.Services.AddSingleton(CreateTokenManager(mock =>
            {
                var token = new OpenIddictToken();

                mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                // Note: the GUIDs used here are deliberately different from the ones used in the
                // principal to ensure that the identifiers are restored from the database entry.
                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("92A7963F-ECAF-4A3E-8A47-3A62DAFDF466");

                mock.Setup(manager => manager.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("0EB8CC35-F389-4F06-A156-9220B79C2101");

                mock.Setup(manager => manager.GetSessionIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("563D96CC-9758-4D3E-AC4C-A0253D9DE192");

                mock.Setup(manager => manager.FindByIdAsync("92A7963F-ECAF-4A3E-8A47-3A62DAFDF466", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(TokenTypeIdentifiers.AccessToken);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            }));

            options.Services.AddSingleton(CreateAuthorizationManager(mock =>
            {
                var authorization = new OpenIddictAuthorization();

                mock.Setup(manager => manager.FindByIdAsync("0EB8CC35-F389-4F06-A156-9220B79C2101", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(authorization);

                mock.Setup(manager => manager.HasStatusAsync(authorization, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            }));

            options.Services.AddSingleton(CreateSessionManager(mock =>
            {
                var session = new OpenIddictSession();

                mock.Setup(manager => manager.FindByIdAsync("563D96CC-9758-4D3E-AC4C-A0253D9DE192", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(session);

                mock.Setup(manager => manager.HasStatusAsync(session, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task ValidateToken_IssuedAtIsMappedToCreationDate()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserInfoEndpointUris("/authenticate");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.AccessToken], context.ValidTokenTypes);

                    var identity = new ClaimsIdentity("Bearer");
                    identity.AddClaim(new Claim(Claims.IssuedAt, "1577836800", ClaimValueTypes.Integer64));

                    context.Principal = new ClaimsPrincipal(identity)
                        .SetTokenType(TokenTypeIdentifiers.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
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
            options.SetUserInfoEndpointUris("/authenticate");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.AccessToken], context.ValidTokenTypes);

                    var identity = new ClaimsIdentity("Bearer");
                    identity.AddClaim(new Claim(Claims.ExpiresAt, "2524608000", ClaimValueTypes.Integer64));

                    context.Principal = new ClaimsPrincipal(identity)
                        .SetTokenType(TokenTypeIdentifiers.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
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
            options.SetUserInfoEndpointUris("/authenticate");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.AccessToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetClaim(Claims.AuthorizedParty, "Fabrikam");

                    return ValueTask.CompletedTask;
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
            options.SetUserInfoEndpointUris("/authenticate");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.AccessToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetClaim(Claims.ClientId, "Fabrikam");

                    return ValueTask.CompletedTask;
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
            options.SetUserInfoEndpointUris("/authenticate");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.AccessToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetClaim(Claims.Audience, "Fabrikam");

                    return ValueTask.CompletedTask;
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
            options.SetUserInfoEndpointUris("/authenticate");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.AccessToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetClaims(Claims.Audience, ["Fabrikam", "Contoso"]);

                    return ValueTask.CompletedTask;
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
        Assert.Equal<IEnumerable<string?>?>(["Fabrikam", "Contoso"], (ImmutableArray<string?>?) response[Claims.Audience]);
        Assert.Equal<IEnumerable<string?>?>(["Fabrikam", "Contoso"], (ImmutableArray<string?>?) response[Claims.Private.Audience]);
    }

    [Fact]
    public async Task ValidateToken_MultiplePublicScopesAreNormalizedToSingleClaim()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserInfoEndpointUris("/authenticate");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.AccessToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetClaims(Claims.Scope, [Scopes.OpenId, Scopes.Profile]);

                    return ValueTask.CompletedTask;
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
            options.SetUserInfoEndpointUris("/authenticate");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.AccessToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetClaim(Claims.Scope, "openid profile");

                    return ValueTask.CompletedTask;
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
        Assert.Equal<IEnumerable<string?>?>([Scopes.OpenId, Scopes.Profile], (ImmutableArray<string?>?) response[Claims.Private.Scope]);
    }

    [Fact]
    public async Task ValidateToken_MultiplePublicScopesAreMappedToPrivateClaims()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserInfoEndpointUris("/authenticate");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.AccessToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetClaims(Claims.Scope, [Scopes.OpenId, Scopes.Profile]);

                    return ValueTask.CompletedTask;
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
        Assert.Equal<IEnumerable<string?>?>([Scopes.OpenId, Scopes.Profile], (ImmutableArray<string?>?) response[Claims.Private.Scope]);
    }

    [Fact]
    public async Task ValidateToken_TokenPayloadUsedInsteadOfTokenReferenceIdentifierIsRejected()
    {
        // Arrange
        var token = new OpenIddictToken();

        var manager = CreateTokenManager(mock =>
        {
            mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                .ReturnsAsync(token);

            mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

            mock.Setup(manager => manager.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync(TokenTypeIdentifiers.AccessToken);

            mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetReferenceIdAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync("reference_id");
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.SetUserInfoEndpointUris("/authenticate");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("token_payload", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.AccessToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.AccessToken)
                        .SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56")
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetClaims(Claims.Scope, [Scopes.OpenId, Scopes.Profile]);

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = "token_payload"
        });

        // Assert
        Assert.Null((string?) response[Claims.Subject]);

        Mock.Get(manager).Verify(manager => manager.GetReferenceIdAsync(token, It.IsAny<CancellationToken>()), Times.Once());
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

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(null)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
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
            options.SetUserInfoEndpointUris("/authenticate");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.AccessToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.Private.AuthorizationCode)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
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
        Assert.Equal(SR.FormatID0005(TokenTypeIdentifiers.Private.AuthorizationCode, TokenTypeIdentifiers.AccessToken), exception.Message);
    }

    [Fact]
    public async Task ValidateToken_RequestIsRejectedWhenAuthorizationAssociatedWithTokenCannotBeFound()
    {
        // Arrange
        var manager = CreateAuthorizationManager(mock =>
        {
            mock.Setup(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                .ReturnsAsync(value: null);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.RefreshToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.RefreshToken)
                        .SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                        .SetAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0")
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.Services.AddSingleton(CreateTokenManager(mock =>
            {
                var token = new OpenIddictToken();

                mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                mock.Setup(manager => manager.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(TokenTypeIdentifiers.RefreshToken);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");
            }));

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.TokenExchange,
            SubjectToken = "8xLOxBtZp8",
            SubjectTokenType = TokenTypeIdentifiers.RefreshToken
        });

        // Assert
        Assert.Equal(Errors.InvalidGrant, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2022), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2022), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateToken_RequestIsRejectedWhenAuthorizationAssociatedWithTokenIsInvalid()
    {
        // Arrange
        var authorization = new OpenIddictAuthorization();

        var manager = CreateAuthorizationManager(mock =>
        {
            mock.Setup(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                .ReturnsAsync(authorization);

            mock.Setup(manager => manager.HasStatusAsync(authorization, Statuses.Valid, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.RefreshToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.RefreshToken)
                        .SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                        .SetAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0")
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.Services.AddSingleton(CreateTokenManager(mock =>
            {
                var token = new OpenIddictToken();

                mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                mock.Setup(manager => manager.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(TokenTypeIdentifiers.RefreshToken);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");
            }));

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ActorToken = "accVkjcJyb4BWCxGsndESCJQbdFMogUC5PbRDqceLTC",
            ActorTokenType = TokenTypeIdentifiers.AccessToken,
            GrantType = GrantTypes.TokenExchange,
            SubjectToken = "8xLOxBtZp8",
            SubjectTokenType = TokenTypeIdentifiers.RefreshToken
        });

        // Assert
        Assert.Equal(Errors.InvalidGrant, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2022), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2022), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
        Mock.Get(manager).Verify(manager => manager.HasStatusAsync(authorization, Statuses.Valid, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateToken_RequestIsRejectedWhenSessionAssociatedWithTokenCannotBeFound()
    {
        // Arrange
        var manager = CreateSessionManager(mock =>
        {
            mock.Setup(manager => manager.FindByIdAsync("DE7F0AF0-9595-4546-BE3D-F6BB43FB5FA5", It.IsAny<CancellationToken>()))
                .ReturnsAsync(value: null);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.RefreshToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.RefreshToken)
                        .SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                        .SetAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0")
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.Services.AddSingleton(CreateTokenManager(mock =>
            {
                var token = new OpenIddictToken();

                mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                mock.Setup(manager => manager.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(TokenTypeIdentifiers.RefreshToken);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.GetSessionIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("DE7F0AF0-9595-4546-BE3D-F6BB43FB5FA5");
            }));

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.TokenExchange,
            SubjectToken = "8xLOxBtZp8",
            SubjectTokenType = TokenTypeIdentifiers.RefreshToken
        });

        // Assert
        Assert.Equal(Errors.InvalidGrant, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2210), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2210), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByIdAsync("DE7F0AF0-9595-4546-BE3D-F6BB43FB5FA5", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateToken_RequestIsRejectedWhenSessionAssociatedWithTokenIsInvalid()
    {
        // Arrange
        var session = new OpenIddictSession();

        var manager = CreateSessionManager(mock =>
        {
            mock.Setup(manager => manager.FindByIdAsync("D61DB5C2-235F-4755-9B6F-7D31404A4771", It.IsAny<CancellationToken>()))
                .ReturnsAsync(session);

            mock.Setup(manager => manager.HasStatusAsync(session, Statuses.Valid, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.Token);
                    Assert.Equal([TokenTypeIdentifiers.RefreshToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.RefreshToken)
                        .SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                        .SetSessionId("D61DB5C2-235F-4755-9B6F-7D31404A4771")
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.Services.AddSingleton(CreateTokenManager(mock =>
            {
                var token = new OpenIddictToken();

                mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                mock.Setup(manager => manager.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(TokenTypeIdentifiers.RefreshToken);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.GetSessionIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("D61DB5C2-235F-4755-9B6F-7D31404A4771");
            }));

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ActorToken = "accVkjcJyb4BWCxGsndESCJQbdFMogUC5PbRDqceLTC",
            ActorTokenType = TokenTypeIdentifiers.AccessToken,
            GrantType = GrantTypes.TokenExchange,
            SubjectToken = "8xLOxBtZp8",
            SubjectTokenType = TokenTypeIdentifiers.RefreshToken
        });

        // Assert
        Assert.Equal(Errors.InvalidGrant, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2210), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2210), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByIdAsync("D61DB5C2-235F-4755-9B6F-7D31404A4771", It.IsAny<CancellationToken>()), Times.Once());
        Mock.Get(manager).Verify(manager => manager.HasStatusAsync(session, Statuses.Valid, It.IsAny<CancellationToken>()), Times.Once());
    }
}
