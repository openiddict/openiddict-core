/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Moq;
using Xunit;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlers.Protection;

namespace OpenIddict.Validation.IntegrationTests;

public abstract partial class OpenIddictValidationIntegrationTests
{
    [Fact]
    public async Task ValidateToken_TokenIdentifiersAreRestoredFromClaims()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
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
            options.EnableAuthorizationEntryValidation();
            options.EnableSessionEntryValidation();
            options.EnableTokenEntryValidation();

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
}
