/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Owin.Testing;
using OpenIddict.Validation.Owin;
using Owin;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.Owin.IntegrationTests;

/// <summary>
/// Ensures the validation stack configured with the server integration follows the issuer resolved per request.
/// </summary>
public class OpenIddictServerOwinIssuerResolutionValidationTests
{
    [Theory]
    [InlineData("tenant1", "tenant1", HttpStatusCode.OK)]
    [InlineData("tenant2", "tenant2", HttpStatusCode.OK)]
    [InlineData("tenant1", "tenant2", HttpStatusCode.Unauthorized)]
    [InlineData("tenant1", "unknown", HttpStatusCode.Unauthorized)]
    public async Task Validation_AccessTokensAreValidatedAgainstResolvedIssuer(
        string issuer, string api, HttpStatusCode status)
    {
        // Arrange
        using var server = CreateServer();
        using var client = server.HttpClient;

        var token = await GetAccessTokenAsync(client, issuer);

        // Act
        using var request = new HttpRequestMessage(HttpMethod.Get, $"http://localhost/{api}/api");
        request.Headers.Authorization = new AuthenticationHeaderValue(Schemes.Bearer, token);

        using var response = await client.SendAsync(request);

        // Assert
        Assert.Equal(status, response.StatusCode);
    }

    private static async Task<string> GetAccessTokenAsync(HttpClient client, string tenant)
    {
        using var response = await client.PostAsync($"http://localhost/{tenant}/connect/token", new FormUrlEncodedContent(
        [
            new(Parameters.GrantType, GrantTypes.Password),
            new(Parameters.Username, "johndoe"),
            new(Parameters.Password, "A3ddj3w")
        ]));

        var payload = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(payload);

        Assert.True(document.RootElement.TryGetProperty(Parameters.AccessToken, out JsonElement token), payload);

        return token.GetString()!;
    }

    private static TestServer CreateServer()
    {
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.EnableDegradedMode();
                options.AddIssuers("http://localhost/tenant1/", "http://localhost/tenant2/");

                options.AllowPasswordFlow()
                       .AcceptAnonymousClients()
                       .SetTokenEndpointUris("connect/token");

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                options.UseOwin()
                       .DisableTransportSecurityRequirement();

                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder.UseInlineHandler(static context => ValueTask.CompletedTask));

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(static context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return ValueTask.CompletedTask;
                    }));
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseOwin();
            });

        var provider = services.BuildServiceProvider();

        return TestServer.Create(app =>
        {
            app.Use(async (context, next) =>
            {
                await using var scope = provider.CreateAsyncScope();

                context.Set(typeof(IServiceProvider).FullName, scope.ServiceProvider);

                try
                {
                    await next();
                }

                finally
                {
                    context.Environment.Remove(typeof(IServiceProvider).FullName);
                }
            });

            app.UseOpenIddictServer();
            app.UseOpenIddictValidation();

            app.Run(async context =>
            {
                if (!context.Request.Path.Value.EndsWith("/api", StringComparison.Ordinal))
                {
                    context.Response.StatusCode = 404;
                    return;
                }

                var result = await context.Authentication.AuthenticateAsync(OpenIddictValidationOwinDefaults.AuthenticationType);
                if (result?.Identity is not { IsAuthenticated: true })
                {
                    context.Response.StatusCode = 401;
                    return;
                }

                await context.Response.WriteAsync(result.Identity.FindFirst(Claims.Subject)!.Value);
            });
        });
    }
}
