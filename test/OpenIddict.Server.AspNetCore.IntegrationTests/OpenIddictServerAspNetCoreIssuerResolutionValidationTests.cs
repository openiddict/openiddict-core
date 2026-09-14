/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Validation.AspNetCore;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.AspNetCore.IntegrationTests;

/// <summary>
/// Ensures the validation stack configured with the server integration follows the issuer resolved per request.
/// </summary>
public class OpenIddictServerAspNetCoreIssuerResolutionValidationTests
{
    [Theory]
    [InlineData("tenant1", "tenant1", HttpStatusCode.OK)]
    [InlineData("tenant2", "tenant2", HttpStatusCode.OK)]
    [InlineData("tenant1", "tenant2", HttpStatusCode.Unauthorized)]
    [InlineData("tenant2", "tenant1", HttpStatusCode.Unauthorized)]
    [InlineData("tenant1", "unknown", HttpStatusCode.Unauthorized)]
    public async Task Validation_AccessTokensAreValidatedAgainstResolvedIssuer(
        string issuer, string api, HttpStatusCode status)
    {
        // Arrange
        using var host = await CreateHostAsync(credentials: false);
        using var client = host.GetTestClient();

        var token = await GetAccessTokenAsync(client, issuer);

        // Act
        using var response = await CallApiAsync(client, api, token);

        // Assert
        Assert.Equal(status, response.StatusCode);
    }

    [Theory]
    [InlineData("tenant1", "tenant1", HttpStatusCode.OK)]
    [InlineData("tenant2", "tenant2", HttpStatusCode.OK)]
    [InlineData("tenant2", "tenant1", HttpStatusCode.Unauthorized)]
    public async Task Validation_IssuerSpecificCredentialsAreUsed(string issuer, string api, HttpStatusCode status)
    {
        // Arrange
        using var host = await CreateHostAsync(credentials: true);
        using var client = host.GetTestClient();

        var token = await GetAccessTokenAsync(client, issuer);

        // Act
        using var response = await CallApiAsync(client, api, token);

        // Assert
        Assert.Equal(status, response.StatusCode);
    }

    [Theory]
    [InlineData(false, HttpStatusCode.OK)]
    [InlineData(true, HttpStatusCode.Unauthorized)]
    public async Task Validation_TokenWithCorrectIssuerSignedWithAnotherIssuerKeyIsRejected(
        bool credentials, HttpStatusCode status)
    {
        // Arrange
        var toggle = new CredentialsSwitch { Enabled = false };

        using var host = await CreateHostAsync(credentials: true, encryption: false, toggle);
        using var client = host.GetTestClient();

        // Note: while the issuer-specific credentials are disabled, the token issued for tenant2 carries
        // the correct "iss" claim but is signed using the default signing key (i.e the key of tenant1).
        var token = await GetAccessTokenAsync(client, "tenant2");

        toggle.Enabled = credentials;

        // Act
        using var response = await CallApiAsync(client, "tenant2", token);

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

    private static async Task<HttpResponseMessage> CallApiAsync(HttpClient client, string tenant, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"http://localhost/{tenant}/api");
        request.Headers.Authorization = new AuthenticationHeaderValue(Schemes.Bearer, token);

        return await client.SendAsync(request);
    }

    private static async Task<IHost> CreateHostAsync(bool credentials, bool encryption = true, CredentialsSwitch? toggle = null)
    {
        var builder = new HostBuilder();
        builder.UseEnvironment("Testing");

        builder.ConfigureServices(services =>
        {
            services.AddSingleton(toggle ?? new CredentialsSwitch { Enabled = true });

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

                    options.UseAspNetCore()
                           .DisableTransportSecurityRequirement();

                    if (!encryption)
                    {
                        options.DisableAccessTokenEncryption();
                    }

                    if (credentials)
                    {
                        options.SetIssuerCredentialsProvider<TenantCredentialsProvider>();
                    }

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
                    options.UseAspNetCore();
                });
        });

        builder.ConfigureWebHost(options =>
        {
            options.UseTestServer();
            options.Configure(app =>
            {
                app.UseAuthentication();

                app.Run(async context =>
                {
                    if (!context.Request.Path.Value!.EndsWith("/api", StringComparison.Ordinal))
                    {
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                        return;
                    }

                    var result = await context.AuthenticateAsync(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                    if (result.Principal is null)
                    {
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        return;
                    }

                    await context.Response.WriteAsync(result.Principal.GetClaim(Claims.Subject)!);
                });
            });
        });

        return await builder.StartAsync();
    }

    private sealed class CredentialsSwitch
    {
        public bool Enabled { get; set; }
    }

    private sealed class TenantCredentialsProvider(CredentialsSwitch toggle) : IOpenIddictServerIssuerCredentialsProvider
    {
        private static readonly SigningCredentials Credentials = new(
            new RsaSecurityKey(RSA.Create(keySizeInBits: 2048)) { KeyId = "tenant2" }, SecurityAlgorithms.RsaSha256);

        private static readonly EncryptingCredentials Encryption = new(
            new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)) { KeyId = "tenant2-enc" },
            SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes128CbcHmacSha256);

        public ValueTask<OpenIddictServerCredentials?> GetCredentialsAsync(
            Uri issuer, IServiceProvider provider, CancellationToken cancellationToken)
            => new(toggle.Enabled && issuer.AbsoluteUri is "http://localhost/tenant2/" ?
                new OpenIddictServerCredentials([Credentials], [Encryption]) : null);
    }
}
