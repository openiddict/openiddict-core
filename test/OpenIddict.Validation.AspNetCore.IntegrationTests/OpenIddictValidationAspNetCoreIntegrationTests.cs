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
using OpenIddict.Validation.IntegrationTests;
using Xunit;
using Xunit.Abstractions;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlers.Protection;

#if SUPPORTS_JSON_NODES
using System.Text.Json.Nodes;
#endif

namespace OpenIddict.Validation.AspNetCore.IntegrationTests;

public partial class OpenIddictValidationAspNetCoreIntegrationTests : OpenIddictValidationIntegrationTests
{
    public OpenIddictValidationAspNetCoreIntegrationTests(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task ProcessAuthentication_CreationDateIsMappedToIssuedUtc()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
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

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The caller is responsible for disposing the test server.")]
    protected override
#if SUPPORTS_GENERIC_HOST
        async
#endif
        ValueTask<OpenIddictValidationIntegrationTestServer> CreateServerAsync(Action<OpenIddictValidationBuilder>? configuration = null)
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
                .AddValidation(options =>
                {
                    options.UseAspNetCore();

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

        return new OpenIddictValidationAspNetCoreIntegrationTestServer(host);
#else
        var server = new TestServer(builder);

        return new(new OpenIddictValidationAspNetCoreIntegrationTestServer(server));
#endif

        void ConfigurePipeline(IApplicationBuilder app)
        {
            app.Use(next => async context =>
            {
                await next(context);

                var feature = context.Features.Get<OpenIddictValidationAspNetCoreFeature>();
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
                if (context.Request.Path == "/authenticate")
                {
                    var result = await context.AuthenticateAsync(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                    if (result?.Principal is null)
                    {
                        await context.ChallengeAsync(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
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
                    var result = await context.AuthenticateAsync(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                    if (result?.Properties is null)
                    {
                        return;
                    }

                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(new OpenIddictResponse(result.Properties.Items)));
                    return;
                }

                else if (context.Request.Path == "/challenge")
                {
                    await context.ChallengeAsync(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
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
