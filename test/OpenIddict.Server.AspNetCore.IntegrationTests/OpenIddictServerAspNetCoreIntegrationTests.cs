/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server.IntegrationTests;
using Xunit;
using Xunit.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreHandlers;
using static OpenIddict.Server.OpenIddictServerEvents;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server.AspNetCore.IntegrationTests
{
    public partial class OpenIddictServerAspNetCoreIntegrationTests : OpenIddictServerIntegrationTests
    {
        public OpenIddictServerAspNetCoreIntegrationTests(ITestOutputHelper outputHelper)
            : base(outputHelper)
        {
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
        public async Task ProcessRequest_MatchesCorrespondingEndpoint(string path, OpenIddictServerEndpointType type)
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleLogoutRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SignOut();

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
        [InlineData("/custom/connect/custom", OpenIddictServerEndpointType.Unknown)]
        [InlineData("/custom/connect/introspect", OpenIddictServerEndpointType.Introspection)]
        [InlineData("/custom/connect/logout", OpenIddictServerEndpointType.Logout)]
        [InlineData("/custom/connect/revoke", OpenIddictServerEndpointType.Revocation)]
        [InlineData("/custom/connect/token", OpenIddictServerEndpointType.Token)]
        [InlineData("/custom/connect/userinfo", OpenIddictServerEndpointType.Userinfo)]
        [InlineData("/custom/.well-known/openid-configuration", OpenIddictServerEndpointType.Configuration)]
        [InlineData("/custom/.well-known/jwks", OpenIddictServerEndpointType.Cryptography)]
        public async Task ProcessRequest_AllowsOverridingEndpoint(string address, OpenIddictServerEndpointType type)
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleLogoutRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SignOut();

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
        [InlineData("/connect/introspect")]
        [InlineData("/connect/logout")]
        [InlineData("/connect/revoke")]
        [InlineData("/connect/token")]
        [InlineData("/connect/userinfo")]
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
        }

        [Theory]
        [InlineData("/.well-known/openid-configuration")]
        [InlineData("/.well-known/jwks")]
        [InlineData("/custom")]
        [InlineData("/connect/authorize")]
        [InlineData("/connect/introspect")]
        [InlineData("/connect/logout")]
        [InlineData("/connect/revoke")]
        [InlineData("/connect/token")]
        [InlineData("/connect/userinfo")]
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
        [InlineData("/connect/introspect")]
        [InlineData("/connect/logout")]
        [InlineData("/connect/revoke")]
        [InlineData("/connect/token")]
        [InlineData("/connect/userinfo")]
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

        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The caller is responsible of disposing the test server.")]
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

            return new ValueTask<OpenIddictServerIntegrationTestServer>(new OpenIddictServerAspNetCoreIntegrationTestServer(server));
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
                            items: new Dictionary<string, string?>(),
                            parameters: new Dictionary<string, object?>
                            {
                                ["boolean_parameter"] = true,
                                ["integer_parameter"] = 42,
                                ["string_parameter"] = "Bob l'Eponge",
                                ["array_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"[""Contoso"",""Fabrikam""]"),
                                ["object_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}")
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
                            items: new Dictionary<string, string?>(),
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
                                [OpenIddictServerAspNetCoreConstants.Properties.ErrorUri] = "custom_error_uri"
                            },
                            parameters: new Dictionary<string, object?>
                            {
                                ["boolean_parameter"] = true,
                                ["integer_parameter"] = 42,
                                ["string_parameter"] = "Bob l'Eponge",
                                ["array_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"[""Contoso"",""Fabrikam""]"),
                                ["object_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}")
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

                        context.Response.ContentType = "application/json";
                        await context.Response.WriteAsync(JsonSerializer.Serialize(
                            new OpenIddictResponse(result.Principal.Claims.GroupBy(claim => claim.Type)
                                .Select(group => new KeyValuePair<string, string?[]?>(
                                    group.Key, group.Select(claim => claim.Value).ToArray())))));
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
}
