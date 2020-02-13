/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
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
using OpenIddict.Abstractions;
using OpenIddict.Server.FunctionalTests;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreHandlers;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.AspNetCore.FunctionalTests
{
    public partial class OpenIddictServerAspNetCoreIntegrationTests : OpenIddictServerIntegrationTests
    {
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
        public Task ProcessRequest_MatchesCorrespondingEndpoint(string path, OpenIddictServerEndpointType type)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        // Assert
                        Assert.Equal(type, context.EndpointType);

                        return default;
                    }));
            });

            // Act
            return client.PostAsync(path, new OpenIddictRequest());
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
        public Task ProcessRequest_AllowsOverridingEndpoint(string address, OpenIddictServerEndpointType type)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

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

            // Act
            return client.PostAsync(address, new OpenIddictRequest());
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
        public async Task HandleRequestAsync_RejectsInsecureHttpRequests(string address)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.UseAspNetCore()
                       .Configure(options => options.DisableTransportSecurityRequirement = false);
            });

            // Act
            var response = await client.PostAsync(address, new OpenIddictRequest());

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("This server only accepts HTTPS requests.", response.ErrorDescription);
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
            var client = CreateClient(options =>
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

            // Act
            var response = await client.PostAsync(address, new OpenIddictRequest());

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
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
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync(address, new OpenIddictRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        protected override OpenIddictServerIntegrationTestClient CreateClient(Action<OpenIddictServerBuilder> configuration = null)
        {
            var builder = new WebHostBuilder();

            builder.UseEnvironment("Testing");

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

            builder.Configure(app =>
            {
                app.Use(next => async context =>
                {
                    await next(context);

                    var feature = context.Features.Get<OpenIddictServerAspNetCoreFeature>();
                    var response = feature?.Transaction.GetProperty<object>("custom_response");
                    if (response != null)
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

                    else if (context.Request.Path == "/signout")
                    {
                        await context.SignOutAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                        return;
                    }

                    else if (context.Request.Path == "/challenge")
                    {
                        await context.ChallengeAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                        return;
                    }

                    else if (context.Request.Path == "/challenge/custom")
                    {
                        var properties = new AuthenticationProperties(new Dictionary<string, string>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = "custom_error",
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "custom_error_description",
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorUri] = "custom_error_uri"
                        });

                        await context.ChallengeAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, properties);
                        return;
                    }

                    else if (context.Request.Path == "/authenticate")
                    {
                        var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                        if (result?.Principal == null)
                        {
                            return;
                        }

                        context.Response.ContentType = "application/json";
                        await context.Response.WriteAsync(JsonSerializer.Serialize(
                            new OpenIddictResponse(result.Principal.Claims.GroupBy(claim => claim.Type)
                                .Select(group => new KeyValuePair<string, string[]>(
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
            });

            var server = new TestServer(builder);
            return new OpenIddictServerIntegrationTestClient(server.CreateClient());
        }
    }
}
