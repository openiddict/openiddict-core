/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.Server.FunctionalTests;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Server.AspNetCore.FunctionalTests
{
    public partial class OpenIddictServerAspNetCoreIntegrationTests : OpenIddictServerIntegrationTests
    {
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

                app.Use(next => context =>
                {
                    if (context.Request.Path == "/invalid-signin")
                    {
                        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                        identity.AddClaim(Claims.Subject, "Bob le Bricoleur");

                        var principal = new ClaimsPrincipal(identity);

                        return context.SignInAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, principal);
                    }

                    else if (context.Request.Path == "/invalid-signout")
                    {
                        return context.SignOutAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    }

                    else if (context.Request.Path == "/invalid-challenge")
                    {
                        return context.ChallengeAsync(
                            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                            new AuthenticationProperties());
                    }

                    else if (context.Request.Path == "/invalid-authenticate")
                    {
                        return context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    }

                    return next(context);
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
