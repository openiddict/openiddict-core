/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Owin;
using Microsoft.Owin.Testing;
using OpenIddict.Abstractions;
using OpenIddict.Server.FunctionalTests;
using Owin;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Server.Owin.FunctionalTests
{
    public partial class OpenIddictServerOwinIntegrationTests : OpenIddictServerIntegrationTests
    {
        protected override OpenIddictServerIntegrationTestClient CreateClient(Action<OpenIddictServerBuilder> configuration = null)
        {
            var services = new ServiceCollection();
            ConfigureServices(services);

            services.AddOpenIddict()
                .AddServer(options =>
                {
                    // Disable the transport security requirement during testing.
                    options.UseOwin()
                           .DisableTransportSecurityRequirement();

                    configuration?.Invoke(options);
                });

            var provider = services.BuildServiceProvider();

            var server = TestServer.Create(app =>
            {
                app.Use(async (context, next) =>
                {
                    using var scope = provider.CreateScope();

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

                app.Use(async (context, next) =>
                {
                    await next();

                    var transaction = context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName);
                    var response = transaction?.GetProperty<object>("custom_response");
                    if (response != null)
                    {
                        context.Response.ContentType = "application/json";
                        await context.Response.WriteAsync(JsonSerializer.Serialize(response));
                    }
                });

                app.UseOpenIddictServer();

                app.Use((context, next) =>
                {
                    if (context.Request.Path == new PathString("/invalid-signin"))
                    {
                        var identity = new ClaimsIdentity(OpenIddictServerOwinDefaults.AuthenticationType);
                        identity.AddClaim(Claims.Subject, "Bob le Bricoleur");

                        context.Authentication.SignIn(identity);
                        return Task.CompletedTask;
                    }

                    else if (context.Request.Path == new PathString("/invalid-signout"))
                    {
                        context.Authentication.SignOut(OpenIddictServerOwinDefaults.AuthenticationType);
                        return Task.CompletedTask;
                    }

                    else if (context.Request.Path == new PathString("/invalid-challenge"))
                    {
                        context.Authentication.Challenge(OpenIddictServerOwinDefaults.AuthenticationType);
                        return Task.CompletedTask;
                    }

                    else if (context.Request.Path == new PathString("/invalid-authenticate"))
                    {
                        return context.Authentication.AuthenticateAsync(OpenIddictServerOwinDefaults.AuthenticationType);
                    }

                    return next();
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

            return new OpenIddictServerIntegrationTestClient(server.HttpClient);
        }
    }
}
