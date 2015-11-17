/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNet.Hosting;
using Microsoft.AspNet.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using OpenIddict;

namespace Microsoft.AspNet.Builder {
    public static class OpenIddictExtensions {
        public static IdentityBuilder AddOpenIddictCore<TApplication>(
            [NotNull] this IdentityBuilder builder,
            [NotNull] Action<OpenIddictServices> configuration)
            where TApplication : class {
            builder.Services.AddAuthentication();
            builder.Services.AddCaching();

            builder.Services.AddSingleton(
                typeof(OpenIdConnectServerProvider),
                typeof(OpenIddictProvider<,>).MakeGenericType(
                    builder.UserType, typeof(TApplication)));

            builder.Services.AddScoped(
                typeof(OpenIddictManager<,>).MakeGenericType(
                    builder.UserType, typeof(TApplication)));

            var services = new OpenIddictServices(builder.Services) {
                ApplicationType = typeof(TApplication),
                RoleType = builder.RoleType,
                UserType = builder.UserType
            };

            builder.Services.AddInstance(services);

            configuration(services);

            return builder;
        }

        public static OpenIddictBuilder AddModule(
            [NotNull] this OpenIddictBuilder builder, int position,
            [NotNull] Action<IApplicationBuilder> registration) {
            builder.Modules.Add(new OpenIddictModule {
                Position = position,
                Registration = registration
            });

            return builder;
        }

        public static IApplicationBuilder UseOpenIddictCore([NotNull] this IApplicationBuilder app) {
            return app.UseOpenIddictCore(options => { });
        }

        public static IApplicationBuilder UseOpenIddictCore(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<OpenIddictBuilder> configuration) {
            var builder = new OpenIddictBuilder();

            // Resolve the OpenIddict provider from the services container.
            builder.Options.Provider = app.ApplicationServices.GetRequiredService<OpenIdConnectServerProvider>();

            // By default, enable AllowInsecureHttp in development/testing environments.
            var environment = app.ApplicationServices.GetRequiredService<IHostingEnvironment>();
            builder.Options.AllowInsecureHttp = environment.IsDevelopment() || environment.IsEnvironment("Testing");

            configuration(builder);

            builder.AddModule(-10, map => map.UseCors(options => {
                options.AllowAnyHeader();
                options.AllowAnyMethod();
                options.AllowAnyOrigin();
                options.AllowCredentials();
            }));

            // Add OpenIdConnectServerMiddleware to the ASP.NET 5 pipeline.
            builder.AddModule(0, map => map.UseOpenIdConnectServer(builder.Options));

            // Register the OpenIddict modules in the ASP.NET 5 pipeline.
            foreach (var module in builder.Modules.OrderBy(module => module.Position)) {
                if (module.Registration == null) {
                    throw new InvalidOperationException("The registration delegate cannot be null.");
                }

                module.Registration(app);
            }

            return app;
        }
    }
}