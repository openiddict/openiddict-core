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
using Microsoft.Extensions.DependencyInjection.Extensions;
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

            builder.Services.TryAddSingleton(
                typeof(IOpenIdConnectServerProvider),
                typeof(OpenIddictProvider<,>).MakeGenericType(
                    builder.UserType, typeof(TApplication)));

            builder.Services.TryAddScoped(
                typeof(OpenIddictManager<,>).MakeGenericType(
                    builder.UserType, typeof(TApplication)));

            var services = new OpenIddictServices(builder.Services) {
                ApplicationType = typeof(TApplication),
                RoleType = builder.RoleType,
                UserType = builder.UserType
            };

            builder.Services.TryAddSingleton(services);

            configuration(services);

            return builder;
        }

        public static OpenIddictBuilder AddModule(
            [NotNull] this OpenIddictBuilder builder,
            [NotNull] string name, int position,
            [NotNull] Action<IApplicationBuilder> registration) {
            // Note: always call ToArray to make sure the foreach
            // block doesn't iterate on the modified collection.
            foreach (var module in builder.Modules.Where(module => string.Equals(module.Name, name)).ToArray()) {
                builder.Modules.Remove(module);
            }

            builder.Modules.Add(new OpenIddictModule {
                Name = name,
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
            builder.Options.Provider = app.ApplicationServices.GetRequiredService<IOpenIdConnectServerProvider>();

            // By default, enable AllowInsecureHttp in development/testing environments.
            var environment = app.ApplicationServices.GetRequiredService<IHostingEnvironment>();
            builder.Options.AllowInsecureHttp = environment.IsDevelopment() || environment.IsEnvironment("Testing");

            configuration(builder);


            // Add OpenIdConnectServerMiddleware to the ASP.NET 5 pipeline.
            builder.AddModule("ASOS", 0, map => map.UseOpenIdConnectServer(builder.Options));

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