/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using JetBrains.Annotations;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict;
using OpenIddict.Infrastructure;

namespace Microsoft.AspNetCore.Builder {
    public static class OpenIddictExtensions {
        /// <summary>
        /// Registers the OpenIddict core services in the DI container.
        /// When using this method, custom stores must be manually registered.
        /// </summary>
        /// <typeparam name="TUser">The type of the User entity.</typeparam>
        /// <typeparam name="TRole">The type of the Role entity.</typeparam>
        /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
        /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
        /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
        /// <typeparam name="TToken">The type of the Token entity.</typeparam>
        /// <param name="services">The services collection.</param>
        /// <remarks>
        /// Note: the core services include native support for the non-interactive flows
        /// (resource owner password credentials, client credentials, refresh token).
        /// To support interactive flows like authorization code or implicit/hybrid,
        /// consider adding the MVC module or creating your own authorization controller.
        /// </remarks>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddOpenIddict<TUser, TRole, TApplication, TAuthorization, TScope, TToken>(
            [NotNull] this IServiceCollection services)
            where TUser : class
            where TRole : class
            where TApplication : class
            where TAuthorization : class
            where TScope : class
            where TToken : class {
            if (services == null) {
                throw new ArgumentNullException(nameof(services));
            }

            var builder = new OpenIddictBuilder(services) {
                ApplicationType = typeof(TApplication),
                AuthorizationType = typeof(TAuthorization),
                RoleType = typeof(TRole),
                ScopeType = typeof(TScope),
                TokenType = typeof(TToken),
                UserType = typeof(TUser)
            };

            // Register the services required by the OpenID Connect server middleware.
            builder.Services.AddAuthentication();
            builder.Services.AddDistributedMemoryCache();

            builder.Configure(options => {
                // Register the OpenID Connect server provider in the OpenIddict options.
                options.Provider = new OpenIddictProvider<TUser, TApplication, TAuthorization, TScope, TToken>();
            });

            // Register the OpenIddict core services in the DI container.
            builder.Services.TryAddScoped<OpenIddictApplicationManager<TApplication>>();
            builder.Services.TryAddScoped<OpenIddictAuthorizationManager<TAuthorization>>();
            builder.Services.TryAddScoped<OpenIddictScopeManager<TScope>>();
            builder.Services.TryAddScoped<OpenIddictTokenManager<TToken>>();
            builder.Services.TryAddScoped<OpenIddictUserManager<TUser>>();
            builder.Services.TryAddScoped<OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>>();

            return builder;
        }

        /// <summary>
        /// Registers OpenIddict in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="app">The application builder used to register middleware instances.</param>
        /// <returns>The <see cref="IApplicationBuilder"/>.</returns>
        public static IApplicationBuilder UseOpenIddict([NotNull] this IApplicationBuilder app) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            // Resolve the OpenIddict options from the DI container.
            var options = app.ApplicationServices.GetRequiredService<IOptions<OpenIddictOptions>>().Value;

            if (options.Cache == null) {
                options.Cache = app.ApplicationServices.GetRequiredService<IDistributedCache>();
            }

            // Get the modules registered by the application
            // and add the OpenID Connect server middleware.
            var modules = options.Modules.ToList();
            modules.Add(new OpenIddictModule("OpenID Connect server", 0, builder => builder.UseOpenIdConnectServer(options)));

            // Register the OpenIddict modules in the ASP.NET Core pipeline.
            foreach (var module in modules.OrderBy(module => module.Position)) {
                if (module?.Registration == null) {
                    throw new InvalidOperationException("An invalid OpenIddict module was registered.");
                }

                module.Registration(app);
            }

            return app;
        }
    }
}