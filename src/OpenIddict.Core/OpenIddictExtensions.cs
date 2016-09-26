/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using AspNet.Security.OpenIdConnect.Extensions;
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
        /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
        /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
        /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
        /// <typeparam name="TToken">The type of the Token entity.</typeparam>
        /// <param name="services">The services collection.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddOpenIddict<TApplication, TAuthorization, TScope, TToken>(
            [NotNull] this IServiceCollection services)
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
                ScopeType = typeof(TScope),
                TokenType = typeof(TToken)
            };

            // Register the services required by the OpenID Connect server middleware.
            builder.Services.AddAuthentication();
            builder.Services.AddDistributedMemoryCache();

            builder.Configure(options => {
                // Register the OpenID Connect server provider in the OpenIddict options.
                options.Provider = new OpenIddictProvider<TApplication, TAuthorization, TScope, TToken>();
            });

            // Register the OpenIddict core services in the DI container.
            builder.Services.TryAddScoped<OpenIddictApplicationManager<TApplication>>();
            builder.Services.TryAddScoped<OpenIddictAuthorizationManager<TAuthorization>>();
            builder.Services.TryAddScoped<OpenIddictScopeManager<TScope>>();
            builder.Services.TryAddScoped<OpenIddictTokenManager<TToken>>();
            builder.Services.TryAddScoped<OpenIddictServices<TApplication, TAuthorization, TScope, TToken>>();

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

            if (options.SigningCredentials.Count == 0) {
                throw new InvalidOperationException("At least one signing key must be registered. Consider registering a X.509 " +
                                                    "certificate using 'services.AddOpenIddict().AddSigningCertificate()' or call " +
                                                    "'services.AddOpenIddict().AddEphemeralSigningKey()' to use an ephemeral key.");
            }

            // Ensure at least one flow has been enabled.
            if (options.GrantTypes.Count == 0) {
                throw new InvalidOperationException("At least one OAuth2/OpenID Connect flow must be enabled.");
            }

            // Ensure the authorization endpoint has been enabled when
            // the authorization code or implicit grants are supported.
            if (!options.AuthorizationEndpointPath.HasValue && (options.IsAuthorizationCodeFlowEnabled() ||
                                                                options.IsImplicitFlowEnabled())) {
                throw new InvalidOperationException("The authorization endpoint must be enabled to use " +
                                                    "the authorization code and implicit flows.");
            }

            // Ensure the token endpoint has been enabled when the authorization code,
            // client credentials, password or refresh token grants are supported.
            else if (!options.TokenEndpointPath.HasValue && (options.IsAuthorizationCodeFlowEnabled() ||
                                                             options.IsClientCredentialsFlowEnabled() ||
                                                             options.IsPasswordFlowEnabled() ||
                                                             options.IsRefreshTokenFlowEnabled())) {
                throw new InvalidOperationException("The token endpoint must be enabled to use the authorization code, " +
                                                    "client credentials, password and refresh token flows.");
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

        /// <summary>
        /// Determines whether the authorization code flow has been enabled.
        /// </summary>
        /// <param name="options">The OpenIddict options.</param>
        /// <returns><c>true</c> if the authorization code flow has been enabled, <c>false</c> otherwise.</returns>
        public static bool IsAuthorizationCodeFlowEnabled([NotNull] this OpenIddictOptions options) {
            if (options == null) {
                throw new ArgumentNullException(nameof(options));
            }

            return options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.AuthorizationCode);
        }

        /// <summary>
        /// Determines whether the client credentials flow has been enabled.
        /// </summary>
        /// <param name="options">The OpenIddict options.</param>
        /// <returns><c>true</c> if the client credentials flow has been enabled, <c>false</c> otherwise.</returns>
        public static bool IsClientCredentialsFlowEnabled([NotNull] this OpenIddictOptions options) {
            if (options == null) {
                throw new ArgumentNullException(nameof(options));
            }

            return options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.ClientCredentials);
        }

        /// <summary>
        /// Determines whether the implicit flow has been enabled.
        /// </summary>
        /// <param name="options">The OpenIddict options.</param>
        /// <returns><c>true</c> if the implicit flow has been enabled, <c>false</c> otherwise.</returns>
        public static bool IsImplicitFlowEnabled([NotNull] this OpenIddictOptions options) {
            if (options == null) {
                throw new ArgumentNullException(nameof(options));
            }

            return options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.Implicit);
        }

        /// <summary>
        /// Determines whether the password flow has been enabled.
        /// </summary>
        /// <param name="options">The OpenIddict options.</param>
        /// <returns><c>true</c> if the password flow has been enabled, <c>false</c> otherwise.</returns>
        public static bool IsPasswordFlowEnabled([NotNull] this OpenIddictOptions options) {
            if (options == null) {
                throw new ArgumentNullException(nameof(options));
            }

            return options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.Password);
        }

        /// <summary>
        /// Determines whether the refresh token flow has been enabled.
        /// </summary>
        /// <param name="options">The OpenIddict options.</param>
        /// <returns><c>true</c> if the refresh token flow has been enabled, <c>false</c> otherwise.</returns>
        public static bool IsRefreshTokenFlowEnabled([NotNull] this OpenIddictOptions options) {
            if (options == null) {
                throw new ArgumentNullException(nameof(options));
            }

            return options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.RefreshToken);
        }
    }
}