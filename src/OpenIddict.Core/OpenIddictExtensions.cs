/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Core;
using OpenIddict.Models;

namespace Microsoft.Extensions.DependencyInjection {
    public static class OpenIddictExtensions {
        /// <summary>
        /// Registers the default OpenIddict services in the DI container,
        /// using the default entities and the default entity key type.
        /// </summary>
        /// <param name="services">The services collection.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddOpenIddict([NotNull] this IServiceCollection services) {
            if (services == null) {
                throw new ArgumentNullException(nameof(services));
            }

            return services.AddOpenIddict<OpenIddictApplication, OpenIddictAuthorization, OpenIddictScope, OpenIddictToken>();
        }

        /// <summary>
        /// Registers the default OpenIddict services in the DI container,
        /// using the default entities and the specified entity key type.
        /// </summary>
        /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
        /// <param name="services">The services collection.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddOpenIddict<TKey>([NotNull] this IServiceCollection services)
            where TKey : IEquatable<TKey> {
            if (services == null) {
                throw new ArgumentNullException(nameof(services));
            }

            return services.AddOpenIddict<OpenIddictApplication<TKey>,
                                          OpenIddictAuthorization<TKey>,
                                          OpenIddictScope<TKey>,
                                          OpenIddictToken<TKey>>();
        }

        /// <summary>
        /// Registers the default OpenIddict services in the DI container, using the specified entities.
        /// </summary>
        /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
        /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
        /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
        /// <typeparam name="TToken">The type of the Token entity.</typeparam>
        /// <param name="services">The services collection.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddOpenIddict<TApplication, TAuthorization, TScope, TToken>([NotNull] this IServiceCollection services)
            where TApplication : class
            where TAuthorization : class
            where TScope : class
            where TToken : class {
            if (services == null) {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddOptions();

            var builder = new OpenIddictBuilder(services) {
                ApplicationType = typeof(TApplication),
                AuthorizationType = typeof(TAuthorization),
                ScopeType = typeof(TScope),
                TokenType = typeof(TToken)
            };

            // Register the OpenIddict core services in the DI container.
            builder.Services.TryAddSingleton(builder);
            builder.Services.TryAddScoped<OpenIddictApplicationManager<TApplication>>();
            builder.Services.TryAddScoped<OpenIddictAuthorizationManager<TAuthorization>>();
            builder.Services.TryAddScoped<OpenIddictScopeManager<TScope>>();
            builder.Services.TryAddScoped<OpenIddictTokenManager<TToken>>();

            return builder;
        }
    }
}