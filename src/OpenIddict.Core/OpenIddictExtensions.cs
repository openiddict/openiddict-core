/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Core;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class OpenIddictExtensions
    {
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
            where TToken : class
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddDistributedMemoryCache();
            services.AddMemoryCache();
            services.AddOptions();

            // Register the OpenIddict core services in the DI container.
            services.TryAddScoped<OpenIddictApplicationManager<TApplication>>();
            services.TryAddScoped<OpenIddictAuthorizationManager<TAuthorization>>();
            services.TryAddScoped<OpenIddictScopeManager<TScope>>();
            services.TryAddScoped<OpenIddictTokenManager<TToken>>();

            return new OpenIddictBuilder(services)
            {
                ApplicationType = typeof(TApplication),
                AuthorizationType = typeof(TAuthorization),
                ScopeType = typeof(TScope),
                TokenType = typeof(TToken)
            };
        }

        /// <summary>
        /// Registers the default OpenIddict services in the DI container, using the specified entities.
        /// </summary>
        /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
        /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
        /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
        /// <typeparam name="TToken">The type of the Token entity.</typeparam>
        /// <param name="services">The services collection.</param>
        /// <param name="configuration">The configuration delegate used to register new services.</param>
        /// <returns>The <see cref="IServiceCollection"/>.</returns>
        public static IServiceCollection AddOpenIddict<TApplication, TAuthorization, TScope, TToken>(
            [NotNull] this IServiceCollection services,
            [NotNull] Action<OpenIddictBuilder> configuration)
            where TApplication : class
            where TAuthorization : class
            where TScope : class
            where TToken : class
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            // Register the OpenIddict core services and invoke the configuration delegate.
            configuration(services.AddOpenIddict<TApplication, TAuthorization, TScope, TToken>());

            return services;
        }
    }
}