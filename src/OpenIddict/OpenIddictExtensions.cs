/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict;

namespace Microsoft.AspNetCore.Builder {
    public static class OpenIddictExtensions {
        /// <summary>
        /// Registers the default OpenIddict services in the DI container,
        /// including the Entity Framework stores and the built-in entities.
        /// </summary>
        /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
        /// <param name="services">The services collection.</param>
        /// <remarks>
        /// Note: the core services include native support for the non-interactive flows
        /// (resource owner password credentials, client credentials, refresh token).
        /// To support interactive flows like authorization code or implicit/hybrid,
        /// consider adding the MVC module or creating your own authorization controller.
        /// </remarks>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddOpenIddict<TContext>([NotNull] this IServiceCollection services)
            where TContext : DbContext {
            if (services == null) {
                throw new ArgumentNullException(nameof(services));
            }

            return services.AddOpenIddict<OpenIddictUser, TContext>();
        }

        /// <summary>
        /// Registers the default OpenIddict services in the DI container,
        /// including the Entity Framework stores and the specified entities.
        /// </summary>
        /// <typeparam name="TUser">The type of the User entity.</typeparam>
        /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
        /// <param name="services">The services collection.</param>
        /// <remarks>
        /// Note: the core services include native support for the non-interactive flows
        /// (resource owner password credentials, client credentials, refresh token).
        /// To support interactive flows like authorization code or implicit/hybrid,
        /// consider adding the MVC module or creating your own authorization controller.
        /// </remarks>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddOpenIddict<TUser, TContext>([NotNull] this IServiceCollection services)
            where TUser : OpenIddictUser
            where TContext : DbContext {
            if (services == null) {
                throw new ArgumentNullException(nameof(services));
            }

            return services.AddOpenIddict<TUser, IdentityRole, OpenIddictApplication,
                                                               OpenIddictAuthorization,
                                                               OpenIddictScope,
                                                               OpenIddictToken, TContext, string>();
        }

        /// <summary>
        /// Registers the default OpenIddict services in the DI container,
        /// including the Entity Framework stores and the specified entities.
        /// </summary>
        /// <typeparam name="TUser">The type of the User entity.</typeparam>
        /// <typeparam name="TRole">The type of the Role entity.</typeparam>
        /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
        /// <param name="services">The services collection.</param>
        /// <remarks>
        /// Note: the core services include native support for the non-interactive flows
        /// (resource owner password credentials, client credentials, refresh token).
        /// To support interactive flows like authorization code or implicit/hybrid,
        /// consider adding the MVC module or creating your own authorization controller.
        /// </remarks>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddOpenIddict<TUser, TRole, TContext>([NotNull] this IServiceCollection services)
            where TUser : OpenIddictUser
            where TRole : IdentityRole
            where TContext : DbContext {
            if (services == null) {
                throw new ArgumentNullException(nameof(services));
            }

            return services.AddOpenIddict<TUser, TRole, OpenIddictApplication,
                                                        OpenIddictAuthorization,
                                                        OpenIddictScope,
                                                        OpenIddictToken, TContext, string>();
        }

        /// <summary>
        /// Registers the default OpenIddict services in the DI container,
        /// including the Entity Framework stores and the specified entities.
        /// </summary>
        /// <typeparam name="TUser">The type of the User entity.</typeparam>
        /// <typeparam name="TRole">The type of the Role entity.</typeparam>
        /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
        /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
        /// <param name="services">The services collection.</param>
        /// <remarks>
        /// Note: the core services include native support for the non-interactive flows
        /// (resource owner password credentials, client credentials, refresh token).
        /// To support interactive flows like authorization code or implicit/hybrid,
        /// consider adding the MVC module or creating your own authorization controller.
        /// </remarks>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddOpenIddict<TUser, TRole, TContext, TKey>([NotNull] this IServiceCollection services)
            where TUser : OpenIddictUser<TKey>
            where TRole : IdentityRole<TKey>
            where TContext : DbContext
            where TKey : IEquatable<TKey> {
            if (services == null) {
                throw new ArgumentNullException(nameof(services));
            }

            return services.AddOpenIddict<TUser, TRole, OpenIddictApplication<TKey>,
                                                        OpenIddictAuthorization<TKey>,
                                                        OpenIddictScope<TKey>,
                                                        OpenIddictToken<TKey>, TContext, TKey>();
        }

        /// <summary>
        /// Registers the default OpenIddict services in the DI container,
        /// including the Entity Framework stores and the specified entities.
        /// </summary>
        /// <typeparam name="TUser">The type of the User entity.</typeparam>
        /// <typeparam name="TRole">The type of the Role entity.</typeparam>
        /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
        /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
        /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
        /// <typeparam name="TToken">The type of the Token entity.</typeparam>
        /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
        /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
        /// <param name="services">The services collection.</param>
        /// <remarks>
        /// Note: the core services include native support for the non-interactive flows
        /// (resource owner password credentials, client credentials, refresh token).
        /// To support interactive flows like authorization code or implicit/hybrid,
        /// consider adding the MVC module or creating your own authorization controller.
        /// </remarks>
        /// <returns>The <see cref="IServiceCollection"/>.</returns>
        public static OpenIddictBuilder AddOpenIddict<TUser, TRole, TApplication, TAuthorization, TScope, TToken, TContext, TKey>(
            [NotNull] this IServiceCollection services)
            where TUser : OpenIddictUser<TKey, TAuthorization, TToken>
            where TRole : IdentityRole<TKey>
            where TApplication : OpenIddictApplication<TKey, TToken>
            where TAuthorization : OpenIddictAuthorization<TKey, TToken>
            where TScope : OpenIddictScope<TKey>
            where TToken : OpenIddictToken<TKey>
            where TContext : DbContext
            where TKey : IEquatable<TKey> {
            if (services == null) {
                throw new ArgumentNullException(nameof(services));
            }

            // Register the OpenIddict core services and the default EntityFramework stores.
            return services.AddOpenIddict<TUser, TRole, TApplication, TAuthorization, TScope, TToken>()
                           .AddEntityFramework<TContext, TKey>();
        }
    }
}