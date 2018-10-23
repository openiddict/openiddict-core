/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore.Infrastructure;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace Microsoft.EntityFrameworkCore
{
    /// <summary>
    /// Exposes extensions allowing to register the OpenIddict Entity Framework Core entity sets.
    /// </summary>
    public static class OpenIddictEntityFrameworkCoreHelpers
    {
        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework Core context
        /// using the default OpenIddict models and the default key type (string).
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbContextOptionsBuilder UseOpenIddict([NotNull] this DbContextOptionsBuilder builder)
            => builder.UseOpenIddict<OpenIddictApplication,
                                     OpenIddictAuthorization,
                                     OpenIddictScope,
                                     OpenIddictToken, string>();

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework Core 
        /// context using the default OpenIddict models and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbContextOptionsBuilder UseOpenIddict<TKey>([NotNull] this DbContextOptionsBuilder builder)
            where TKey : IEquatable<TKey>
            => builder.UseOpenIddict<OpenIddictApplication<TKey>,
                                     OpenIddictAuthorization<TKey>,
                                     OpenIddictScope<TKey>,
                                     OpenIddictToken<TKey>, TKey>();

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework Core
        /// context using the specified entities and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbContextOptionsBuilder UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>([NotNull] this DbContextOptionsBuilder builder)
            where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>
            where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>
            where TScope : OpenIddictScope<TKey>
            where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>
            where TKey : IEquatable<TKey>
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            var extension = new OpenIddictEntityFrameworkCoreExtension<TApplication, TAuthorization, TScope, TToken, TKey>();
            ((IDbContextOptionsBuilderInfrastructure) builder).AddOrUpdateExtension(extension);

            return builder;
        }

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework Core context
        /// using the default OpenIddict models and the default key type (string).
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static ModelBuilder UseOpenIddict([NotNull] this ModelBuilder builder)
            => builder.UseOpenIddict<OpenIddictApplication,
                                     OpenIddictAuthorization,
                                     OpenIddictScope,
                                     OpenIddictToken, string>();

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework Core
        /// context using the default OpenIddict models and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static ModelBuilder UseOpenIddict<TKey>([NotNull] this ModelBuilder builder) where TKey : IEquatable<TKey>
            => builder.UseOpenIddict<OpenIddictApplication<TKey>,
                                     OpenIddictAuthorization<TKey>,
                                     OpenIddictScope<TKey>,
                                     OpenIddictToken<TKey>, TKey>();

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework Core
        /// context using the specified entities and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static ModelBuilder UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>([NotNull] this ModelBuilder builder)
            where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>
            where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>
            where TScope : OpenIddictScope<TKey>
            where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>
            where TKey : IEquatable<TKey>
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            new OpenIddictApplicationConfiguration<TApplication, TAuthorization, TToken, TKey>()
                .Configure(builder.Entity<TApplication>());
            new OpenIddictAuthorizationConfiguration<TAuthorization, TApplication, TToken, TKey>()
                .Configure(builder.Entity<TAuthorization>());
            new OpenIddictScopeConfiguration<TScope, TKey>()
                .Configure(builder.Entity<TScope>());
            new OpenIddictTokenConfiguration<TToken, TApplication, TAuthorization, TKey>()
                .Configure(builder.Entity<TToken>());

            return builder;
        }
    }
}