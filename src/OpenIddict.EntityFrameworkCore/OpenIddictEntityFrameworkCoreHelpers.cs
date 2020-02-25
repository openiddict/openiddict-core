/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore.Infrastructure;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace Microsoft.EntityFrameworkCore
{
    /// <summary>
    /// Exposes extensions simplifying the integration between OpenIddict and Entity Framework Core.
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
            => builder.UseOpenIddict<OpenIddictEntityFrameworkCoreApplication,
                                     OpenIddictEntityFrameworkCoreAuthorization,
                                     OpenIddictEntityFrameworkCoreScope,
                                     OpenIddictEntityFrameworkCoreToken, string>();

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework Core 
        /// context using the default OpenIddict models and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbContextOptionsBuilder UseOpenIddict<TKey>([NotNull] this DbContextOptionsBuilder builder)
            where TKey : IEquatable<TKey>
            => builder.UseOpenIddict<OpenIddictEntityFrameworkCoreApplication<TKey>,
                                     OpenIddictEntityFrameworkCoreAuthorization<TKey>,
                                     OpenIddictEntityFrameworkCoreScope<TKey>,
                                     OpenIddictEntityFrameworkCoreToken<TKey>, TKey>();

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework Core
        /// context using the specified entities and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbContextOptionsBuilder UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>([NotNull] this DbContextOptionsBuilder builder)
            where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TToken>
            where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TToken>
            where TScope : OpenIddictEntityFrameworkCoreScope<TKey>
            where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
            where TKey : IEquatable<TKey>
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.ReplaceService<IModelCustomizer, OpenIddictEntityFrameworkCoreCustomizer<
                TApplication, TAuthorization, TScope, TToken, TKey>>();
        }

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework Core context
        /// using the default OpenIddict models and the default key type (string).
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static ModelBuilder UseOpenIddict([NotNull] this ModelBuilder builder)
            => builder.UseOpenIddict<OpenIddictEntityFrameworkCoreApplication,
                                     OpenIddictEntityFrameworkCoreAuthorization,
                                     OpenIddictEntityFrameworkCoreScope,
                                     OpenIddictEntityFrameworkCoreToken, string>();

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework Core
        /// context using the default OpenIddict models and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static ModelBuilder UseOpenIddict<TKey>([NotNull] this ModelBuilder builder) where TKey : IEquatable<TKey>
            => builder.UseOpenIddict<OpenIddictEntityFrameworkCoreApplication<TKey>,
                                     OpenIddictEntityFrameworkCoreAuthorization<TKey>,
                                     OpenIddictEntityFrameworkCoreScope<TKey>,
                                     OpenIddictEntityFrameworkCoreToken<TKey>, TKey>();

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework Core
        /// context using the specified entities and the specified key type.
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static ModelBuilder UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>([NotNull] this ModelBuilder builder)
            where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TToken>
            where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TToken>
            where TScope : OpenIddictEntityFrameworkCoreScope<TKey>
            where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
            where TKey : IEquatable<TKey>
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder
                .ApplyConfiguration(new OpenIddictEntityFrameworkCoreApplicationConfiguration<TApplication, TAuthorization, TToken, TKey>())
                .ApplyConfiguration(new OpenIddictEntityFrameworkCoreAuthorizationConfiguration<TAuthorization, TApplication, TToken, TKey>())
                .ApplyConfiguration(new OpenIddictEntityFrameworkCoreScopeConfiguration<TScope, TKey>())
                .ApplyConfiguration(new OpenIddictEntityFrameworkCoreTokenConfiguration<TToken, TApplication, TAuthorization, TKey>());
        }

#if !SUPPORTS_BCL_ASYNC_ENUMERABLE
        /// <summary>
        /// Executes the query and returns the results as a non-streamed async enumeration.
        /// </summary>
        /// <typeparam name="T">The type of the returned entities.</typeparam>
        /// <param name="source">The query source.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>The non-streamed async enumeration containing the results.</returns>
        internal static IAsyncEnumerable<T> AsAsyncEnumerable<T>(
            [NotNull] this IQueryable<T> source, CancellationToken cancellationToken = default)
        {
            if (source == null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<T> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                foreach (var element in await source.ToListAsync(cancellationToken))
                {
                    yield return element;
                }
            }
        }
#endif
    }
}