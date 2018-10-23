/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using JetBrains.Annotations;
using OpenIddict.EntityFramework;
using OpenIddict.EntityFramework.Models;

namespace System.Data.Entity
{
    /// <summary>
    /// Exposes extensions allowing to register the OpenIddict Entity Framework 6.x entity sets.
    /// </summary>
    public static class OpenIddictEntityFrameworkHelpers
    {
        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework 6.x context
        /// using the default OpenIddict models and the default key type (string).
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbModelBuilder UseOpenIddict([NotNull] this DbModelBuilder builder)
            => builder.UseOpenIddict<OpenIddictApplication,
                                     OpenIddictAuthorization,
                                     OpenIddictScope,
                                     OpenIddictToken, string>();

        /// <summary>
        /// Registers the OpenIddict entity sets in the Entity Framework 6.x
        /// context using the specified entities and the specified key type.
        /// Note: using this method requires creating non-generic derived classes
        /// for all the OpenIddict entities (application, authorization, scope, token).
        /// </summary>
        /// <param name="builder">The builder used to configure the Entity Framework context.</param>
        /// <returns>The Entity Framework context builder.</returns>
        public static DbModelBuilder UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>([NotNull] this DbModelBuilder builder)
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

            builder.Configurations
                .Add(new OpenIddictApplicationConfiguration<TApplication, TAuthorization, TToken, TKey>())
                .Add(new OpenIddictAuthorizationConfiguration<TAuthorization, TApplication, TToken, TKey>())
                .Add(new OpenIddictScopeConfiguration<TScope, TKey>())
                .Add(new OpenIddictTokenConfiguration<TToken, TApplication, TAuthorization, TKey>());

            return builder;
        }
    }
}