/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Data.Entity;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.EntityFramework;
using OpenIddict.EntityFramework.Models;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes extensions allowing to register the OpenIddict Entity Framework 6.x services.
    /// </summary>
    public static class OpenIddictEntityFrameworkExtensions
    {
        /// <summary>
        /// Registers the Entity Framework 6.x stores services in the DI container and
        /// configures OpenIddict to use the Entity Framework 6.x entities by default.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictEntityFrameworkBuilder"/>.</returns>
        public static OpenIddictEntityFrameworkBuilder UseEntityFramework([NotNull] this OpenIddictCoreBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.AddMemoryCache();

            builder.SetDefaultApplicationEntity<OpenIddictApplication>()
                   .SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                   .SetDefaultScopeEntity<OpenIddictScope>()
                   .SetDefaultTokenEntity<OpenIddictToken>();

            builder.ReplaceApplicationStoreResolver<OpenIddictApplicationStoreResolver>()
                   .ReplaceAuthorizationStoreResolver<OpenIddictAuthorizationStoreResolver>()
                   .ReplaceScopeStoreResolver<OpenIddictScopeStoreResolver>()
                   .ReplaceTokenStoreResolver<OpenIddictTokenStoreResolver>();

            builder.Services.TryAddScoped(typeof(OpenIddictApplicationStore<,,,,>));
            builder.Services.TryAddScoped(typeof(OpenIddictAuthorizationStore<,,,,>));
            builder.Services.TryAddScoped(typeof(OpenIddictScopeStore<,,>));
            builder.Services.TryAddScoped(typeof(OpenIddictTokenStore<,,,,>));

            return new OpenIddictEntityFrameworkBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the Entity Framework 6.x stores services in the DI container and
        /// configures OpenIddict to use the Entity Framework 6.x entities by default.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the Entity Framework 6.x services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public static OpenIddictCoreBuilder UseEntityFramework(
            [NotNull] this OpenIddictCoreBuilder builder,
            [NotNull] Action<OpenIddictEntityFrameworkBuilder> configuration)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            configuration(builder.UseEntityFramework());

            return builder;
        }

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

            builder.Configurations.Add(new OpenIddictApplicationConfiguration<TApplication, TAuthorization, TToken, TKey>());
            builder.Configurations.Add(new OpenIddictAuthorizationConfiguration<TAuthorization, TApplication, TToken, TKey>());
            builder.Configurations.Add(new OpenIddictScopeConfiguration<TScope, TKey>());
            builder.Configurations.Add(new OpenIddictTokenConfiguration<TToken, TApplication, TAuthorization, TKey>());

            return builder;
        }
    }
}