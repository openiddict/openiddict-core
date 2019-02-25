/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes extensions allowing to register the OpenIddict Entity Framework Core services.
    /// </summary>
    public static class OpenIddictEntityFrameworkCoreExtensions
    {
        /// <summary>
        /// Registers the Entity Framework Core stores services in the DI container and
        /// configures OpenIddict to use the Entity Framework Core entities by default.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictEntityFrameworkCoreBuilder"/>.</returns>
        public static OpenIddictEntityFrameworkCoreBuilder UseEntityFrameworkCore([NotNull] this OpenIddictCoreBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            // Since Entity Framework Core may be used with databases performing case-insensitive
            // or culture-sensitive comparisons, ensure the additional filtering logic is enforced
            // in case case-sensitive stores were registered before this extension was called.
            builder.Configure(options => options.DisableAdditionalFiltering = false);

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

            return new OpenIddictEntityFrameworkCoreBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the Entity Framework Core stores services in the DI container and
        /// configures OpenIddict to use the Entity Framework Core entities by default.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the Entity Framework Core services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public static OpenIddictCoreBuilder UseEntityFrameworkCore(
            [NotNull] this OpenIddictCoreBuilder builder,
            [NotNull] Action<OpenIddictEntityFrameworkCoreBuilder> configuration)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            configuration(builder.UseEntityFrameworkCore());

            return builder;
        }
    }
}