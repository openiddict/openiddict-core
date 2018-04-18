/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using OpenIddict.Models;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class OpenIddictExtensions
    {
        /// <summary>
        /// Configures OpenIddict to use the default entities, with the default entity key type (string).
        /// The default entities are <see cref="OpenIddictApplication"/>, <see cref="OpenIddictAuthorization"/>,
        /// <see cref="OpenIddictScope"/> and <see cref="OpenIddictToken"/>.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public static OpenIddictCoreBuilder UseDefaultModels([NotNull] this OpenIddictCoreBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.UseCustomModels<OpenIddictApplication,
                                           OpenIddictAuthorization,
                                           OpenIddictScope,
                                           OpenIddictToken>();
        }

        /// <summary>
        /// Configures OpenIddict to use the default entities, with the specified entity key type.
        /// The default entities are <see cref="OpenIddictApplication{TKey}"/>, <see cref="OpenIddictAuthorization{TKey}"/>,
        /// <see cref="OpenIddictScope{TKey}"/> and <see cref="OpenIddictToken{TKey}"/>.
        /// </summary>
        /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
        /// <param name="builder">The services builder used by OpenIddict to register new services</param>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public static OpenIddictCoreBuilder UseDefaultModels<TKey>([NotNull] this OpenIddictCoreBuilder builder)
            where TKey : IEquatable<TKey>
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.UseCustomModels<OpenIddictApplication<TKey>,
                                           OpenIddictAuthorization<TKey>,
                                           OpenIddictScope<TKey>,
                                           OpenIddictToken<TKey>>();
        }
    }
}
