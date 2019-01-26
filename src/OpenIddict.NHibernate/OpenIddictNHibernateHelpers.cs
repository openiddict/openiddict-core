/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using NHibernate.Mapping.ByCode;
using OpenIddict.NHibernate;
using OpenIddict.NHibernate.Models;

namespace NHibernate.Cfg
{
    /// <summary>
    /// Exposes extensions allowing to register the OpenIddict NHibernate mappings.
    /// </summary>
    public static class OpenIddictNHibernateHelpers
    {
        /// <summary>
        /// Registers the OpenIddict entity mappings in the NHibernate
        /// configuration using the default entities and the default key type.
        /// </summary>
        /// <param name="configuration">The NHibernate configuration builder.</param>
        /// <returns>The <see cref="Configuration"/>.</returns>
        public static Configuration UseOpenIddict([NotNull] this Configuration configuration)
            => configuration.UseOpenIddict<OpenIddictApplication,
                                           OpenIddictAuthorization,
                                           OpenIddictScope,
                                           OpenIddictToken, string>();

        /// <summary>
        /// Registers the OpenIddict entity mappings in the NHibernate
        /// configuration using the default entities and the specified key type.
        /// </summary>
        /// <param name="configuration">The NHibernate configuration builder.</param>
        /// <returns>The <see cref="Configuration"/>.</returns>
        public static Configuration UseOpenIddict<TKey>([NotNull] this Configuration configuration)
            where TKey : IEquatable<TKey>
            => configuration.UseOpenIddict<OpenIddictApplication<TKey>,
                                           OpenIddictAuthorization<TKey>,
                                           OpenIddictScope<TKey>,
                                           OpenIddictToken<TKey>, TKey>();

        /// <summary>
        /// Registers the OpenIddict entity mappings in the NHibernate
        /// configuration using the specified entities and the specified key type.
        /// </summary>
        /// <param name="configuration">The NHibernate configuration builder.</param>
        /// <returns>The <see cref="Configuration"/>.</returns>
        public static Configuration UseOpenIddict<TApplication, TAuthorization, TScope, TToken, TKey>([NotNull] this Configuration configuration)
            where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>
            where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>
            where TScope : OpenIddictScope<TKey>
            where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>
            where TKey : IEquatable<TKey>
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            var mapper = new ModelMapper();
            mapper.AddMapping<OpenIddictApplicationMapping<TApplication, TAuthorization, TToken, TKey>>();
            mapper.AddMapping<OpenIddictAuthorizationMapping<TAuthorization, TApplication, TToken, TKey>>();
            mapper.AddMapping<OpenIddictScopeMapping<TScope, TKey>>();
            mapper.AddMapping<OpenIddictTokenMapping<TToken, TApplication, TAuthorization, TKey>>();

            configuration.AddMapping(mapper.CompileMappingForAllExplicitlyAddedEntities());

            return configuration;
        }
    }
}
