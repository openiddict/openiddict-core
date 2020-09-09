/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.EntityFramework.Models;
using OpenIddict.Extensions;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.EntityFramework
{
    /// <summary>
    /// Exposes a method allowing to resolve a token store.
    /// </summary>
    public class OpenIddictEntityFrameworkTokenStoreResolver : IOpenIddictTokenStoreResolver
    {
        private readonly TypeResolutionCache _cache;
        private readonly IOptionsMonitor<OpenIddictEntityFrameworkOptions> _options;
        private readonly IServiceProvider _provider;

        public OpenIddictEntityFrameworkTokenStoreResolver(
            TypeResolutionCache cache,
            IOptionsMonitor<OpenIddictEntityFrameworkOptions> options,
            IServiceProvider provider)
        {
            _cache = cache;
            _options = options;
            _provider = provider;
        }

        /// <summary>
        /// Returns a token store compatible with the specified token type or throws an
        /// <see cref="InvalidOperationException"/> if no store can be built using the specified type.
        /// </summary>
        /// <typeparam name="TToken">The type of the Token entity.</typeparam>
        /// <returns>An <see cref="IOpenIddictTokenStore{TToken}"/>.</returns>
        public IOpenIddictTokenStore<TToken> Get<TToken>() where TToken : class
        {
            var store = _provider.GetService<IOpenIddictTokenStore<TToken>>();
            if (store is not null)
            {
                return store;
            }

            var type = _cache.GetOrAdd(typeof(TToken), key =>
            {
                var root = OpenIddictHelpers.FindGenericBaseType(key, typeof(OpenIddictEntityFrameworkToken<,,>));
                if (root is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1237));
                }

                var context = _options.CurrentValue.DbContextType;
                if (context is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1234));
                }

                return typeof(OpenIddictEntityFrameworkTokenStore<,,,,>).MakeGenericType(
                    /* TToken: */ key,
                    /* TApplication: */ root.GenericTypeArguments[1],
                    /* TAuthorization: */ root.GenericTypeArguments[2],
                    /* TContext: */ context,
                    /* TKey: */ root.GenericTypeArguments[0]);
            });

            return (IOpenIddictTokenStore<TToken>) _provider.GetRequiredService(type);
        }

        // Note: Entity Framework resolvers are registered as scoped dependencies as their inner
        // service provider must be able to resolve scoped services (typically, the store they return).
        // To avoid having to declare a static type resolution cache, a special cache service is used
        // here and registered as a singleton dependency so that its content persists beyond the scope.
        public class TypeResolutionCache : ConcurrentDictionary<Type, Type> { }
    }
}
