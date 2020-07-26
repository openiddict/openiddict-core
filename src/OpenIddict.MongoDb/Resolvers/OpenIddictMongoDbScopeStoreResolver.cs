/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.MongoDb.Models;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.MongoDb
{
    /// <summary>
    /// Exposes a method allowing to resolve a scope store.
    /// </summary>
    public class OpenIddictMongoDbScopeStoreResolver : IOpenIddictScopeStoreResolver
    {
        private readonly ConcurrentDictionary<Type, Type> _cache = new ConcurrentDictionary<Type, Type>();
        private readonly IServiceProvider _provider;

        public OpenIddictMongoDbScopeStoreResolver(IServiceProvider provider)
            => _provider = provider;

        /// <summary>
        /// Returns a scope store compatible with the specified scope type or throws an
        /// <see cref="InvalidOperationException"/> if no store can be built using the specified type.
        /// </summary>
        /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
        /// <returns>An <see cref="IOpenIddictScopeStore{TScope}"/>.</returns>
        public IOpenIddictScopeStore<TScope> Get<TScope>() where TScope : class
        {
            var store = _provider.GetService<IOpenIddictScopeStore<TScope>>();
            if (store != null)
            {
                return store;
            }

            var type = _cache.GetOrAdd(typeof(TScope), key =>
            {
                if (!typeof(OpenIddictMongoDbScope).IsAssignableFrom(key))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1258));
                }

                return typeof(OpenIddictMongoDbScopeStore<>).MakeGenericType(key);
            });

            return (IOpenIddictScopeStore<TScope>) _provider.GetRequiredService(type);
        }
    }
}
