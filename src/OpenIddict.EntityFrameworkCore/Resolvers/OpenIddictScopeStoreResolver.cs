/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Concurrent;
using System.Text;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict.Extensions;

namespace OpenIddict.EntityFrameworkCore
{
    /// <summary>
    /// Exposes a method allowing to resolve a scope store.
    /// </summary>
    public class OpenIddictScopeStoreResolver : IOpenIddictScopeStoreResolver
    {
        private readonly TypeResolutionCache _cache;
        private readonly IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> _options;
        private readonly IServiceProvider _provider;

        public OpenIddictScopeStoreResolver(
            [NotNull] TypeResolutionCache cache,
            [NotNull] IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options,
            [NotNull] IServiceProvider provider)
        {
            _cache = cache;
            _options = options;
            _provider = provider;
        }

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
                var root = OpenIddictHelpers.FindGenericBaseType(key, typeof(OpenIddictScope<>));
                if (root == null)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The specified scope type is not compatible with the Entity Framework Core stores.")
                        .Append("When enabling the Entity Framework Core stores, make sure you use the built-in ")
                        .Append("'OpenIddictScope' entity (from the 'OpenIddict.EntityFrameworkCore.Models' package) ")
                        .Append("or a custom entity that inherits from the generic 'OpenIddictScope' entity.")
                        .ToString());
                }

                var context = _options.CurrentValue.DbContextType;
                if (context == null)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("No Entity Framework Core context was specified in the OpenIddict options.")
                        .Append("To configure the OpenIddict Entity Framework Core stores to use a specific 'DbContext', ")
                        .Append("use 'options.UseEntityFrameworkCore().UseDbContext<TContext>()'.")
                        .ToString());
                }

                return typeof(OpenIddictScopeStore<,,>).MakeGenericType(
                    /* TScope: */ key,
                    /* TContext: */ context,
                    /* TKey: */ root.GenericTypeArguments[0]);
            });

            return (IOpenIddictScopeStore<TScope>) _provider.GetRequiredService(type);
        }

        // Note: Entity Framework Core resolvers are registered as scoped dependencies as their inner
        // service provider must be able to resolve scoped services (typically, the store they return).
        // To avoid having to declare a static type resolution cache, a special cache service is used
        // here and registered as a singleton dependency so that its content persists beyond the scope.
        public class TypeResolutionCache : ConcurrentDictionary<Type, Type> { }
    }
}
