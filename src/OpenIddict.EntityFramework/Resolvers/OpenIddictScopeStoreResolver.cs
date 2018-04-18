using System;
using System.Collections.Concurrent;
using System.Data.Entity;
using System.Text;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.Models;

namespace OpenIddict.EntityFramework
{
    /// <summary>
    /// Exposes a method allowing to resolve a scope store.
    /// </summary>
    public class OpenIddictScopeStoreResolver<TContext> : IOpenIddictScopeStoreResolver
        where TContext : DbContext
    {
        private static readonly ConcurrentDictionary<Type, Type> _cache = new ConcurrentDictionary<Type, Type>();
        private readonly IServiceProvider _provider;

        public OpenIddictScopeStoreResolver([NotNull] IServiceProvider provider)
        {
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
                var root = OpenIddictCoreHelpers.FindGenericBaseType(key, typeof(OpenIddictScope<>));
                if (root == null)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The specified scope type is not compatible with the Entity Framework 6.x stores.")
                        .Append("When enabling the Entity Framework 6.x stores, make sure you use the built-in generic ")
                        .Append("'OpenIdScope' entity (from the 'OpenIddict.Models' package) or a custom entity ")
                        .Append("that inherits from the generic 'OpenIddictScope' entity.")
                        .ToString());
                }

                return typeof(OpenIddictScopeStore<,,>).MakeGenericType(
                    /* TScope: */ key,
                    /* TContext: */ typeof(TContext),
                    /* TKey: */ root.GenericTypeArguments[0]);
            });

            return (IOpenIddictScopeStore<TScope>) _provider.GetRequiredService(type);
        }
    }
}
