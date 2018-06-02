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
using OpenIddict.Core;
using OpenIddict.EntityFramework.Models;

namespace OpenIddict.EntityFramework
{
    /// <summary>
    /// Exposes a method allowing to resolve a scope store.
    /// </summary>
    public class OpenIddictScopeStoreResolver : IOpenIddictScopeStoreResolver
    {
        private static readonly ConcurrentDictionary<Type, Type> _cache = new ConcurrentDictionary<Type, Type>();
        private readonly IOptionsMonitor<OpenIddictEntityFrameworkOptions> _options;
        private readonly IServiceProvider _provider;

        public OpenIddictScopeStoreResolver(
            [NotNull] IOptionsMonitor<OpenIddictEntityFrameworkOptions> options,
            [NotNull] IServiceProvider provider)
        {
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
                var root = OpenIddictCoreHelpers.FindGenericBaseType(key, typeof(OpenIddictScope<>));
                if (root == null)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The specified scope type is not compatible with the Entity Framework 6.x stores.")
                        .Append("When enabling the Entity Framework 6.x stores, make sure you use the built-in ")
                        .Append("'OpenIdScope' entity (from the 'OpenIddict.EntityFramework.Models' package) ")
                        .Append("or a custom entity that inherits from the generic 'OpenIddictScope' entity.")
                        .ToString());
                }

                var context = _options.CurrentValue.DbContextType;
                if (context == null)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("No Entity Framework 6.x context was specified in the OpenIddict options.")
                        .Append("To configure the OpenIddict Entity Framework 6.x stores to use a specific 'DbContext', ")
                        .Append("use 'options.UseEntityFramework().UseDbContext<TContext>()'.")
                        .ToString());
                }

                return typeof(OpenIddictScopeStore<,,>).MakeGenericType(
                    /* TScope: */ key,
                    /* TContext: */ context,
                    /* TKey: */ root.GenericTypeArguments[0]);
            });

            return (IOpenIddictScopeStore<TScope>) _provider.GetRequiredService(type);
        }
    }
}
