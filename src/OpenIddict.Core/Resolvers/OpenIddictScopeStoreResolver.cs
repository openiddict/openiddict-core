using System;
using System.Text;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace OpenIddict.Core
{
    /// <summary>
    /// Exposes a method allowing to resolve a scope store.
    /// </summary>
    public class OpenIddictScopeStoreResolver : IOpenIddictScopeStoreResolver
    {
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
            if (store == null)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("No scope store has been registered in the dependency injection container.")
                    .Append("To register the Entity Framework Core stores, reference the 'OpenIddict.EntityFrameworkCore' ")
                    .AppendLine("package and call 'services.AddOpenIddict().AddCore().AddEntityFrameworkCoreStores()'.")
                    .Append("To register a custom store, create an implementation of 'IOpenIddictScopeStore' and ")
                    .Append("use 'services.AddOpenIddict().AddCore().AddScopeStore()' to add it to the DI container.")
                    .ToString());
            }

            return store;
        }
    }
}
