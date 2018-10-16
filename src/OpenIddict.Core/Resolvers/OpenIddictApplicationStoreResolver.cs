using System;
using System.Text;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace OpenIddict.Core
{
    /// <summary>
    /// Exposes a method allowing to resolve an application store.
    /// </summary>
    public class OpenIddictApplicationStoreResolver : IOpenIddictApplicationStoreResolver
    {
        private readonly IServiceProvider _provider;

        public OpenIddictApplicationStoreResolver([NotNull] IServiceProvider provider)
            => _provider = provider;

        /// <summary>
        /// Returns an application store compatible with the specified application type or throws an
        /// <see cref="InvalidOperationException"/> if no store can be built using the specified type.
        /// </summary>
        /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
        /// <returns>An <see cref="IOpenIddictApplicationStore{TApplication}"/>.</returns>
        public IOpenIddictApplicationStore<TApplication> Get<TApplication>() where TApplication : class
        {
            var store = _provider.GetService<IOpenIddictApplicationStore<TApplication>>();
            if (store == null)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("No application store has been registered in the dependency injection container.")
                    .Append("To register the Entity Framework Core stores, reference the 'OpenIddict.EntityFrameworkCore' ")
                    .AppendLine("package and call 'services.AddOpenIddict().AddCore().UseEntityFrameworkCore()'.")
                    .Append("To register a custom store, create an implementation of 'IOpenIddictApplicationStore' and ")
                    .Append("use 'services.AddOpenIddict().AddCore().AddApplicationStore()' to add it to the DI container.")
                    .ToString());
            }

            return store;
        }
    }
}
