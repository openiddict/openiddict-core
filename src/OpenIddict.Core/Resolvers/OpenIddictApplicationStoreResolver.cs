using System;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using SR = OpenIddict.Abstractions.OpenIddictResources;

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
            => _provider.GetService<IOpenIddictApplicationStore<TApplication>>() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1227));
    }
}
