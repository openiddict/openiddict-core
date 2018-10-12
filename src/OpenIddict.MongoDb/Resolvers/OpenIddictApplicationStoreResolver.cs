/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.MongoDb.Models;

namespace OpenIddict.MongoDb
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
            if (store != null)
            {
                return store;
            }

            if (!typeof(OpenIddictApplication).IsAssignableFrom(typeof(TApplication)))
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The specified application type is not compatible with the MongoDB stores.")
                    .Append("When enabling the MongoDB stores, make sure you use the built-in 'OpenIddictApplication' ")
                    .Append("entity (from the 'OpenIddict.MongoDb.Models' package) or a custom entity ")
                    .Append("that inherits from the 'OpenIddictApplication' entity.")
                    .ToString());
            }

            return (IOpenIddictApplicationStore<TApplication>) _provider.GetRequiredService(
                typeof(OpenIddictApplicationStore<>).MakeGenericType(typeof(TApplication)));
        }
    }
}
