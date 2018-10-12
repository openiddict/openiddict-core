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
    /// Exposes a method allowing to resolve an authorization store.
    /// </summary>
    public class OpenIddictAuthorizationStoreResolver : IOpenIddictAuthorizationStoreResolver
    {
        private readonly IServiceProvider _provider;

        public OpenIddictAuthorizationStoreResolver([NotNull] IServiceProvider provider)
            => _provider = provider;

        /// <summary>
        /// Returns an authorization store compatible with the specified authorization type or throws an
        /// <see cref="InvalidOperationException"/> if no store can be built using the specified type.
        /// </summary>
        /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
        /// <returns>An <see cref="IOpenIddictAuthorizationStore{TAuthorization}"/>.</returns>
        public IOpenIddictAuthorizationStore<TAuthorization> Get<TAuthorization>() where TAuthorization : class
        {
            var store = _provider.GetService<IOpenIddictAuthorizationStore<TAuthorization>>();
            if (store != null)
            {
                return store;
            }

            if (!typeof(OpenIddictAuthorization).IsAssignableFrom(typeof(TAuthorization)))
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The specified authorization type is not compatible with the MongoDB stores.")
                    .Append("When enabling the MongoDB stores, make sure you use the built-in 'OpenIddictAuthorization' ")
                    .Append("entity (from the 'OpenIddict.MongoDb.Models' package) or a custom entity ")
                    .Append("that inherits from the 'OpenIddictAuthorization' entity.")
                    .ToString());
            }

            return (IOpenIddictAuthorizationStore<TAuthorization>) _provider.GetRequiredService(
                typeof(OpenIddictAuthorizationStore<>).MakeGenericType(typeof(TAuthorization)));
        }
    }
}
