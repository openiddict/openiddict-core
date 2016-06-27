/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace OpenIddict {
    /// <summary>
    /// Creates a new instance of a persistence store for the specified client application and authorization token types.
    /// </summary>
    /// <typeparam name="TApplication">The type representing an application.</typeparam>
    /// <typeparam name="TToken">The type representing a token.</typeparam>
    /// <typeparam name="TContext">The type of the data context class used to access the store.</typeparam>
    /// <typeparam name="TKey">The type of the primary key for an application and a token.</typeparam>
    public class OpenIddictApplicationStore<TApplication, TToken, TContext, TKey> : IOpenIddictApplicationStore<TApplication>
        where TApplication : OpenIddictApplication<TKey, TToken>
        where TToken : OpenIddictToken<TKey>, new()
        where TContext : DbContext
        where TKey : IEquatable<TKey> {
        public OpenIddictApplicationStore(TContext context) {
            Context = context;
        }

        /// <summary>
        /// Gets the database context for this store.
        /// </summary>
        protected virtual TContext Context { get; }

        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="TApplication"/> entity.
        /// </summary>
        protected DbSet<TApplication> Applications => Context.Set<TApplication>();


        /// <summary>
        /// Creates a new application.
        /// </summary>
        /// <param name="application">The application to create.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the application.
        /// </returns>
        /// <exception cref="System.ArgumentNullException"></exception> // TODO: Add reason
        /// <exception cref="System.InvalidOperationException"></exception> // TODO: Add reason
        public virtual async Task<string> CreateAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            // Ensure that the key type can be serialized.
            var converter = TypeDescriptor.GetConverter(typeof(TKey));
            if (!converter.CanConvertTo(typeof(string))) {
                throw new InvalidOperationException($"The '{typeof(TKey).Name}' key type is not supported.");
            }

            Context.Add(application);

            await Context.SaveChangesAsync(cancellationToken);

            return converter.ConvertToInvariantString(application.Id);
        }

        /// <summary>
        /// Finds and returns an application, if any, which has the specified <paramref name="id" />.
        /// </summary>
        /// <param name="id">The identifier of application entity to search for.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> that can be used to monitor the asynchronous operation,
        /// whose result returns the client application corresponding to the identifier.
        /// </returns>
        public virtual Task<TApplication> FindByIdAsync(string id, CancellationToken cancellationToken) {
            var converter = TypeDescriptor.GetConverter(typeof(TKey));

            // If the string key cannot be converted to TKey, return null
            // to indicate that the requested application doesn't exist.
            if (!converter.CanConvertFrom(typeof(string))) {
                return Task.FromResult<TApplication>(null);
            }

            var key = (TKey) converter.ConvertFromInvariantString(id);

            return Applications.SingleOrDefaultAsync(application => application.Id.Equals(key), cancellationToken);
        }


        /// <summary>
        /// Finds and returns an application, if any, which has the specified client_id.
        /// </summary>
        /// <param name="clientId">The identifier of client application to search for.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> that can be used to monitor the asynchronous operation,
        /// whose result returns the client application corresponding to the identifier.
        /// </returns>
        public virtual Task<TApplication> FindByClientIdAsync(string clientId, CancellationToken cancellationToken) {
            return Applications.SingleOrDefaultAsync(application => application.ClientId.Equals(clientId), cancellationToken);
        }



        /// <summary>
        /// Finds and returns an application, if any, which has the specified post_logout_redirect_uri.
        /// </summary>
        /// <param name="url">The post logout redirect URI of application to search for.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> that can be used to monitor the asynchronous operation, whose result
        /// returns the client application corresponding to the post logout redirect URI.
        /// </returns>
        public virtual Task<TApplication> FindByLogoutRedirectUri(string url, CancellationToken cancellationToken) {
            return Applications.SingleOrDefaultAsync(application => application.LogoutRedirectUri == url, cancellationToken);
        }

        /// <summary>
        /// Retrieves the client type associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> that can be used to monitor the asynchronous operation,
        /// whose result returns the client type of the application (by default, "public").
        /// </returns>
        /// <exception cref="System.ArgumentNullException"></exception>
        public virtual Task<string> GetClientTypeAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Task.FromResult(application.Type);
        }

        /// <summary>
        /// Retrieves the display name associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> that can be used to monitor the asynchronous operation,
        /// whose result returns the display name associated with the application.
        /// </returns>
        /// <exception cref="System.ArgumentNullException"></exception> // TODO: Add reason
        public virtual Task<string> GetDisplayNameAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Task.FromResult(application.DisplayName);
        }

        /// <summary>
        /// Retrieves the hashed secret associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> that can be used to monitor the asynchronous operation,
        /// whose result returns the hashed secret associated with the application.
        /// </returns>
        /// <exception cref="System.ArgumentNullException"></exception> // TODO: Add reason
        public virtual Task<string> GetHashedSecretAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Task.FromResult(application.ClientSecret);
        }

        /// <summary>
        /// Retrieves the callback address associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> that can be used to monitor the asynchronous operation,
        /// whose result returns the redirect_uri associated with the application.
        /// </returns>
        /// <exception cref="System.ArgumentNullException"></exception> // TODO: Add reason
        public virtual Task<string> GetRedirectUriAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Task.FromResult(application.RedirectUri);
        }

        /// <summary>
        /// Retrieves the token identifiers associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens associated with the application.
        /// </returns>
        /// <exception cref="System.ArgumentNullException"></exception> // TODO: Add reason
        /// <exception cref="System.InvalidOperationException"></exception> // TODO: Add reason
        public virtual async Task<IEnumerable<string>> GetTokensAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            // Ensure that the key type can be serialized.
            var converter = TypeDescriptor.GetConverter(typeof(TKey));
            if (!converter.CanConvertTo(typeof(string))) {
                throw new InvalidOperationException($"The '{typeof(TKey).Name}' key type is not supported.");
            }

            var query = from entity in Applications
                        where entity.Id.Equals(application.Id)
                        from token in entity.Tokens
                        select token.Id;

            var tokens = new List<string>();

            foreach (var identifier in await query.ToArrayAsync()) {
                tokens.Add(converter.ConvertToInvariantString(identifier));
            }

            return tokens;
        }
    }
}