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
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Core;
using OpenIddict.Models;

namespace OpenIddict.EntityFrameworkCore {
    /// <summary>
    /// Provides methods allowing to manage the applications stored in a database.
    /// </summary>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public class OpenIddictApplicationStore<TApplication, TToken, TContext, TKey> : IOpenIddictApplicationStore<TApplication>
        where TApplication : OpenIddictApplication<TKey, TToken>
        where TToken : OpenIddictToken<TKey>, new()
        where TContext : DbContext
        where TKey : IEquatable<TKey> {
        public OpenIddictApplicationStore([NotNull] TContext context) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            Context = context;
        }

        /// <summary>
        /// Gets the database context associated with the current store.
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
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual async Task<string> CreateAsync([NotNull] TApplication application, CancellationToken cancellationToken) {
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
        /// Retrieves an application using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client application corresponding to the identifier.
        /// </returns>
        public virtual Task<TApplication> FindByIdAsync(string identifier, CancellationToken cancellationToken) {
            var converter = TypeDescriptor.GetConverter(typeof(TKey));

            // If the string key cannot be converted to TKey, return null
            // to indicate that the requested application doesn't exist.
            if (!converter.CanConvertFrom(typeof(string))) {
                return Task.FromResult<TApplication>(null);
            }

            var key = (TKey) converter.ConvertFromInvariantString(identifier);

            return Applications.SingleOrDefaultAsync(application => application.Id.Equals(key), cancellationToken);
        }

        /// <summary>
        /// Retrieves an application using its client identifier.
        /// </summary>
        /// <param name="identifier">The client identifier associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client application corresponding to the identifier.
        /// </returns>
        public virtual Task<TApplication> FindByClientIdAsync(string identifier, CancellationToken cancellationToken) {
            return Applications.SingleOrDefaultAsync(application => application.ClientId.Equals(identifier), cancellationToken);
        }

        /// <summary>
        /// Retrieves an application using its post_logout_redirect_uri.
        /// </summary>
        /// <param name="url">The post_logout_redirect_uri associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result
        /// returns the client application corresponding to the post_logout_redirect_uri.
        /// </returns>
        public virtual Task<TApplication> FindByLogoutRedirectUri(string url, CancellationToken cancellationToken) {
            return Applications.SingleOrDefaultAsync(application => application.LogoutRedirectUri == url, cancellationToken);
        }

        /// <summary>
        /// Retrieves the client type associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client type of the application (by default, "public").
        /// </returns>
        public virtual Task<string> GetClientTypeAsync([NotNull] TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Task.FromResult(application.Type);
        }

        /// <summary>
        /// Retrieves the display name associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the display name associated with the application.
        /// </returns>
        public virtual Task<string> GetDisplayNameAsync([NotNull] TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Task.FromResult(application.DisplayName);
        }

        /// <summary>
        /// Retrieves the hashed secret associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the hashed secret associated with the application.
        /// </returns>
        public virtual Task<string> GetHashedSecretAsync([NotNull] TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Task.FromResult(application.ClientSecret);
        }

        /// <summary>
        /// Retrieves the callback address associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the redirect_uri associated with the application.
        /// </returns>
        public virtual Task<string> GetRedirectUriAsync([NotNull] TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Task.FromResult(application.RedirectUri);
        }

        /// <summary>
        /// Retrieves the token identifiers associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens associated with the application.
        /// </returns>
        public virtual async Task<IEnumerable<string>> GetTokensAsync([NotNull] TApplication application, CancellationToken cancellationToken) {
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