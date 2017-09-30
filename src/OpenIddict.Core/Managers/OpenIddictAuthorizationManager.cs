/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Core
{
    /// <summary>
    /// Provides methods allowing to manage the authorizations stored in the store.
    /// </summary>
    /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
    public class OpenIddictAuthorizationManager<TAuthorization> where TAuthorization : class
    {
        public OpenIddictAuthorizationManager(
            [NotNull] IOpenIddictAuthorizationStore<TAuthorization> store,
            [NotNull] ILogger<OpenIddictAuthorizationManager<TAuthorization>> logger)
        {
            Logger = logger;
            Store = store;
        }

        /// <summary>
        /// Gets the logger associated with the current manager.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Gets the store associated with the current manager.
        /// </summary>
        protected IOpenIddictAuthorizationStore<TAuthorization> Store { get; }

        /// <summary>
        /// Creates a new authorization.
        /// </summary>
        /// <param name="authorization">The application to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result returns the authorization.
        /// </returns>
        public virtual async Task<TAuthorization> CreateAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            await ValidateAsync(authorization, cancellationToken);
            return await Store.CreateAsync(authorization, cancellationToken);
        }

        /// <summary>
        /// Creates a new authorization.
        /// </summary>
        /// <param name="descriptor">The authorization descriptor.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result returns the authorization.
        /// </returns>
        public virtual async Task<TAuthorization> CreateAsync([NotNull] OpenIddictAuthorizationDescriptor descriptor, CancellationToken cancellationToken)
        {
            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            await ValidateAsync(descriptor, cancellationToken);
            return await Store.CreateAsync(descriptor, cancellationToken);
        }

        /// <summary>
        /// Retrieves an authorization using its associated subject/client.
        /// </summary>
        /// <param name="subject">The subject associated with the authorization.</param>
        /// <param name="client">The client associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorization corresponding to the subject/client.
        /// </returns>
        public virtual Task<TAuthorization> FindAsync(string subject, string client, CancellationToken cancellationToken)
        {
            return Store.FindAsync(subject, client, cancellationToken);
        }

        /// <summary>
        /// Retrieves an authorization using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorization corresponding to the identifier.
        /// </returns>
        public virtual Task<TAuthorization> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        {
            return Store.FindByIdAsync(identifier, cancellationToken);
        }

        /// <summary>
        /// Executes the specified query.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the single element returned when executing the specified query.
        /// </returns>
        public virtual Task<TResult> GetAsync<TResult>([NotNull] Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return Store.GetAsync(query, cancellationToken);
        }

        /// <summary>
        /// Retrieves the unique identifier associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the authorization.
        /// </returns>
        public virtual Task<string> GetIdAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return Store.GetIdAsync(authorization, cancellationToken);
        }

        /// <summary>
        /// Executes the specified query.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the elements returned when executing the specified query.
        /// </returns>
        public virtual Task<TResult[]> ListAsync<TResult>([NotNull] Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return Store.ListAsync(query, cancellationToken);
        }

        /// <summary>
        /// Revokes an authorization.
        /// </summary>
        /// <param name="authorization">The authorization to revoke.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual async Task RevokeAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var status = await Store.GetStatusAsync(authorization, cancellationToken);
            if (!string.Equals(status, OpenIddictConstants.Statuses.Revoked, StringComparison.OrdinalIgnoreCase))
            {
                await Store.SetStatusAsync(authorization, OpenIddictConstants.Statuses.Revoked, cancellationToken);
                await ValidateAsync(authorization, cancellationToken);
                await UpdateAsync(authorization, cancellationToken);
            }
        }

        /// <summary>
        /// Updates an existing authorization.
        /// </summary>
        /// <param name="authorization">The authorization to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task UpdateAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            await ValidateAsync(authorization, cancellationToken);
            await Store.UpdateAsync(authorization, cancellationToken);
        }

        /// <summary>
        /// Validates the authorization to ensure it's in a consistent state.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        protected virtual async Task ValidateAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var descriptor = new OpenIddictAuthorizationDescriptor
            {
                Status = await Store.GetStatusAsync(authorization, cancellationToken),
                Subject = await Store.GetSubjectAsync(authorization, cancellationToken)
            };

            await ValidateAsync(descriptor, cancellationToken);
        }

        /// <summary>
        /// Validates the authorization descriptor to ensure it's in a consistent state.
        /// </summary>
        /// <param name="descriptor">The authorization descriptor.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        protected virtual Task ValidateAsync([NotNull] OpenIddictAuthorizationDescriptor descriptor, CancellationToken cancellationToken)
        {
            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            if (string.IsNullOrEmpty(descriptor.Status))
            {
                throw new ArgumentException("The status cannot be null or empty.");
            }

            if (string.IsNullOrEmpty(descriptor.Subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.");
            }

            return Task.CompletedTask;
        }
    }
}