/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
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
        /// Determines the number of authorizations that exist in the database.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of authorizations in the database.
        /// </returns>
        public virtual Task<long> CountAsync(CancellationToken cancellationToken)
        {
            return Store.CountAsync(cancellationToken);
        }

        /// <summary>
        /// Determines the number of authorizations that match the specified query.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of authorizations that match the specified query.
        /// </returns>
        public virtual Task<long> CountAsync<TResult>([NotNull] Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return Store.CountAsync(query, cancellationToken);
        }

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

            // If no type was explicitly specified, assume that the authorization is a permanent authorization.
            if (string.IsNullOrEmpty(await Store.GetTypeAsync(authorization, cancellationToken)))
            {
                await Store.SetTypeAsync(authorization, OpenIddictConstants.AuthorizationTypes.Permanent, cancellationToken);
            }

            await ValidateAsync(authorization, cancellationToken);

            try
            {
                return await Store.CreateAsync(authorization, cancellationToken);
            }

            catch (Exception exception)
            {
                Logger.LogError(exception, "An exception occurred while trying to create a new authorization.");

                throw;
            }
        }

        /// <summary>
        /// Creates a new authorization based on the specified descriptor.
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

            var authorization = await Store.InstantiateAsync(cancellationToken);
            if (authorization == null)
            {
                throw new InvalidOperationException("An error occurred while trying to create a new authorization.");
            }

            await PopulateAsync(authorization, descriptor, cancellationToken);
            return await CreateAsync(authorization, cancellationToken);
        }

        /// <summary>
        /// Removes an existing authorization.
        /// </summary>
        /// <param name="authorization">The authorization to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task DeleteAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            try
            {
                await Store.DeleteAsync(authorization, cancellationToken);
            }

            catch (Exception exception)
            {
                Logger.LogError(exception, "An exception occurred while trying to delete an existing authorization.");

                throw;
            }
        }

        /// <summary>
        /// Retrieves the authorizations corresponding to the specified
        /// subject and associated with the application identifier.
        /// </summary>
        /// <param name="subject">The subject associated with the authorization.</param>
        /// <param name="client">The client associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorizations corresponding to the subject/client.
        /// </returns>
        public virtual Task<ImmutableArray<TAuthorization>> FindAsync([NotNull] string subject, [NotNull] string client, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.", nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException("The client identifier cannot be null or empty.", nameof(client));
            }

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
        public virtual Task<TAuthorization> FindByIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            return Store.FindByIdAsync(identifier, cancellationToken);
        }

        /// <summary>
        /// Retrieves the optional application identifier associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the application identifier associated with the authorization.
        /// </returns>
        public virtual Task<string> GetApplicationIdAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return Store.GetApplicationIdAsync(authorization, cancellationToken);
        }

        /// <summary>
        /// Executes the specified query and returns the first element.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the first element returned when executing the query.
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
        /// Retrieves the status associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the status associated with the specified authorization.
        /// </returns>
        public virtual Task<string> GetStatusAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return Store.GetStatusAsync(authorization, cancellationToken);
        }

        /// <summary>
        /// Determines whether a given authorization has been revoked.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns><c>true</c> if the authorization has been revoked, <c>false</c> otherwise.</returns>
        public virtual async Task<bool> IsRevokedAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var status = await Store.GetStatusAsync(authorization, cancellationToken);
            if (string.IsNullOrEmpty(status))
            {
                return false;
            }

            return string.Equals(status, OpenIddictConstants.Statuses.Revoked, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether a given authorization is valid.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns><c>true</c> if the authorization is valid, <c>false</c> otherwise.</returns>
        public virtual async Task<bool> IsValidAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var status = await Store.GetStatusAsync(authorization, cancellationToken);
            if (string.IsNullOrEmpty(status))
            {
                return false;
            }

            return string.Equals(status, OpenIddictConstants.Statuses.Valid, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <param name="count">The number of results to return.</param>
        /// <param name="offset">The number of results to skip.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the elements returned when executing the specified query.
        /// </returns>
        public virtual Task<ImmutableArray<TAuthorization>> ListAsync([CanBeNull] int? count, [CanBeNull] int? offset, CancellationToken cancellationToken)
        {
            return Store.ListAsync(count, offset, cancellationToken);
        }

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the elements returned when executing the specified query.
        /// </returns>
        public virtual Task<ImmutableArray<TResult>> ListAsync<TResult>([NotNull] Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return Store.ListAsync(query, cancellationToken);
        }

        /// <summary>
        /// Lists the ad-hoc authorizations that are marked as invalid or have no
        /// valid token attached and that can be safely removed from the database.
        /// </summary>
        /// <param name="count">The number of results to return.</param>
        /// <param name="offset">The number of results to skip.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the elements returned when executing the specified query.
        /// </returns>
        public virtual Task<ImmutableArray<TAuthorization>> ListInvalidAsync([CanBeNull] int? count, [CanBeNull] int? offset, CancellationToken cancellationToken)
        {
            return Store.ListInvalidAsync(count, offset, cancellationToken);
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
        /// Sets the application identifier associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="identifier">The unique identifier associated with the client application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task SetApplicationIdAsync([NotNull] TAuthorization authorization, [CanBeNull] string identifier, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            await Store.SetApplicationIdAsync(authorization, identifier, cancellationToken);
            await UpdateAsync(authorization, cancellationToken);
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

            try
            {
                await Store.UpdateAsync(authorization, cancellationToken);
            }

            catch (Exception exception)
            {
                Logger.LogError(exception, "An exception occurred while trying to update an existing authorization.");

                throw;
            }
        }

        /// <summary>
        /// Updates an existing authorization.
        /// </summary>
        /// <param name="authorization">The authorization to update.</param>
        /// <param name="operation">The delegate used to update the authorization based on the given descriptor.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task UpdateAsync([NotNull] TAuthorization authorization,
            [NotNull] Func<OpenIddictAuthorizationDescriptor, Task> operation, CancellationToken cancellationToken)
        {
            if (operation == null)
            {
                throw new ArgumentNullException(nameof(operation));
            }

            var descriptor = new OpenIddictAuthorizationDescriptor
            {
                ApplicationId = await Store.GetApplicationIdAsync(authorization, cancellationToken),
                Status = await Store.GetStatusAsync(authorization, cancellationToken),
                Subject = await Store.GetSubjectAsync(authorization, cancellationToken),
                Type = await Store.GetTypeAsync(authorization, cancellationToken)
            };

            foreach (var scope in await Store.GetScopesAsync(authorization, cancellationToken))
            {
                descriptor.Scopes.Add(scope);
            }

            await operation(descriptor);
            await PopulateAsync(authorization, descriptor, cancellationToken);
            await UpdateAsync(authorization, cancellationToken);
        }

        /// <summary>
        /// Populates the authorization using the specified descriptor.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="descriptor">The descriptor.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        protected virtual async Task PopulateAsync([NotNull] TAuthorization authorization,
            [NotNull] OpenIddictAuthorizationDescriptor descriptor, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            await Store.SetApplicationIdAsync(authorization, descriptor.ApplicationId, cancellationToken);
            await Store.SetScopesAsync(authorization, ImmutableArray.CreateRange(descriptor.Scopes), cancellationToken);
            await Store.SetStatusAsync(authorization, descriptor.Status, cancellationToken);
            await Store.SetSubjectAsync(authorization, descriptor.Subject, cancellationToken);
            await Store.SetTypeAsync(authorization, descriptor.Type, cancellationToken);
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

            var type = await Store.GetTypeAsync(authorization, cancellationToken);
            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The authorization type cannot be null or empty.", nameof(authorization));
            }

            if (!string.Equals(type, OpenIddictConstants.AuthorizationTypes.AdHoc, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(type, OpenIddictConstants.AuthorizationTypes.Permanent, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("The specified authorization type is not supported by the default token manager.", nameof(authorization));
            }

            if (string.IsNullOrEmpty(await Store.GetStatusAsync(authorization, cancellationToken)))
            {
                throw new ArgumentException("The status cannot be null or empty.", nameof(authorization));
            }

            if (string.IsNullOrEmpty(await Store.GetSubjectAsync(authorization, cancellationToken)))
            {
                throw new ArgumentException("The subject cannot be null or empty.", nameof(authorization));
            }

            // Ensure that the scopes are not null or empty and do not contain spaces.
            foreach (var scope in await Store.GetScopesAsync(authorization, cancellationToken))
            {
                if (string.IsNullOrEmpty(scope))
                {
                    throw new ArgumentException("Scopes cannot be null or empty.", nameof(authorization));
                }

                if (scope.Contains(OpenIddictConstants.Separators.Space))
                {
                    throw new ArgumentException("Scopes cannot contain spaces.", nameof(authorization));
                }
            }
        }
    }
}