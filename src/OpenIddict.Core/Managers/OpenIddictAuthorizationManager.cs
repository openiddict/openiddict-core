/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
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
        public virtual Task<long> CountAsync(CancellationToken cancellationToken = default)
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
        public virtual Task<long> CountAsync<TResult>(
            [NotNull] Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
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
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task CreateAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken = default)
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

            var results = await ValidateAsync(authorization, cancellationToken);
            if (results.Any(result => result != ValidationResult.Success))
            {
                throw new ValidationException(results.FirstOrDefault(result => result != ValidationResult.Success), null, authorization);
            }

            await Store.CreateAsync(authorization, cancellationToken);
        }

        /// <summary>
        /// Creates a new authorization based on the specified descriptor.
        /// </summary>
        /// <param name="descriptor">The authorization descriptor.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result returns the authorization.
        /// </returns>
        public virtual async Task<TAuthorization> CreateAsync(
            [NotNull] OpenIddictAuthorizationDescriptor descriptor, CancellationToken cancellationToken = default)
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
            await CreateAsync(authorization, cancellationToken);

            return authorization;
        }

        /// <summary>
        /// Removes an existing authorization.
        /// </summary>
        /// <param name="authorization">The authorization to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task DeleteAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken = default)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return Store.DeleteAsync(authorization, cancellationToken);
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
        public virtual Task<ImmutableArray<TAuthorization>> FindAsync(
            [NotNull] string subject, [NotNull] string client, CancellationToken cancellationToken = default)
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
        public virtual Task<TAuthorization> FindByIdAsync([NotNull] string identifier, CancellationToken cancellationToken = default)
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
        public virtual Task<string> GetApplicationIdAsync(
            [NotNull] TAuthorization authorization, CancellationToken cancellationToken = default)
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
        public virtual Task<TResult> GetAsync<TResult>(
            [NotNull] Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
        {
            return GetAsync((authorizations, state) => state(authorizations), query, cancellationToken);
        }

        /// <summary>
        /// Executes the specified query and returns the first element.
        /// </summary>
        /// <typeparam name="TState">The state type.</typeparam>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="state">The optional state.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the first element returned when executing the query.
        /// </returns>
        public virtual Task<TResult> GetAsync<TState, TResult>(
            [NotNull] Func<IQueryable<TAuthorization>, TState, IQueryable<TResult>> query,
            [CanBeNull] TState state, CancellationToken cancellationToken = default)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return Store.GetAsync(query, state, cancellationToken);
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
        public virtual Task<string> GetIdAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken = default)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return Store.GetIdAsync(authorization, cancellationToken);
        }

        /// <summary>
        /// Retrieves the scopes associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scopes associated with the specified authorization.
        /// </returns>
        public virtual Task<ImmutableArray<string>> GetScopesAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken = default)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return Store.GetScopesAsync(authorization, cancellationToken);
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
        public virtual Task<string> GetStatusAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken = default)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return Store.GetStatusAsync(authorization, cancellationToken);
        }

        /// <summary>
        /// Retrieves the subject associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the subject associated with the specified authorization.
        /// </returns>
        public virtual Task<string> GetSubjectAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken = default)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return Store.GetSubjectAsync(authorization, cancellationToken);
        }

        /// <summary>
        /// Retrieves the type associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the type associated with the specified authorization.
        /// </returns>
        public virtual Task<string> GetTypeAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken = default)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return Store.GetTypeAsync(authorization, cancellationToken);
        }

        /// <summary>
        /// Determines whether the specified scopes are included in the authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="scopes">The scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns><c>true</c> if the scopes are included in the authorization, <c>false</c> otherwise.</returns>
        public virtual async Task<bool> HasScopesAsync([NotNull] TAuthorization authorization,
            ImmutableArray<string> scopes, CancellationToken cancellationToken = default)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return (await Store.GetScopesAsync(authorization, cancellationToken))
                .ToImmutableHashSet(StringComparer.Ordinal)
                .IsSupersetOf(scopes);
        }

        /// <summary>
        /// Determines whether a given authorization is ad hoc.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns><c>true</c> if the authorization is ad hoc, <c>false</c> otherwise.</returns>
        public async Task<bool> IsAdHocAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken = default)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var type = await GetTypeAsync(authorization, cancellationToken);
            if (string.IsNullOrEmpty(type))
            {
                return false;
            }

            return string.Equals(type, OpenIddictConstants.AuthorizationTypes.AdHoc, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether a given authorization is permanent.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns><c>true</c> if the authorization is permanent, <c>false</c> otherwise.</returns>
        public async Task<bool> IsPermanentAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken = default)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var type = await GetTypeAsync(authorization, cancellationToken);
            if (string.IsNullOrEmpty(type))
            {
                return false;
            }

            return string.Equals(type, OpenIddictConstants.AuthorizationTypes.Permanent, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether a given authorization has been revoked.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns><c>true</c> if the authorization has been revoked, <c>false</c> otherwise.</returns>
        public virtual async Task<bool> IsRevokedAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken = default)
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
        public virtual async Task<bool> IsValidAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken = default)
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
        public virtual Task<ImmutableArray<TAuthorization>> ListAsync(
            [CanBeNull] int? count, [CanBeNull] int? offset, CancellationToken cancellationToken = default)
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
        public virtual Task<ImmutableArray<TResult>> ListAsync<TResult>(
            [NotNull] Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
        {
            return ListAsync((authorizations, state) => state(authorizations), query, cancellationToken);
        }

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <typeparam name="TState">The state type.</typeparam>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="state">The optional state.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the elements returned when executing the specified query.
        /// </returns>
        public virtual Task<ImmutableArray<TResult>> ListAsync<TState, TResult>(
            [NotNull] Func<IQueryable<TAuthorization>, TState, IQueryable<TResult>> query,
            [CanBeNull] TState state, CancellationToken cancellationToken = default)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return Store.ListAsync(query, state, cancellationToken);
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
        public virtual Task<ImmutableArray<TAuthorization>> ListInvalidAsync(
            [CanBeNull] int? count, [CanBeNull] int? offset, CancellationToken cancellationToken = default)
        {
            return Store.ListInvalidAsync(count, offset, cancellationToken);
        }

        /// <summary>
        /// Removes the ad-hoc authorizations that are marked as invalid or have no valid token attached.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task PruneInvalidAsync(CancellationToken cancellationToken = default)
        {
            ImmutableArray<TAuthorization> authorizations;

            do
            {
                // Note: don't use an offset here, as the elements returned by this method
                // are progressively removed from the database immediately after calling it.
                authorizations = await ListInvalidAsync(100, 0, cancellationToken);

                foreach (var authorization in authorizations)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    try
                    {
                        await DeleteAsync(authorization, cancellationToken);

                        Logger.LogDebug("The authorization {AuthorizationId} was successfully removed from the database.",
                            await GetIdAsync(authorization, cancellationToken));
                    }

                    catch (Exception exception)
                    {
                        Logger.LogDebug(exception,
                            "An error occurred while removing the authorization {AuthorizationId} from the database.",
                            await GetIdAsync(authorization, cancellationToken));
                    }
                }

                cancellationToken.ThrowIfCancellationRequested();
            }

            while (!authorizations.IsDefaultOrEmpty);
        }

        /// <summary>
        /// Revokes an authorization.
        /// </summary>
        /// <param name="authorization">The authorization to revoke.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual async Task RevokeAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken = default)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var status = await Store.GetStatusAsync(authorization, cancellationToken);
            if (!string.Equals(status, OpenIddictConstants.Statuses.Revoked, StringComparison.OrdinalIgnoreCase))
            {
                await Store.SetStatusAsync(authorization, OpenIddictConstants.Statuses.Revoked, cancellationToken);

                var results = await ValidateAsync(authorization, cancellationToken);
                if (results.Any(result => result != ValidationResult.Success))
                {
                    throw new ValidationException(results.FirstOrDefault(result => result != ValidationResult.Success), null, authorization);
                }

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
        public virtual async Task SetApplicationIdAsync(
            [NotNull] TAuthorization authorization, [CanBeNull] string identifier, CancellationToken cancellationToken = default)
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
        public virtual async Task UpdateAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken = default)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var results = await ValidateAsync(authorization, cancellationToken);
            if (results.Any(result => result != ValidationResult.Success))
            {
                throw new ValidationException(results.FirstOrDefault(result => result != ValidationResult.Success), null, authorization);
            }

            await Store.UpdateAsync(authorization, cancellationToken);
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
            [NotNull] Func<OpenIddictAuthorizationDescriptor, Task> operation, CancellationToken cancellationToken = default)
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
        /// Validates the authorization to ensure it's in a consistent state.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the validation error encountered when validating the authorization.
        /// </returns>
        public virtual async Task<ImmutableArray<ValidationResult>> ValidateAsync(
            [NotNull] TAuthorization authorization, CancellationToken cancellationToken = default)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var results = ImmutableArray.CreateBuilder<ValidationResult>();

            var type = await Store.GetTypeAsync(authorization, cancellationToken);
            if (string.IsNullOrEmpty(type))
            {
                results.Add(new ValidationResult("The authorization type cannot be null or empty."));
            }

            else if (!string.Equals(type, OpenIddictConstants.AuthorizationTypes.AdHoc, StringComparison.OrdinalIgnoreCase) &&
                     !string.Equals(type, OpenIddictConstants.AuthorizationTypes.Permanent, StringComparison.OrdinalIgnoreCase))
            {
                results.Add(new ValidationResult("The specified authorization type is not supported by the default token manager."));
            }

            if (string.IsNullOrEmpty(await Store.GetStatusAsync(authorization, cancellationToken)))
            {
                results.Add(new ValidationResult("The status cannot be null or empty."));
            }

            if (string.IsNullOrEmpty(await Store.GetSubjectAsync(authorization, cancellationToken)))
            {
                results.Add(new ValidationResult("The subject cannot be null or empty."));
            }

            // Ensure that the scopes are not null or empty and do not contain spaces.
            foreach (var scope in await Store.GetScopesAsync(authorization, cancellationToken))
            {
                if (string.IsNullOrEmpty(scope))
                {
                    results.Add(new ValidationResult("Scopes cannot be null or empty."));

                    break;
                }

                if (scope.Contains(OpenIddictConstants.Separators.Space))
                {
                    results.Add(new ValidationResult("Scopes cannot contain spaces."));

                    break;
                }
            }

            return results.ToImmutable();
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
            [NotNull] OpenIddictAuthorizationDescriptor descriptor, CancellationToken cancellationToken = default)
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
    }
}