/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Core
{
    /// <summary>
    /// Provides methods allowing to manage the scopes stored in the store.
    /// </summary>
    /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
    public class OpenIddictScopeManager<TScope> : IOpenIddictScopeManager where TScope : class
    {
        public OpenIddictScopeManager(
            [NotNull] IOpenIddictScopeCache<TScope> cache,
            [NotNull] IOpenIddictScopeStoreResolver resolver,
            [NotNull] ILogger<OpenIddictScopeManager<TScope>> logger,
            [NotNull] IOptionsMonitor<OpenIddictCoreOptions> options)
        {
            Cache = cache;
            Store = resolver.Get<TScope>();
            Logger = logger;
            Options = options;
        }

        /// <summary>
        /// Gets the cache associated with the current manager.
        /// </summary>
        protected IOpenIddictScopeCache<TScope> Cache { get; }

        /// <summary>
        /// Gets the logger associated with the current manager.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Gets the options associated with the current manager.
        /// </summary>
        protected IOptionsMonitor<OpenIddictCoreOptions> Options { get; }

        /// <summary>
        /// Gets the store associated with the current manager.
        /// </summary>
        protected IOpenIddictScopeStore<TScope> Store { get; }

        /// <summary>
        /// Determines the number of scopes that exist in the database.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of scopes in the database.
        /// </returns>
        public virtual ValueTask<long> CountAsync(CancellationToken cancellationToken = default)
            => Store.CountAsync(cancellationToken);

        /// <summary>
        /// Determines the number of scopes that match the specified query.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of scopes that match the specified query.
        /// </returns>
        public virtual ValueTask<long> CountAsync<TResult>(
            [NotNull] Func<IQueryable<TScope>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return Store.CountAsync(query, cancellationToken);
        }

        /// <summary>
        /// Creates a new scope.
        /// </summary>
        /// <param name="scope">The scope to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async ValueTask CreateAsync([NotNull] TScope scope, CancellationToken cancellationToken = default)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            var results = await ValidateAsync(scope, cancellationToken).ToListAsync(cancellationToken);
            if (results.Any(result => result != ValidationResult.Success))
            {
                var builder = new StringBuilder();
                builder.AppendLine("One or more validation error(s) occurred while trying to create a new scope:");
                builder.AppendLine();

                foreach (var result in results)
                {
                    builder.AppendLine(result.ErrorMessage);
                }

                throw new OpenIddictExceptions.ValidationException(builder.ToString(), results.ToImmutableArray());
            }

            await Store.CreateAsync(scope, cancellationToken);

            if (!Options.CurrentValue.DisableEntityCaching)
            {
                await Cache.AddAsync(scope, cancellationToken);
            }
        }

        /// <summary>
        /// Creates a new scope based on the specified descriptor.
        /// </summary>
        /// <param name="descriptor">The scope descriptor.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation, whose result returns the scope.
        /// </returns>
        public virtual async ValueTask<TScope> CreateAsync(
            [NotNull] OpenIddictScopeDescriptor descriptor, CancellationToken cancellationToken = default)
        {
            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            var scope = await Store.InstantiateAsync(cancellationToken);
            if (scope == null)
            {
                throw new InvalidOperationException("An error occurred while trying to create a new scope.");
            }

            await PopulateAsync(scope, descriptor, cancellationToken);
            await CreateAsync(scope, cancellationToken);

            return scope;
        }

        /// <summary>
        /// Removes an existing scope.
        /// </summary>
        /// <param name="scope">The scope to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async ValueTask DeleteAsync([NotNull] TScope scope, CancellationToken cancellationToken = default)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (!Options.CurrentValue.DisableEntityCaching)
            {
                await Cache.RemoveAsync(scope, cancellationToken);
            }

            await Store.DeleteAsync(scope, cancellationToken);
        }

        /// <summary>
        /// Retrieves a scope using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scope corresponding to the identifier.
        /// </returns>
        public virtual async ValueTask<TScope> FindByIdAsync([NotNull] string identifier, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            var scope = Options.CurrentValue.DisableEntityCaching ?
                await Store.FindByIdAsync(identifier, cancellationToken) :
                await Cache.FindByIdAsync(identifier, cancellationToken);

            if (scope == null)
            {
                return null;
            }

            // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
            // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
            // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.
            if (!Options.CurrentValue.DisableAdditionalFiltering &&
                !string.Equals(await Store.GetIdAsync(scope, cancellationToken), identifier, StringComparison.Ordinal))
            {
                return null;
            }

            return scope;
        }

        /// <summary>
        /// Retrieves a scope using its name.
        /// </summary>
        /// <param name="name">The name associated with the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scope corresponding to the specified name.
        /// </returns>
        public virtual async ValueTask<TScope> FindByNameAsync([NotNull] string name, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The scope name cannot be null or empty.", nameof(name));
            }

            var scope = Options.CurrentValue.DisableEntityCaching ?
                await Store.FindByNameAsync(name, cancellationToken) :
                await Cache.FindByNameAsync(name, cancellationToken);

            if (scope == null)
            {
                return null;
            }

            // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
            // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
            // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

            if (!Options.CurrentValue.DisableAdditionalFiltering &&
                !string.Equals(await Store.GetNameAsync(scope, cancellationToken), name, StringComparison.Ordinal))
            {
                return null;
            }

            return scope;
        }

        /// <summary>
        /// Retrieves a list of scopes using their name.
        /// </summary>
        /// <param name="names">The names associated with the scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>The scopes corresponding to the specified names.</returns>
        public virtual IAsyncEnumerable<TScope> FindByNamesAsync(
            ImmutableArray<string> names, CancellationToken cancellationToken = default)
        {
            if (names.IsDefaultOrEmpty)
            {
                return AsyncEnumerable.Empty<TScope>();
            }

            if (names.Any(name => string.IsNullOrEmpty(name)))
            {
                throw new ArgumentException("Scope names cannot be null or empty.", nameof(names));
            }

            var scopes = Options.CurrentValue.DisableEntityCaching ?
                Store.FindByNamesAsync(names, cancellationToken) :
                Cache.FindByNamesAsync(names, cancellationToken);

            if (Options.CurrentValue.DisableAdditionalFiltering)
            {
                return scopes;
            }

            // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
            // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
            // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

            return scopes.WhereAwait(async scope => names.Contains(await Store.GetNameAsync(scope, cancellationToken), StringComparer.Ordinal));
        }

        /// <summary>
        /// Retrieves all the scopes that contain the specified resource.
        /// </summary>
        /// <param name="resource">The resource associated with the scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>The scopes associated with the specified resource.</returns>
        public virtual IAsyncEnumerable<TScope> FindByResourceAsync(
            [NotNull] string resource, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentException("The resource cannot be null or empty.", nameof(resource));
            }

            var scopes = Options.CurrentValue.DisableEntityCaching ?
                Store.FindByResourceAsync(resource, cancellationToken) :
                Cache.FindByResourceAsync(resource, cancellationToken);

            if (Options.CurrentValue.DisableAdditionalFiltering)
            {
                return scopes;
            }

            // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
            // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
            // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

            return scopes.WhereAwait(async scope =>
                (await Store.GetResourcesAsync(scope, cancellationToken)).Contains(resource, StringComparer.Ordinal));
        }

        /// <summary>
        /// Executes the specified query and returns the first element.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the first element returned when executing the query.
        /// </returns>
        public virtual ValueTask<TResult> GetAsync<TResult>(
            [NotNull] Func<IQueryable<TScope>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return GetAsync((scopes, state) => state(scopes), query, cancellationToken);
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
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the first element returned when executing the query.
        /// </returns>
        public virtual ValueTask<TResult> GetAsync<TState, TResult>(
            [NotNull] Func<IQueryable<TScope>, TState, IQueryable<TResult>> query,
            [CanBeNull] TState state, CancellationToken cancellationToken = default)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return Store.GetAsync(query, state, cancellationToken);
        }

        /// <summary>
        /// Retrieves the description associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the description associated with the specified scope.
        /// </returns>
        public virtual ValueTask<string> GetDescriptionAsync([NotNull] TScope scope, CancellationToken cancellationToken = default)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return Store.GetDescriptionAsync(scope, cancellationToken);
        }

        /// <summary>
        /// Retrieves the display name associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the display name associated with the scope.
        /// </returns>
        public virtual ValueTask<string> GetDisplayNameAsync([NotNull] TScope scope, CancellationToken cancellationToken = default)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return Store.GetDisplayNameAsync(scope, cancellationToken);
        }

        /// <summary>
        /// Retrieves the unique identifier associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the scope.
        /// </returns>
        public virtual ValueTask<string> GetIdAsync([NotNull] TScope scope, CancellationToken cancellationToken = default)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return Store.GetIdAsync(scope, cancellationToken);
        }

        /// <summary>
        /// Retrieves the name associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the name associated with the specified scope.
        /// </returns>
        public virtual ValueTask<string> GetNameAsync([NotNull] TScope scope, CancellationToken cancellationToken = default)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return Store.GetNameAsync(scope, cancellationToken);
        }

        /// <summary>
        /// Retrieves the resources associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the resources associated with the scope.
        /// </returns>
        public virtual ValueTask<ImmutableArray<string>> GetResourcesAsync(
            [NotNull] TScope scope, CancellationToken cancellationToken = default)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return Store.GetResourcesAsync(scope, cancellationToken);
        }

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <param name="count">The number of results to return.</param>
        /// <param name="offset">The number of results to skip.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>All the elements returned when executing the specified query.</returns>
        public virtual IAsyncEnumerable<TScope> ListAsync(
            [CanBeNull] int? count = null, [CanBeNull] int? offset = null, CancellationToken cancellationToken = default)
            => Store.ListAsync(count, offset, cancellationToken);

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>All the elements returned when executing the specified query.</returns>
        public virtual IAsyncEnumerable<TResult> ListAsync<TResult>(
            [NotNull] Func<IQueryable<TScope>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return ListAsync((scopes, state) => state(scopes), query, cancellationToken);
        }

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <typeparam name="TState">The state type.</typeparam>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="state">The optional state.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>All the elements returned when executing the specified query.</returns>
        public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
            [NotNull] Func<IQueryable<TScope>, TState, IQueryable<TResult>> query,
            [CanBeNull] TState state, CancellationToken cancellationToken = default)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return Store.ListAsync(query, state, cancellationToken);
        }

        /// <summary>
        /// Lists all the resources associated with the specified scopes.
        /// </summary>
        /// <param name="scopes">The scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>All the resources associated with the specified scopes.</returns>
        public virtual IAsyncEnumerable<string> ListResourcesAsync(
            ImmutableArray<string> scopes, CancellationToken cancellationToken = default)
        {
            if (scopes.IsDefaultOrEmpty)
            {
                return AsyncEnumerable.Empty<string>();
            }

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<string> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var resources = new HashSet<string>(StringComparer.Ordinal);

                await foreach (var scope in FindByNamesAsync(scopes, cancellationToken))
                {
                    resources.UnionWith(await GetResourcesAsync(scope, cancellationToken));
                }

                foreach (var resource in resources)
                {
                    yield return resource;
                }
            }
        }

        /// <summary>
        /// Populates the scope using the specified descriptor.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="descriptor">The descriptor.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async ValueTask PopulateAsync([NotNull] TScope scope,
            [NotNull] OpenIddictScopeDescriptor descriptor, CancellationToken cancellationToken = default)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            await Store.SetDescriptionAsync(scope, descriptor.Description, cancellationToken);
            await Store.SetDisplayNameAsync(scope, descriptor.DisplayName, cancellationToken);
            await Store.SetNameAsync(scope, descriptor.Name, cancellationToken);
            await Store.SetResourcesAsync(scope, descriptor.Resources.ToImmutableArray(), cancellationToken);
        }

        /// <summary>
        /// Populates the specified descriptor using the properties exposed by the scope.
        /// </summary>
        /// <param name="descriptor">The descriptor.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async ValueTask PopulateAsync(
            [NotNull] OpenIddictScopeDescriptor descriptor,
            [NotNull] TScope scope, CancellationToken cancellationToken = default)
        {
            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            descriptor.Description = await Store.GetDescriptionAsync(scope, cancellationToken);
            descriptor.DisplayName = await Store.GetDisplayNameAsync(scope, cancellationToken);
            descriptor.Name = await Store.GetNameAsync(scope, cancellationToken);
            descriptor.Resources.Clear();
            descriptor.Resources.UnionWith(await Store.GetResourcesAsync(scope, cancellationToken));
        }

        /// <summary>
        /// Updates an existing scope.
        /// </summary>
        /// <param name="scope">The scope to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async ValueTask UpdateAsync([NotNull] TScope scope, CancellationToken cancellationToken = default)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            var results = await ValidateAsync(scope, cancellationToken).ToListAsync(cancellationToken);
            if (results.Any(result => result != ValidationResult.Success))
            {
                var builder = new StringBuilder();
                builder.AppendLine("One or more validation error(s) occurred while trying to update an existing scope:");
                builder.AppendLine();

                foreach (var result in results)
                {
                    builder.AppendLine(result.ErrorMessage);
                }

                throw new OpenIddictExceptions.ValidationException(builder.ToString(), results.ToImmutableArray());
            }

            await Store.UpdateAsync(scope, cancellationToken);

            if (!Options.CurrentValue.DisableEntityCaching)
            {
                await Cache.RemoveAsync(scope, cancellationToken);
                await Cache.AddAsync(scope, cancellationToken);
            }
        }

        /// <summary>
        /// Updates an existing scope.
        /// </summary>
        /// <param name="scope">The scope to update.</param>
        /// <param name="descriptor">The descriptor used to update the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async ValueTask UpdateAsync([NotNull] TScope scope,
            [NotNull] OpenIddictScopeDescriptor descriptor, CancellationToken cancellationToken = default)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            await PopulateAsync(scope, descriptor, cancellationToken);
            await UpdateAsync(scope, cancellationToken);
        }

        /// <summary>
        /// Validates the scope to ensure it's in a consistent state.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>The validation error encountered when validating the scope.</returns>
        public virtual async IAsyncEnumerable<ValidationResult> ValidateAsync(
            [NotNull] TScope scope, [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            // Ensure the name is not null or empty, does not contain a
            // space and is not already used for a different scope entity.
            var name = await Store.GetNameAsync(scope, cancellationToken);
            if (string.IsNullOrEmpty(name))
            {
                yield return new ValidationResult("The scope name cannot be null or empty.");
            }

            else if (name.Contains(Separators.Space[0]))
            {
                yield return new ValidationResult("The scope name cannot contain spaces.");
            }

            else
            {
                // Note: depending on the database/table/query collation used by the store, a scope
                // whose name doesn't exactly match the specified value may be returned (e.g because
                // the casing is different). To avoid issues when the scope name is part of an index
                // using the same collation, an error is added even if the two names don't exactly match.
                var other = await Store.FindByNameAsync(name, cancellationToken);
                if (other != null && !string.Equals(
                    await Store.GetIdAsync(other, cancellationToken),
                    await Store.GetIdAsync(scope, cancellationToken), StringComparison.Ordinal))
                {
                    yield return new ValidationResult("A scope with the same name already exists.");
                }
            }
        }

        ValueTask<long> IOpenIddictScopeManager.CountAsync(CancellationToken cancellationToken)
            => CountAsync(cancellationToken);

        ValueTask<long> IOpenIddictScopeManager.CountAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken)
            => CountAsync(query, cancellationToken);

        async ValueTask<object> IOpenIddictScopeManager.CreateAsync(OpenIddictScopeDescriptor descriptor, CancellationToken cancellationToken)
            => await CreateAsync(descriptor, cancellationToken);

        ValueTask IOpenIddictScopeManager.CreateAsync(object scope, CancellationToken cancellationToken)
            => CreateAsync((TScope) scope, cancellationToken);

        ValueTask IOpenIddictScopeManager.DeleteAsync(object scope, CancellationToken cancellationToken)
            => DeleteAsync((TScope) scope, cancellationToken);

        async ValueTask<object> IOpenIddictScopeManager.FindByIdAsync(string identifier, CancellationToken cancellationToken)
            => await FindByIdAsync(identifier, cancellationToken);

        async ValueTask<object> IOpenIddictScopeManager.FindByNameAsync(string name, CancellationToken cancellationToken)
            => await FindByNameAsync(name, cancellationToken);

        IAsyncEnumerable<object> IOpenIddictScopeManager.FindByNamesAsync(ImmutableArray<string> names, CancellationToken cancellationToken)
            => FindByNamesAsync(names, cancellationToken).OfType<object>();

        IAsyncEnumerable<object> IOpenIddictScopeManager.FindByResourceAsync(string resource, CancellationToken cancellationToken)
            => FindByResourceAsync(resource, cancellationToken).OfType<object>();

        ValueTask<TResult> IOpenIddictScopeManager.GetAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken)
            => GetAsync(query, cancellationToken);

        ValueTask<TResult> IOpenIddictScopeManager.GetAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken)
            => GetAsync(query, state, cancellationToken);

        ValueTask<string> IOpenIddictScopeManager.GetDescriptionAsync(object scope, CancellationToken cancellationToken)
            => GetDescriptionAsync((TScope) scope, cancellationToken);

        ValueTask<string> IOpenIddictScopeManager.GetDisplayNameAsync(object scope, CancellationToken cancellationToken)
            => GetDisplayNameAsync((TScope) scope, cancellationToken);

        ValueTask<string> IOpenIddictScopeManager.GetIdAsync(object scope, CancellationToken cancellationToken)
            => GetIdAsync((TScope) scope, cancellationToken);

        ValueTask<string> IOpenIddictScopeManager.GetNameAsync(object scope, CancellationToken cancellationToken)
            => GetNameAsync((TScope) scope, cancellationToken);

        ValueTask<ImmutableArray<string>> IOpenIddictScopeManager.GetResourcesAsync(object scope, CancellationToken cancellationToken)
            => GetResourcesAsync((TScope) scope, cancellationToken);

        IAsyncEnumerable<object> IOpenIddictScopeManager.ListAsync(int? count, int? offset, CancellationToken cancellationToken)
            => ListAsync(count, offset, cancellationToken).OfType<object>();

        IAsyncEnumerable<TResult> IOpenIddictScopeManager.ListAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken)
            => ListAsync(query, cancellationToken);

        IAsyncEnumerable<TResult> IOpenIddictScopeManager.ListAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken)
            => ListAsync(query, state, cancellationToken);

        IAsyncEnumerable<string> IOpenIddictScopeManager.ListResourcesAsync(ImmutableArray<string> scopes, CancellationToken cancellationToken)
            => ListResourcesAsync(scopes, cancellationToken);

        ValueTask IOpenIddictScopeManager.PopulateAsync(OpenIddictScopeDescriptor descriptor, object scope, CancellationToken cancellationToken)
            => PopulateAsync(descriptor, (TScope) scope, cancellationToken);

        ValueTask IOpenIddictScopeManager.PopulateAsync(object scope, OpenIddictScopeDescriptor descriptor, CancellationToken cancellationToken)
            => PopulateAsync((TScope) scope, descriptor, cancellationToken);

        ValueTask IOpenIddictScopeManager.UpdateAsync(object scope, CancellationToken cancellationToken)
            => UpdateAsync((TScope) scope, cancellationToken);

        ValueTask IOpenIddictScopeManager.UpdateAsync(object scope, OpenIddictScopeDescriptor descriptor, CancellationToken cancellationToken)
            => UpdateAsync((TScope) scope, descriptor, cancellationToken);

        IAsyncEnumerable<ValidationResult> IOpenIddictScopeManager.ValidateAsync(object scope, CancellationToken cancellationToken)
            => ValidateAsync((TScope) scope, cancellationToken);
    }
}