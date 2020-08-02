/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

#nullable disable

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace OpenIddict.Abstractions
{
    /// <summary>
    /// Provides methods allowing to manage the scopes stored in the store.
    /// Note: this interface is not meant to be implemented by custom managers,
    /// that should inherit from the generic OpenIddictScopeManager class.
    /// It is primarily intended to be used by services that cannot easily
    /// depend on the generic scope manager. The actual scope entity type is
    /// automatically determined at runtime based on the OpenIddict core options.
    /// </summary>
    public interface IOpenIddictScopeManager
    {
        /// <summary>
        /// Determines the number of scopes that exist in the database.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of scopes in the database.
        /// </returns>
        ValueTask<long> CountAsync(CancellationToken cancellationToken = default);

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
        ValueTask<long> CountAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken = default);

        /// <summary>
        /// Creates a new scope based on the specified descriptor.
        /// </summary>
        /// <param name="descriptor">The scope descriptor.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation, whose result returns the scope.
        /// </returns>
        ValueTask<object> CreateAsync(OpenIddictScopeDescriptor descriptor, CancellationToken cancellationToken = default);

        /// <summary>
        /// Creates a new scope.
        /// </summary>
        /// <param name="scope">The scope to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        ValueTask CreateAsync(object scope, CancellationToken cancellationToken = default);

        /// <summary>
        /// Removes an existing scope.
        /// </summary>
        /// <param name="scope">The scope to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        ValueTask DeleteAsync(object scope, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves a scope using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scope corresponding to the identifier.
        /// </returns>
        ValueTask<object> FindByIdAsync(string identifier, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves a scope using its name.
        /// </summary>
        /// <param name="name">The name associated with the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scope corresponding to the specified name.
        /// </returns>
        ValueTask<object> FindByNameAsync(string name, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves a list of scopes using their name.
        /// </summary>
        /// <param name="names">The names associated with the scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>The scopes corresponding to the specified names.</returns>
        IAsyncEnumerable<object> FindByNamesAsync(ImmutableArray<string> names, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves all the scopes that contain the specified resource.
        /// </summary>
        /// <param name="resource">The resource associated with the scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>The scopes associated with the specified resource.</returns>
        IAsyncEnumerable<object> FindByResourceAsync(string resource, CancellationToken cancellationToken = default);

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
        ValueTask<TResult> GetAsync<TResult>(
            Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken = default);

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
        ValueTask<TResult> GetAsync<TState, TResult>(
            Func<IQueryable<object>, TState, IQueryable<TResult>> query,
            TState state, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves the description associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the description associated with the specified scope.
        /// </returns>
        ValueTask<string> GetDescriptionAsync(object scope, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves the localized descriptions associated with an scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the localized descriptions associated with the scope.
        /// </returns>
        ValueTask<ImmutableDictionary<CultureInfo, string>> GetDescriptionsAsync(object scope, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves the display name associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the display name associated with the scope.
        /// </returns>
        ValueTask<string> GetDisplayNameAsync(object scope, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves the localized display names associated with an scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the localized display names associated with the scope.
        /// </returns>
        ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(object scope, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves the unique identifier associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the scope.
        /// </returns>
        ValueTask<string> GetIdAsync(object scope, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves the localized description associated with an scope
        /// and corresponding to the current UI culture or one of its parents.
        /// If no matching value can be found, the non-localized value is returned.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the matching localized description associated with the scope.
        /// </returns>
        ValueTask<string> GetLocalizedDescriptionAsync(object scope, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves the localized description associated with an scope
        /// and corresponding to the specified culture or one of its parents.
        /// If no matching value can be found, the non-localized value is returned.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="culture">The culture (typically <see cref="CultureInfo.CurrentUICulture"/>).</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the matching localized description associated with the scope.
        /// </returns>
        ValueTask<string> GetLocalizedDescriptionAsync(object scope, CultureInfo culture, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves the localized display name associated with an scope
        /// and corresponding to the current UI culture or one of its parents.
        /// If no matching value can be found, the non-localized value is returned.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the display name associated with the scope.
        /// </returns>
        ValueTask<string> GetLocalizedDisplayNameAsync(object scope, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves the localized display name associated with an scope
        /// and corresponding to the specified culture or one of its parents.
        /// If no matching value can be found, the non-localized value is returned.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="culture">The culture (typically <see cref="CultureInfo.CurrentUICulture"/>).</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the display name associated with the scope.
        /// </returns>
        ValueTask<string> GetLocalizedDisplayNameAsync(object scope, CultureInfo culture, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves the name associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the name associated with the specified scope.
        /// </returns>
        ValueTask<string> GetNameAsync(object scope, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves the resources associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the resources associated with the scope.
        /// </returns>
        ValueTask<ImmutableArray<string>> GetResourcesAsync(object scope, CancellationToken cancellationToken = default);

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <param name="count">The number of results to return.</param>
        /// <param name="offset">The number of results to skip.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>All the elements returned when executing the specified query.</returns>
        IAsyncEnumerable<object> ListAsync(
            int? count = null, int? offset = null, CancellationToken cancellationToken = default);

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>All the elements returned when executing the specified query.</returns>
        IAsyncEnumerable<TResult> ListAsync<TResult>(
            Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken = default);

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <typeparam name="TState">The state type.</typeparam>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="state">The optional state.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>All the elements returned when executing the specified query.</returns>
        IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
            Func<IQueryable<object>, TState, IQueryable<TResult>> query,
            TState state, CancellationToken cancellationToken = default);

        /// <summary>
        /// Lists all the resources associated with the specified scopes.
        /// </summary>
        /// <param name="scopes">The scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>All the resources associated with the specified scopes.</returns>
        IAsyncEnumerable<string> ListResourcesAsync(ImmutableArray<string> scopes, CancellationToken cancellationToken = default);

        /// <summary>
        /// Populates the specified descriptor using the properties exposed by the scope.
        /// </summary>
        /// <param name="descriptor">The descriptor.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        ValueTask PopulateAsync(OpenIddictScopeDescriptor descriptor, object scope, CancellationToken cancellationToken = default);

        /// <summary>
        /// Populates the scope using the specified descriptor.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="descriptor">The descriptor.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        ValueTask PopulateAsync(object scope, OpenIddictScopeDescriptor descriptor, CancellationToken cancellationToken = default);

        /// <summary>
        /// Updates an existing scope.
        /// </summary>
        /// <param name="scope">The scope to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        ValueTask UpdateAsync(object scope, CancellationToken cancellationToken = default);

        /// <summary>
        /// Updates an existing scope.
        /// </summary>
        /// <param name="scope">The scope to update.</param>
        /// <param name="descriptor">The descriptor used to update the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        ValueTask UpdateAsync(object scope, OpenIddictScopeDescriptor descriptor, CancellationToken cancellationToken = default);

        /// <summary>
        /// Validates the scope to ensure it's in a consistent state.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>The validation error encountered when validating the scope.</returns>
        IAsyncEnumerable<ValidationResult> ValidateAsync(object scope, CancellationToken cancellationToken = default);
    }
}
