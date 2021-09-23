/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to manage the scopes stored in a database.
/// </summary>
/// <typeparam name="TScope">The type of the Scope entity.</typeparam>
public interface IOpenIddictScopeStore<TScope> where TScope : class
{
    /// <summary>
    /// Determines the number of scopes that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of scopes in the database.
    /// </returns>
    ValueTask<long> CountAsync(CancellationToken cancellationToken);

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
    ValueTask<long> CountAsync<TResult>(Func<IQueryable<TScope>, IQueryable<TResult>> query, CancellationToken cancellationToken);

    /// <summary>
    /// Creates a new scope.
    /// </summary>
    /// <param name="scope">The scope to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask CreateAsync(TScope scope, CancellationToken cancellationToken);

    /// <summary>
    /// Removes an existing scope.
    /// </summary>
    /// <param name="scope">The scope to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask DeleteAsync(TScope scope, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves a scope using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the scope corresponding to the identifier.
    /// </returns>
    ValueTask<TScope?> FindByIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves a scope using its name.
    /// </summary>
    /// <param name="name">The name associated with the scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the scope corresponding to the specified name.
    /// </returns>
    ValueTask<TScope?> FindByNameAsync(string name, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves a list of scopes using their name.
    /// </summary>
    /// <param name="names">The names associated with the scopes.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The scopes corresponding to the specified names.</returns>
    IAsyncEnumerable<TScope> FindByNamesAsync(ImmutableArray<string> names, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves all the scopes that contain the specified resource.
    /// </summary>
    /// <param name="resource">The resource associated with the scopes.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The scopes associated with the specified resource.</returns>
    IAsyncEnumerable<TScope> FindByResourceAsync(string resource, CancellationToken cancellationToken);

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
    ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TScope>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the description associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the description associated with the specified scope.
    /// </returns>
    ValueTask<string?> GetDescriptionAsync(TScope scope, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the localized descriptions associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the localized descriptions associated with the specified scope.
    /// </returns>
    ValueTask<ImmutableDictionary<CultureInfo, string>> GetDescriptionsAsync(TScope scope, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the display name associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the display name associated with the scope.
    /// </returns>
    ValueTask<string?> GetDisplayNameAsync(TScope scope, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the localized display names associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the localized display names associated with the scope.
    /// </returns>
    ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(TScope scope, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the unique identifier associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the scope.
    /// </returns>
    ValueTask<string?> GetIdAsync(TScope scope, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the name associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the name associated with the specified scope.
    /// </returns>
    ValueTask<string?> GetNameAsync(TScope scope, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the additional properties associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation, whose
    /// result returns all the additional properties associated with the scope.
    /// </returns>
    ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TScope scope, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the resources associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the resources associated with the scope.
    /// </returns>
    ValueTask<ImmutableArray<string>> GetResourcesAsync(TScope scope, CancellationToken cancellationToken);

    /// <summary>
    /// Instantiates a new scope.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the instantiated scope, that can be persisted in the database.
    /// </returns>
    ValueTask<TScope> InstantiateAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    IAsyncEnumerable<TScope> ListAsync(int? count, int? offset, CancellationToken cancellationToken);

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
        Func<IQueryable<TScope>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the description associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="description">The description associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetDescriptionAsync(TScope scope, string? description, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the localized descriptions associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="descriptions">The localized descriptions associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetDescriptionsAsync(TScope scope,
        ImmutableDictionary<CultureInfo, string> descriptions, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the display name associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="name">The display name associated with the scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetDisplayNameAsync(TScope scope, string? name, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the localized display names associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="names">The localized display names associated with the scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetDisplayNamesAsync(TScope scope,
        ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the name associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="name">The name associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetNameAsync(TScope scope, string? name, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the additional properties associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="properties">The additional properties associated with the scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetPropertiesAsync(TScope scope,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the resources associated with a scope.
    /// </summary>
    /// <param name="scope">The scope.</param>
    /// <param name="resources">The resources associated with the scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetResourcesAsync(TScope scope, ImmutableArray<string> resources, CancellationToken cancellationToken);

    /// <summary>
    /// Updates an existing scope.
    /// </summary>
    /// <param name="scope">The scope to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask UpdateAsync(TScope scope, CancellationToken cancellationToken);
}
