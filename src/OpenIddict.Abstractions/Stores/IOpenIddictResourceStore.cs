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
/// Provides methods allowing to manage the resources stored in a database.
/// </summary>
/// <typeparam name="TResource">The type of the resource entity.</typeparam>
public interface IOpenIddictResourceStore<TResource> where TResource : class
{
    /// <summary>
    /// Determines the number of resources that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of resources in the database.
    /// </returns>
    ValueTask<long> CountAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Determines the number of resources that match the specified query.
    /// </summary>
    /// <typeparam name="TState">The state type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="state">The optional state.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of resources that match the specified query.
    /// </returns>
    ValueTask<long> CountAsync<TState, TResult>(
        Func<IQueryable<TResource>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken);

    /// <summary>
    /// Creates a new resource.
    /// </summary>
    /// <param name="resource">The resource to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask CreateAsync(TResource resource, CancellationToken cancellationToken);

    /// <summary>
    /// Removes an existing resource.
    /// </summary>
    /// <param name="resource">The resource to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask DeleteAsync(TResource resource, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves a resource using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the resource corresponding to the identifier.
    /// </returns>
    ValueTask<TResource?> FindByIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves a resource using its name.
    /// </summary>
    /// <param name="name">The name associated with the resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the resource corresponding to the specified name.
    /// </returns>
    ValueTask<TResource?> FindByNameAsync(string name, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves a list of resources using their name.
    /// </summary>
    /// <param name="names">The names associated with the resources.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The resources corresponding to the specified names.</returns>
    IAsyncEnumerable<TResource> FindByNamesAsync(ImmutableArray<string> names, CancellationToken cancellationToken);

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
        Func<IQueryable<TResource>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the description associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the description associated with the specified resource.
    /// </returns>
    ValueTask<string?> GetDescriptionAsync(TResource resource, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the localized descriptions associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the localized descriptions associated with the specified resource.
    /// </returns>
    ValueTask<ImmutableDictionary<CultureInfo, string>> GetDescriptionsAsync(TResource resource, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the display name associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the display name associated with the resource.
    /// </returns>
    ValueTask<string?> GetDisplayNameAsync(TResource resource, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the localized display names associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the localized display names associated with the resource.
    /// </returns>
    ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(TResource resource, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the unique identifier associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the resource.
    /// </returns>
    ValueTask<string?> GetIdAsync(TResource resource, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the name associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the name associated with the specified resource.
    /// </returns>
    ValueTask<string?> GetNameAsync(TResource resource, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the additional properties associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation, whose
    /// result returns all the additional properties associated with the resource.
    /// </returns>
    ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TResource resource, CancellationToken cancellationToken);

    /// <summary>
    /// Instantiates a new resource.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the instantiated resource, that can be persisted in the database.
    /// </returns>
    ValueTask<TResource> InstantiateAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    IAsyncEnumerable<TResource> ListAsync(int? count, int? offset, CancellationToken cancellationToken);

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
        Func<IQueryable<TResource>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the description associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="description">The description associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetDescriptionAsync(TResource resource, string? description, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the localized descriptions associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="descriptions">The localized descriptions associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetDescriptionsAsync(TResource resource,
        ImmutableDictionary<CultureInfo, string> descriptions, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the display name associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="name">The display name associated with the resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetDisplayNameAsync(TResource resource, string? name, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the localized display names associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="names">The localized display names associated with the resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetDisplayNamesAsync(TResource resource,
        ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the name associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="name">The name associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetNameAsync(TResource resource, string? name, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the additional properties associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="properties">The additional properties associated with the resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetPropertiesAsync(TResource resource,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken);

    /// <summary>
    /// Updates an existing resource.
    /// </summary>
    /// <param name="resource">The resource to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask UpdateAsync(TResource resource, CancellationToken cancellationToken);
}
