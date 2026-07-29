/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to manage the Resources stored in the store.
/// </summary>
/// <remarks>
/// Note: this interface is not meant to be implemented by custom managers,
/// that should inherit from the generic OpenIddictResourceManager class.
/// It is primarily intended to be used by services that cannot easily
/// depend on the generic resource manager. The actual resource entity type is
/// automatically determined at runtime based on the OpenIddict core options.
/// </remarks>
public interface IOpenIddictResourceManager
{
    /// <summary>
    /// Determines the number of resources that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of resources in the database.
    /// </returns>
    ValueTask<long> CountAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines the number of resources that match the specified query.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of resources that match the specified query.
    /// </returns>
    ValueTask<long> CountAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines the number of resources that match the specified query.
    /// </summary>
    /// <typeparam name="TState">The state type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="state">The optional state.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of resources that match the specified query.
    /// </returns>
    ValueTask<long> CountAsync<TState, TResult>(
        Func<IQueryable<object>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new resource based on the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The resource descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation, whose result returns the resource.
    /// </returns>
    ValueTask<object> CreateAsync(OpenIddictResourceDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new resource.
    /// </summary>
    /// <param name="resource">The resource to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask CreateAsync(object resource, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes an existing resource.
    /// </summary>
    /// <param name="resource">The resource to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask DeleteAsync(object resource, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a resource using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the resource corresponding to the identifier.
    /// </returns>
    ValueTask<object?> FindByIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a resource using its name.
    /// </summary>
    /// <param name="name">The name associated with the resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the resource corresponding to the specified name.
    /// </returns>
    ValueTask<object?> FindByNameAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a list of resources using their name.
    /// </summary>
    /// <param name="names">The names associated with the resources.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The resources corresponding to the specified names.</returns>
    IAsyncEnumerable<object> FindByNamesAsync(ImmutableArray<string> names, CancellationToken cancellationToken = default);

    /// <summary>
    /// Executes the specified query and returns the first element.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the first element returned when executing the query.
    /// </returns>
    ValueTask<TResult?> GetAsync<TResult>(
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
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the first element returned when executing the query.
    /// </returns>
    ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<object>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the description associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the description associated with the specified resource.
    /// </returns>
    ValueTask<string?> GetDescriptionAsync(object resource, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the localized descriptions associated with an resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the localized descriptions associated with the resource.
    /// </returns>
    ValueTask<ImmutableDictionary<CultureInfo, string>> GetDescriptionsAsync(object resource, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the display name associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the display name associated with the resource.
    /// </returns>
    ValueTask<string?> GetDisplayNameAsync(object resource, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the localized display names associated with an resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the localized display names associated with the resource.
    /// </returns>
    ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(object resource, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the unique identifier associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the resource.
    /// </returns>
    ValueTask<string?> GetIdAsync(object resource, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the localized description associated with an resource
    /// and corresponding to the current UI culture or one of its parents.
    /// If no matching value can be found, the non-localized value is returned.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the matching localized description associated with the resource.
    /// </returns>
    ValueTask<string?> GetLocalizedDescriptionAsync(object resource, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the localized description associated with an resource
    /// and corresponding to the specified culture or one of its parents.
    /// If no matching value can be found, the non-localized value is returned.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="culture">The culture (typically <see cref="CultureInfo.CurrentUICulture"/>).</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the matching localized description associated with the resource.
    /// </returns>
    ValueTask<string?> GetLocalizedDescriptionAsync(object resource, CultureInfo culture, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the localized display name associated with an resource
    /// and corresponding to the current UI culture or one of its parents.
    /// If no matching value can be found, the non-localized value is returned.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the display name associated with the resource.
    /// </returns>
    ValueTask<string?> GetLocalizedDisplayNameAsync(object resource, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the localized display name associated with an resource
    /// and corresponding to the specified culture or one of its parents.
    /// If no matching value can be found, the non-localized value is returned.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="culture">The culture (typically <see cref="CultureInfo.CurrentUICulture"/>).</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the display name associated with the resource.
    /// </returns>
    ValueTask<string?> GetLocalizedDisplayNameAsync(object resource, CultureInfo culture, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the name associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the name associated with the specified resource.
    /// </returns>
    ValueTask<string?> GetNameAsync(object resource, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the additional properties associated with a resource.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the additional properties associated with the resource.
    /// </returns>
    ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(object resource, CancellationToken cancellationToken = default);

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
    /// Populates the specified descriptor using the properties exposed by the resource.
    /// </summary>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask PopulateAsync(OpenIddictResourceDescriptor descriptor, object resource, CancellationToken cancellationToken = default);

    /// <summary>
    /// Populates the resource using the specified descriptor.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask PopulateAsync(object resource, OpenIddictResourceDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing resource.
    /// </summary>
    /// <param name="resource">The resource to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask UpdateAsync(object resource, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing resource.
    /// </summary>
    /// <param name="resource">The resource to update.</param>
    /// <param name="descriptor">The descriptor used to update the resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask UpdateAsync(object resource, OpenIddictResourceDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates the resource to ensure it's in a consistent state.
    /// </summary>
    /// <param name="resource">The resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation error encountered when validating the resource.</returns>
    IAsyncEnumerable<ValidationResult> ValidateAsync(object resource, CancellationToken cancellationToken = default);
}
