/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to cache resources after retrieving them from the store.
/// </summary>
/// <typeparam name="TResource">The type of the resource entity.</typeparam>
public interface IOpenIddictResourceCache<TResource> where TResource : class
{
    /// <summary>
    /// Add the specified resource to the cache.
    /// </summary>
    /// <param name="resource">The resource to add to the cache.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask AddAsync(TResource resource, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves a resource using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the resource corresponding to the identifier.
    /// </returns>
    ValueTask<TResource?> FindByIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves a resource using its name.
    /// </summary>
    /// <param name="name">The name associated with the resource.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
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
    /// Removes the specified resource from the cache.
    /// </summary>
    /// <param name="resource">The resource to remove from the cache.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask RemoveAsync(TResource resource, CancellationToken cancellationToken);
}
