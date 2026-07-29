/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to cache authorizations after retrieving them from the store.
/// </summary>
/// <typeparam name="TAuthorization">The type of the authorization entity.</typeparam>
public interface IOpenIddictAuthorizationCache<TAuthorization> where TAuthorization : class
{
    /// <summary>
    /// Add the specified authorization to the cache.
    /// </summary>
    /// <param name="authorization">The authorization to add to the cache.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask AddAsync(TAuthorization authorization, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the authorizations matching the specified query.
    /// </summary>
    /// <param name="query">The query parameters: if a parameter is <see langword="null"/>, it will not be used to filter the results.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authorizations corresponding to the criteria.</returns>
    IAsyncEnumerable<TAuthorization> FindAsync(
        (string? Subject, string? ApplicationId, string? Status,
         string? Type, ImmutableArray<string>? RequiredScopes) query, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the list of authorizations corresponding to the specified application identifier.
    /// </summary>
    /// <param name="identifier">The application identifier associated with the authorizations.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authorizations corresponding to the specified application.</returns>
    IAsyncEnumerable<TAuthorization> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves an authorization using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the authorization corresponding to the identifier.
    /// </returns>
    ValueTask<TAuthorization?> FindByIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves all the authorizations corresponding to the specified subject.
    /// </summary>
    /// <param name="subject">The subject associated with the authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authorizations corresponding to the specified subject.</returns>
    IAsyncEnumerable<TAuthorization> FindBySubjectAsync(string subject, CancellationToken cancellationToken);

    /// <summary>
    /// Removes the specified authorization from the cache.
    /// </summary>
    /// <param name="authorization">The authorization to remove from the cache.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask RemoveAsync(TAuthorization authorization, CancellationToken cancellationToken);
}
