/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to cache sessions after retrieving them from the store.
/// </summary>
/// <typeparam name="TSession">The type of the session entity.</typeparam>
public interface IOpenIddictSessionCache<TSession> where TSession : class
{
    /// <summary>
    /// Add the specified session to the cache.
    /// </summary>
    /// <param name="session">The session to add to the cache.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask AddAsync(TSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the sessions matching the specified query.
    /// </summary>
    /// <param name="query">The query parameters: if a parameter is <see langword="null"/>, it will not be used to filter the results.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the criteria.</returns>
    IAsyncEnumerable<TSession> FindAsync(
        (string? Subject, string? LoginId, string? ApplicationId, string? Status) query, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the list of sessions corresponding to the specified application identifier.
    /// </summary>
    /// <param name="identifier">The application identifier associated with the sessions.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the specified application.</returns>
    IAsyncEnumerable<TSession> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the list of sessions corresponding to the specified authorization identifier.
    /// </summary>
    /// <param name="identifier">The authorization identifier associated with the sessions.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the specified authorization.</returns>
    IAsyncEnumerable<TSession> FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the list of sessions corresponding to the specified login identifier.
    /// </summary>
    /// <param name="identifier">The login identifier associated with the sessions.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the specified login identifier.</returns>
    IAsyncEnumerable<TSession> FindByLoginIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves a session using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the session corresponding to the identifier.
    /// </returns>
    ValueTask<TSession?> FindByIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the list of sessions corresponding to the specified subject.
    /// </summary>
    /// <param name="subject">The subject associated with the sessions.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the specified subject.</returns>
    IAsyncEnumerable<TSession> FindBySubjectAsync(string subject, CancellationToken cancellationToken);

    /// <summary>
    /// Removes the specified session from the cache.
    /// </summary>
    /// <param name="session">The session to remove from the cache.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask RemoveAsync(TSession session, CancellationToken cancellationToken);
}
