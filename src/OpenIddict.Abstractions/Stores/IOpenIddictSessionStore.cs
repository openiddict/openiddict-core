/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to manage the sessions stored in a database.
/// </summary>
/// <typeparam name="TSession">The type of the session entity.</typeparam>
public interface IOpenIddictSessionStore<TSession> where TSession : class
{
    /// <summary>
    /// Determines the number of sessions that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of sessions in the database.
    /// </returns>
    ValueTask<long> CountAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Determines the number of sessions that match the specified query.
    /// </summary>
    /// <typeparam name="TState">The state type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="state">The optional state.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of sessions that match the specified query.
    /// </returns>
    ValueTask<long> CountAsync<TState, TResult>(
        Func<IQueryable<TSession>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken);

    /// <summary>
    /// Creates a new session.
    /// </summary>
    /// <param name="session">The session to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask CreateAsync(TSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Removes an existing session.
    /// </summary>
    /// <param name="session">The session to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask DeleteAsync(TSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the sessions matching the specified query.
    /// </summary>
    /// <param name="query">The query parameters: if a parameter is <see langword="null"/>, it will not be used to filter the results.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the criteria.</returns>
    IAsyncEnumerable<TSession> FindAsync(
        (string? Subject, string? LoginId, string? ApplicationId, string? AuthorizationId, string? Status) query, CancellationToken cancellationToken);

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
    /// Retrieves the optional application identifier associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the application identifier associated with the session.
    /// </returns>
    ValueTask<string?> GetApplicationIdAsync(TSession session, CancellationToken cancellationToken);

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
        Func<IQueryable<TSession>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the optional authorization identifier associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the authorization identifier associated with the session.
    /// </returns>
    ValueTask<string?> GetAuthorizationIdAsync(TSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the creation date associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the creation date associated with the specified session.
    /// </returns>
    ValueTask<DateTimeOffset?> GetCreationDateAsync(TSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the unique identifier associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the session.
    /// </returns>
    ValueTask<string?> GetIdAsync(TSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the login identifier associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the login identifier associated with the specified session.
    /// </returns>
    ValueTask<string?> GetLoginIdAsync(TSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the additional properties associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation, whose
    /// result returns all the additional properties associated with the session.
    /// </returns>
    ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the status associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the status associated with the specified session.
    /// </returns>
    ValueTask<string?> GetStatusAsync(TSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the subject associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the subject associated with the specified session.
    /// </returns>
    ValueTask<string?> GetSubjectAsync(TSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Instantiates a new session.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the instantiated session, that can be persisted in the database.
    /// </returns>
    ValueTask<TSession> InstantiateAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    IAsyncEnumerable<TSession> ListAsync(int? count, int? offset, CancellationToken cancellationToken);

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
        Func<IQueryable<TSession>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken);

    /// <summary>
    /// Removes the sessions that are marked as invalid and don't have any token attached.
    /// Only sessions created before the specified <paramref name="threshold"/> are removed.
    /// </summary>
    /// <remarks>
    /// Since sessions with tokens still attached are not deleted, tokens should always be pruned first.
    /// </remarks>
    /// <param name="threshold">The date before which sessions are not pruned.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of sessions that were removed.</returns>
    ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the application identifier associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="identifier">The unique identifier associated with the session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetApplicationIdAsync(TSession session, string? identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the authorization identifier associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="identifier">The unique identifier associated with the session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetAuthorizationIdAsync(TSession session, string? identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the creation date associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="date">The creation date.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetCreationDateAsync(TSession session, DateTimeOffset? date, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the login identifier associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="identifier">The login identifier associated with the session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetLoginIdAsync(TSession session, string? identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the additional properties associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="properties">The additional properties associated with the session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetPropertiesAsync(TSession session,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the status associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="status">The status associated with the session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetStatusAsync(TSession session, string? status, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the subject associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="subject">The subject associated with the session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetSubjectAsync(TSession session, string? subject, CancellationToken cancellationToken);

    /// <summary>
    /// Updates an existing session.
    /// </summary>
    /// <param name="session">The session to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask UpdateAsync(TSession session, CancellationToken cancellationToken);
}
