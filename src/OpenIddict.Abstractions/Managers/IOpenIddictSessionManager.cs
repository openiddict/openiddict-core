/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to manage the sessions stored in the store.
/// </summary>
/// <remarks>
/// Note: this interface is not meant to be implemented by custom managers,
/// that should inherit from the generic class. It is primarily intended to
/// be used by services that cannot easily depend on the generic manager.
/// </remarks>
public interface IOpenIddictSessionManager
{
    /// <summary>
    /// Determines the number of sessions that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of sessions in the database.
    /// </returns>
    ValueTask<long> CountAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines the number of sessions that match the specified query.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of sessions that match the specified query.
    /// </returns>
    ValueTask<long> CountAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken = default);

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
        Func<IQueryable<object>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new session based on the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The session descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation, whose result returns the session.
    /// </returns>
    ValueTask<object> CreateAsync(OpenIddictSessionDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new session.
    /// </summary>
    /// <param name="session">The session to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask CreateAsync(object session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes an existing session.
    /// </summary>
    /// <param name="session">The session to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask DeleteAsync(object session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the sessions matching the specified query.
    /// </summary>
    /// <param name="query">The query parameters: if a parameter is <see langword="null"/>, it will not be used to filter the results.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the criteria.</returns>
    IAsyncEnumerable<object> FindAsync(
        (string? Subject, string? LoginId, string? ApplicationId, string? AuthorizationId, string? Status) query,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the list of sessions corresponding to the specified application identifier.
    /// </summary>
    /// <param name="identifier">The application identifier associated with the sessions.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the specified application.</returns>
    IAsyncEnumerable<object> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the list of sessions corresponding to the specified authorization identifier.
    /// </summary>
    /// <param name="identifier">The authorization identifier associated with the sessions.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the specified authorization.</returns>
    IAsyncEnumerable<object> FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the list of sessions corresponding to the specified login identifier.
    /// </summary>
    /// <param name="identifier">The login identifier associated with the sessions.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the specified login identifier.</returns>
    IAsyncEnumerable<object> FindByLoginIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a session using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the session corresponding to the identifier.
    /// </returns>
    ValueTask<object?> FindByIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the list of sessions corresponding to the specified subject.
    /// </summary>
    /// <param name="subject">The subject associated with the sessions.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the specified subject.</returns>
    IAsyncEnumerable<object> FindBySubjectAsync(string subject, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the optional application identifier associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the application identifier associated with the session.
    /// </returns>
    ValueTask<string?> GetApplicationIdAsync(object session, CancellationToken cancellationToken = default);

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
    /// Retrieves the optional authorization identifier associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the authorization identifier associated with the session.
    /// </returns>
    ValueTask<string?> GetAuthorizationIdAsync(object session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the creation date associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the creation date associated with the specified session.
    /// </returns>
    ValueTask<DateTimeOffset?> GetCreationDateAsync(object session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the unique identifier associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the session.
    /// </returns>
    ValueTask<string?> GetIdAsync(object session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the login identifier associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the login identifier associated with the specified session.
    /// </returns>
    ValueTask<string?> GetLoginIdAsync(object session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the additional properties associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the additional properties associated with the session.
    /// </returns>
    ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(object session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the status associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the status associated with the specified session.
    /// </returns>
    ValueTask<string?> GetStatusAsync(object session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the subject associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the subject associated with the specified session.
    /// </returns>
    ValueTask<string?> GetSubjectAsync(object session, CancellationToken cancellationToken = default);

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
    /// Populates the specified descriptor using the properties exposed by the session.
    /// </summary>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask PopulateAsync(OpenIddictSessionDescriptor descriptor, object session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Populates the session using the specified descriptor.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask PopulateAsync(object session, OpenIddictSessionDescriptor descriptor, CancellationToken cancellationToken = default);

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
    /// Updates an existing session.
    /// </summary>
    /// <param name="session">The session to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask UpdateAsync(object session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing session.
    /// </summary>
    /// <param name="session">The session to update.</param>
    /// <param name="descriptor">The descriptor used to update the session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask UpdateAsync(object session, OpenIddictSessionDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates the session to ensure it's in a consistent state.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation error encountered when validating the session.</returns>
    IAsyncEnumerable<ValidationResult> ValidateAsync(object session, CancellationToken cancellationToken = default);
}
