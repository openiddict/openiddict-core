/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ValidationException = OpenIddict.Abstractions.OpenIddictExceptions.ValidationException;

namespace OpenIddict.Core;

/// <summary>
/// Provides methods allowing to manage the sessions stored in the store.
/// </summary>
/// <remarks>
/// Applications that do not want to depend on a specific entity type can use the non-generic
/// <see cref="IOpenIddictSessionManager"/> instead, for which the actual entity type is resolved at runtime.
/// </remarks>
/// <typeparam name="TSession">The type of the session entity.</typeparam>
public class OpenIddictSessionManager<TSession> : IOpenIddictSessionManager where TSession : class
{
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictSessionManager{TSession}"/> class.
    /// </summary>
    /// <param name="cache">The cache.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="options">The options.</param>
    /// <param name="store">The store.</param>
    public OpenIddictSessionManager(
        IOpenIddictSessionCache<TSession> cache,
        ILogger<OpenIddictSessionManager<TSession>> logger,
        IOptionsMonitor<OpenIddictCoreOptions> options,
        IOpenIddictSessionStore<TSession> store)
    {
        Cache = cache ?? throw new ArgumentNullException(nameof(cache));
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        Options = options ?? throw new ArgumentNullException(nameof(options));
        Store = store ?? throw new ArgumentNullException(nameof(store));
    }

    /// <summary>
    /// Gets the cache associated with the current manager.
    /// </summary>
    protected IOpenIddictSessionCache<TSession> Cache { get; }

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
    protected IOpenIddictSessionStore<TSession> Store { get; }

    /// <summary>
    /// Determines the number of sessions that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of sessions in the database.
    /// </returns>
    public virtual ValueTask<long> CountAsync(CancellationToken cancellationToken = default)
        => Store.CountAsync(cancellationToken);

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
    public virtual ValueTask<long> CountAsync<TResult>(
        Func<IQueryable<TSession>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        return CountAsync(static (sessions, query) => query(sessions), query, cancellationToken);
    }

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
    public virtual ValueTask<long> CountAsync<TState, TResult>(
        Func<IQueryable<TSession>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        return Store.CountAsync(query, state, cancellationToken);
    }

    /// <summary>
    /// Creates a new session.
    /// </summary>
    /// <param name="session">The session to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask CreateAsync(TSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        // If no status was explicitly specified, assume that the session is valid.
        if (string.IsNullOrEmpty(await Store.GetStatusAsync(session, cancellationToken)))
        {
            await Store.SetStatusAsync(session, Statuses.Valid, cancellationToken);
        }

        // If no creation date was explicitly specified, set it to the current time.
        if (await Store.GetCreationDateAsync(session, cancellationToken) is null)
        {
            await Store.SetCreationDateAsync(session, Options.CurrentValue.TimeProvider.GetUtcNow(), cancellationToken);
        }

        var results = await GetValidationResultsAsync(session, cancellationToken);
        if (results.Any(static result => result != ValidationResult.Success))
        {
            var builder = new StringBuilder();
            builder.AppendLine(SR.GetResourceString(SR.ID0207));
            builder.AppendLine();

            foreach (var result in results)
            {
                builder.AppendLine(result.ErrorMessage);
            }

            throw new ValidationException(builder.ToString(), results);
        }

        await Store.CreateAsync(session, cancellationToken);

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.AddAsync(session, cancellationToken);
        }

        async Task<ImmutableArray<ValidationResult>> GetValidationResultsAsync(
            TSession session, CancellationToken cancellationToken)
        {
            var builder = ImmutableArray.CreateBuilder<ValidationResult>();

            await foreach (var result in ValidateAsync(session, cancellationToken))
            {
                builder.Add(result);
            }

            return builder.ToImmutable();
        }
    }

    /// <summary>
    /// Creates a new session based on the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The session descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation, whose result returns the session.
    /// </returns>
    public virtual async ValueTask<TSession> CreateAsync(
        OpenIddictSessionDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);

        var session = await Store.InstantiateAsync(cancellationToken)
            ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0208));

        await PopulateAsync(session, descriptor, cancellationToken);
        await CreateAsync(session, cancellationToken);

        return session;
    }

    /// <summary>
    /// Removes an existing session.
    /// </summary>
    /// <param name="session">The session to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask DeleteAsync(TSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.RemoveAsync(session, cancellationToken);
        }

        await Store.DeleteAsync(session, cancellationToken);
    }

    /// <summary>
    /// Retrieves the sessions matching the specified query.
    /// </summary>
    /// <param name="query">The query parameters: if a parameter is <see langword="null"/>, it will not be used to filter the results.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the criteria.</returns>
    public virtual IAsyncEnumerable<TSession> FindAsync(
        (string? Subject, string? LoginId, string? ApplicationId, string? AuthorizationId, string? Status) query,
        CancellationToken cancellationToken = default)
    {
        var sessions = Options.CurrentValue.DisableEntityCaching
            ? Store.FindAsync(query, cancellationToken)
            : Cache.FindAsync(query, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return sessions;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var session in sessions.WithCancellation(cancellationToken))
            {
                if (string.IsNullOrEmpty(query.Subject) ||
                    string.Equals(await Store.GetSubjectAsync(session, cancellationToken), query.Subject, StringComparison.Ordinal))
                {
                    yield return session;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves the list of sessions corresponding to the specified application identifier.
    /// </summary>
    /// <param name="identifier">The application identifier associated with the sessions.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the specified application.</returns>
    public virtual IAsyncEnumerable<TSession> FindByApplicationIdAsync(
        string identifier, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var sessions = Options.CurrentValue.DisableEntityCaching
            ? Store.FindByApplicationIdAsync(identifier, cancellationToken)
            : Cache.FindByApplicationIdAsync(identifier, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return sessions;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var session in sessions.WithCancellation(cancellationToken))
            {
                if (string.Equals(await Store.GetApplicationIdAsync(session, cancellationToken), identifier, StringComparison.Ordinal))
                {
                    yield return session;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves the list of sessions corresponding to the specified authorization identifier.
    /// </summary>
    /// <param name="identifier">The authorization identifier associated with the sessions.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the specified authorization.</returns>
    public virtual IAsyncEnumerable<TSession> FindByAuthorizationIdAsync(
        string identifier, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var sessions = Options.CurrentValue.DisableEntityCaching
            ? Store.FindByAuthorizationIdAsync(identifier, cancellationToken)
            : Cache.FindByAuthorizationIdAsync(identifier, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return sessions;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var session in sessions.WithCancellation(cancellationToken))
            {
                if (string.Equals(await Store.GetAuthorizationIdAsync(session, cancellationToken), identifier, StringComparison.Ordinal))
                {
                    yield return session;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves a session using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the session corresponding to the identifier.
    /// </returns>
    public virtual async ValueTask<TSession?> FindByIdAsync(string identifier, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var session = Options.CurrentValue.DisableEntityCaching
            ? await Store.FindByIdAsync(identifier, cancellationToken)
            : await Cache.FindByIdAsync(identifier, cancellationToken);

        if (session is null)
        {
            return null;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.
        if (!Options.CurrentValue.DisableAdditionalFiltering &&
            !string.Equals(await Store.GetIdAsync(session, cancellationToken), identifier, StringComparison.Ordinal))
        {
            return null;
        }

        return session;
    }

    /// <summary>
    /// Retrieves the list of sessions corresponding to the specified login identifier.
    /// </summary>
    /// <param name="identifier">The login identifier associated with the sessions.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the specified login identifier.</returns>
    public virtual IAsyncEnumerable<TSession> FindByLoginIdAsync(string identifier, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var sessions = Options.CurrentValue.DisableEntityCaching
            ? Store.FindByLoginIdAsync(identifier, cancellationToken)
            : Cache.FindByLoginIdAsync(identifier, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return sessions;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var session in sessions.WithCancellation(cancellationToken))
            {
                if (string.Equals(await Store.GetLoginIdAsync(session, cancellationToken), identifier, StringComparison.Ordinal))
                {
                    yield return session;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves the list of sessions corresponding to the specified subject.
    /// </summary>
    /// <param name="subject">The subject associated with the sessions.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions corresponding to the specified subject.</returns>
    public virtual IAsyncEnumerable<TSession> FindBySubjectAsync(
        string subject, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        var sessions = Options.CurrentValue.DisableEntityCaching
            ? Store.FindBySubjectAsync(subject, cancellationToken)
            : Cache.FindBySubjectAsync(subject, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return sessions;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var session in sessions.WithCancellation(cancellationToken))
            {
                if (string.Equals(await Store.GetSubjectAsync(session, cancellationToken), subject, StringComparison.Ordinal))
                {
                    yield return session;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves the optional application identifier associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the application identifier associated with the session.
    /// </returns>
    public virtual ValueTask<string?> GetApplicationIdAsync(TSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        return Store.GetApplicationIdAsync(session, cancellationToken);
    }

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
    public virtual ValueTask<TResult?> GetAsync<TResult>(
        Func<IQueryable<TSession>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        return GetAsync(static (sessions, query) => query(sessions), query, cancellationToken);
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
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the first element returned when executing the query.
    /// </returns>
    public virtual ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TSession>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        return Store.GetAsync(query, state, cancellationToken);
    }

    /// <summary>
    /// Retrieves the optional authorization identifier associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the authorization identifier associated with the session.
    /// </returns>
    public virtual ValueTask<string?> GetAuthorizationIdAsync(TSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        return Store.GetAuthorizationIdAsync(session, cancellationToken);
    }

    /// <summary>
    /// Retrieves the creation date associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the creation date associated with the specified session.
    /// </returns>
    public virtual ValueTask<DateTimeOffset?> GetCreationDateAsync(TSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        return Store.GetCreationDateAsync(session, cancellationToken);
    }

    /// <summary>
    /// Retrieves the unique identifier associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the session.
    /// </returns>
    public virtual ValueTask<string?> GetIdAsync(TSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        return Store.GetIdAsync(session, cancellationToken);
    }

    /// <summary>
    /// Retrieves the login identifier associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the login identifier associated with the specified session.
    /// </returns>
    public virtual ValueTask<string?> GetLoginIdAsync(TSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        return Store.GetLoginIdAsync(session, cancellationToken);
    }

    /// <summary>
    /// Retrieves the additional properties associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the additional properties associated with the session.
    /// </returns>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(
        TSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        return Store.GetPropertiesAsync(session, cancellationToken);
    }

    /// <summary>
    /// Retrieves the status associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the status associated with the specified session.
    /// </returns>
    public virtual ValueTask<string?> GetStatusAsync(TSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        return Store.GetStatusAsync(session, cancellationToken);
    }

    /// <summary>
    /// Retrieves the subject associated with a session.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the subject associated with the specified session.
    /// </returns>
    public virtual ValueTask<string?> GetSubjectAsync(TSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        return Store.GetSubjectAsync(session, cancellationToken);
    }

    /// <summary>
    /// Determines whether a given session has the specified status.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="status">The expected status.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the session has the specified status, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> HasStatusAsync(TSession session, string status, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentException.ThrowIfNullOrEmpty(status);

        return string.Equals(await GetStatusAsync(session, cancellationToken), status, StringComparison.Ordinal);
    }

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    public virtual IAsyncEnumerable<TSession> ListAsync(
        int? count = null, int? offset = null, CancellationToken cancellationToken = default)
        => Store.ListAsync(count, offset, cancellationToken);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    public virtual IAsyncEnumerable<TResult> ListAsync<TResult>(
        Func<IQueryable<TSession>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        return ListAsync(static (sessions, query) => query(sessions), query, cancellationToken);
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
        Func<IQueryable<TSession>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        return Store.ListAsync(query, state, cancellationToken);
    }

    /// <summary>
    /// Populates the session using the specified descriptor.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask PopulateAsync(TSession session,
        OpenIddictSessionDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(descriptor);

        await Store.SetApplicationIdAsync(session, descriptor.ApplicationId, cancellationToken);
        await Store.SetAuthorizationIdAsync(session, descriptor.AuthorizationId, cancellationToken);
        await Store.SetCreationDateAsync(session, descriptor.CreationDate, cancellationToken);
        await Store.SetLoginIdAsync(session, descriptor.LoginId, cancellationToken);
        await Store.SetPropertiesAsync(session, [.. descriptor.Properties], cancellationToken);
        await Store.SetStatusAsync(session, descriptor.Status, cancellationToken);
        await Store.SetSubjectAsync(session, descriptor.Subject, cancellationToken);
    }

    /// <summary>
    /// Populates the specified descriptor using the properties exposed by the session.
    /// </summary>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask PopulateAsync(
        OpenIddictSessionDescriptor descriptor,
        TSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(session);

        descriptor.ApplicationId = await Store.GetApplicationIdAsync(session, cancellationToken);
        descriptor.AuthorizationId = await Store.GetAuthorizationIdAsync(session, cancellationToken);
        descriptor.CreationDate = await Store.GetCreationDateAsync(session, cancellationToken);
        descriptor.LoginId = await Store.GetLoginIdAsync(session, cancellationToken);
        descriptor.Status = await Store.GetStatusAsync(session, cancellationToken);
        descriptor.Subject = await Store.GetSubjectAsync(session, cancellationToken);

        descriptor.Properties.Clear();
        foreach (var pair in await Store.GetPropertiesAsync(session, cancellationToken))
        {
            descriptor.Properties.Add(pair.Key, pair.Value);
        }
    }

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
    public virtual ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
        => Store.PruneAsync(threshold, cancellationToken);

    /// <summary>
    /// Updates an existing session.
    /// </summary>
    /// <param name="session">The session to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask UpdateAsync(TSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        var results = await GetValidationResultsAsync(session, cancellationToken);
        if (results.Any(static result => result != ValidationResult.Success))
        {
            var builder = new StringBuilder();
            builder.AppendLine(SR.GetResourceString(SR.ID0215));
            builder.AppendLine();

            foreach (var result in results)
            {
                builder.AppendLine(result.ErrorMessage);
            }

            throw new ValidationException(builder.ToString(), results);
        }

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.RemoveAsync(session, cancellationToken);
        }

        await Store.UpdateAsync(session, cancellationToken);

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.AddAsync(session, cancellationToken);
        }

        async Task<ImmutableArray<ValidationResult>> GetValidationResultsAsync(
            TSession session, CancellationToken cancellationToken)
        {
            var builder = ImmutableArray.CreateBuilder<ValidationResult>();

            await foreach (var result in ValidateAsync(session, cancellationToken))
            {
                builder.Add(result);
            }

            return builder.ToImmutable();
        }
    }

    /// <summary>
    /// Updates an existing session.
    /// </summary>
    /// <param name="session">The session to update.</param>
    /// <param name="descriptor">The descriptor used to update the session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask UpdateAsync(TSession session,
        OpenIddictSessionDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(descriptor);

        await PopulateAsync(session, descriptor, cancellationToken);
        await UpdateAsync(session, cancellationToken);
    }

    /// <summary>
    /// Validates the session to ensure it's in a consistent state.
    /// </summary>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation error encountered when validating the session.</returns>
    public virtual IAsyncEnumerable<ValidationResult> ValidateAsync(TSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<ValidationResult> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(await Store.GetStatusAsync(session, cancellationToken)))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2038));
            }

            if (string.IsNullOrEmpty(await Store.GetLoginIdAsync(session, cancellationToken)))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2209));
            }
        }
    }

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictSessionManager.CountAsync(CancellationToken cancellationToken)
        => CountAsync(cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictSessionManager.CountAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => CountAsync(query, cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictSessionManager.CountAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken)
        => CountAsync(query, state, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object> IOpenIddictSessionManager.CreateAsync(OpenIddictSessionDescriptor descriptor, CancellationToken cancellationToken)
        => await CreateAsync(descriptor, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictSessionManager.CreateAsync(object session, CancellationToken cancellationToken)
        => CreateAsync((TSession) session, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictSessionManager.DeleteAsync(object session, CancellationToken cancellationToken)
        => DeleteAsync((TSession) session, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictSessionManager.FindAsync((string? Subject, string? LoginId, string? ApplicationId, string? AuthorizationId, string? Status) query, CancellationToken cancellationToken)
        => FindAsync(query, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictSessionManager.FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
        => FindByApplicationIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictSessionManager.FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
        => FindByAuthorizationIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object?> IOpenIddictSessionManager.FindByIdAsync(string identifier, CancellationToken cancellationToken)
        => await FindByIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictSessionManager.FindByLoginIdAsync(string identifier, CancellationToken cancellationToken)
        => FindByLoginIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictSessionManager.FindBySubjectAsync(string subject, CancellationToken cancellationToken)
       => FindBySubjectAsync(subject, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictSessionManager.GetApplicationIdAsync(object session, CancellationToken cancellationToken)
        => GetApplicationIdAsync((TSession) session, cancellationToken);

    /// <inheritdoc/>
    ValueTask<TResult?> IOpenIddictSessionManager.GetAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken) where TResult : default
        => GetAsync(query, cancellationToken);

    /// <inheritdoc/>
    ValueTask<TResult?> IOpenIddictSessionManager.GetAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) where TResult : default
        => GetAsync(query, state, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictSessionManager.GetAuthorizationIdAsync(object session, CancellationToken cancellationToken)
        => GetAuthorizationIdAsync((TSession) session, cancellationToken);

    /// <inheritdoc/>
    ValueTask<DateTimeOffset?> IOpenIddictSessionManager.GetCreationDateAsync(object session, CancellationToken cancellationToken)
        => GetCreationDateAsync((TSession) session, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictSessionManager.GetIdAsync(object session, CancellationToken cancellationToken)
        => GetIdAsync((TSession) session, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictSessionManager.GetLoginIdAsync(object session, CancellationToken cancellationToken)
        => GetLoginIdAsync((TSession) session, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableDictionary<string, JsonElement>> IOpenIddictSessionManager.GetPropertiesAsync(object session, CancellationToken cancellationToken)
        => GetPropertiesAsync((TSession) session, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictSessionManager.GetStatusAsync(object session, CancellationToken cancellationToken)
        => GetStatusAsync((TSession) session, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictSessionManager.GetSubjectAsync(object session, CancellationToken cancellationToken)
        => GetSubjectAsync((TSession) session, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictSessionManager.HasStatusAsync(object session, string status, CancellationToken cancellationToken)
        => HasStatusAsync((TSession) session, status, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictSessionManager.ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        => ListAsync(count, offset, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<TResult> IOpenIddictSessionManager.ListAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => ListAsync(query, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<TResult> IOpenIddictSessionManager.ListAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken)
        => ListAsync(query, state, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictSessionManager.PopulateAsync(OpenIddictSessionDescriptor descriptor, object session, CancellationToken cancellationToken)
        => PopulateAsync(descriptor, (TSession) session, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictSessionManager.PopulateAsync(object session, OpenIddictSessionDescriptor descriptor, CancellationToken cancellationToken)
        => PopulateAsync((TSession) session, descriptor, cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictSessionManager.PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
        => PruneAsync(threshold, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictSessionManager.UpdateAsync(object session, CancellationToken cancellationToken)
        => UpdateAsync((TSession) session, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictSessionManager.UpdateAsync(object session, OpenIddictSessionDescriptor descriptor, CancellationToken cancellationToken)
        => UpdateAsync((TSession) session, descriptor, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<ValidationResult> IOpenIddictSessionManager.ValidateAsync(object session, CancellationToken cancellationToken)
        => ValidateAsync((TSession) session, cancellationToken);
}
