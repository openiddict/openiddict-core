/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Data;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.Options;
using OpenIddict.EntityFrameworkCore.Models;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.EntityFrameworkCore;

/// <summary>
/// Provides methods allowing to manage the sessions stored in a database.
/// </summary>
public class OpenIddictEntityFrameworkCoreSessionStore :
    OpenIddictEntityFrameworkCoreSessionStore<OpenIddictEntityFrameworkCoreSession,
                                              OpenIddictEntityFrameworkCoreApplication,
                                              OpenIddictEntityFrameworkCoreAuthorization,
                                              OpenIddictEntityFrameworkCoreToken, string>
{
    public OpenIddictEntityFrameworkCoreSessionStore(
        IOpenIddictEntityFrameworkCoreContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the sessions stored in a database.
/// </summary>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkCoreSessionStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> :
    OpenIddictEntityFrameworkCoreSessionStore<OpenIddictEntityFrameworkCoreSession<TKey>,
                                              OpenIddictEntityFrameworkCoreApplication<TKey>,
                                              OpenIddictEntityFrameworkCoreAuthorization<TKey>,
                                              OpenIddictEntityFrameworkCoreToken<TKey>, TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkCoreSessionStore(
        IOpenIddictEntityFrameworkCoreContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the sessions stored in a database.
/// </summary>
/// <typeparam name="TSession">The type of the session entity.</typeparam>
/// <typeparam name="TApplication">The type of the application entity.</typeparam>
/// <typeparam name="TAuthorization">The type of the authorization entity.</typeparam>
/// <typeparam name="TToken">The type of the token entity.</typeparam>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkCoreSessionStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TSession,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IOpenIddictSessionStore<TSession>
    where TSession : OpenIddictEntityFrameworkCoreSession<TKey, TApplication, TAuthorization, TToken>
    where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TSession, TToken>
    where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TSession, TToken>
    where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization, TSession>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkCoreSessionStore(
        IOpenIddictEntityFrameworkCoreContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
        Options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Gets the database context associated with the current store.
    /// </summary>
    protected IOpenIddictEntityFrameworkCoreContext Context { get; }

    /// <summary>
    /// Gets the options associated with the current store.
    /// </summary>
    protected IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> Options { get; }

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync(CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        return await context.Set<TSession>().LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync<TState, TResult>(
        Func<IQueryable<TSession>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return await query(context.Set<TSession>(), state).LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask CreateAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Add(session);

        await context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        var context = await Context.GetDbContextAsync(cancellationToken);

        // To prevent an SQL exception from being thrown if a new associated entity is
        // created after the existing entries have been listed, the following logic is
        // executed in a serializable transaction, that will lock the affected tables.
        using var transaction = await CreateTransactionAsync(context,
            IsolationLevel.Serializable, cancellationToken);

        // Remove all the tokens associated with the session.
        var tokens = await
            (from token in context.Set<TToken>()
             where token.Authorization == null
             where token.Session!.Id!.Equals(session.Id)
             select token).ToListAsync(cancellationToken);

        foreach (var token in tokens)
        {
            context.Remove(token);
        }

        context.Remove(session);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the updated entities to prevents future calls from failing.
            context.Entry(session).State = EntityState.Unchanged;

            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239), exception);
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TSession> FindAsync(
        (string? Subject, string? LoginId, string? ApplicationId, string? AuthorizationId, string? Status) query,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        IQueryable<TSession> sessions = context.Set<TSession>()
            .Include(static session => session.Application)
            .Include(static session => session.Authorization)
            .AsTracking();

        if (!string.IsNullOrEmpty(query.Subject))
        {
            sessions = sessions.Where(session => session.Subject == query.Subject);
        }

        if (!string.IsNullOrEmpty(query.ApplicationId))
        {
            var key = ConvertIdentifierFromString(query.ApplicationId);
            sessions = sessions.Where(session => session.Application!.Id!.Equals(key));
        }

        if (!string.IsNullOrEmpty(query.AuthorizationId))
        {
            var key = ConvertIdentifierFromString(query.AuthorizationId);
            sessions = sessions.Where(session => session.Authorization!.Id!.Equals(key));
        }

        if (!string.IsNullOrEmpty(query.LoginId))
        {
            sessions = sessions.Where(session => session.LoginId == query.LoginId);
        }

        if (!string.IsNullOrEmpty(query.Status))
        {
            sessions = sessions.Where(session => session.Status == query.Status);
        }

        await foreach (var session in sessions.AsAsyncEnumerable().WithCancellation(cancellationToken))
        {
            yield return session;
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TSession> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);
            var key = ConvertIdentifierFromString(identifier);

            await foreach (var session in
                (from session in context.Set<TSession>()
                    .Include(static session => session.Application)
                    .Include(static session => session.Authorization)
                    .AsTracking()
                 where session.Application!.Id!.Equals(key)
                 select session).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return session;
            }
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TSession> FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);
            var key = ConvertIdentifierFromString(identifier);

            await foreach (var session in
                (from session in context.Set<TSession>()
                    .Include(static session => session.Application)
                    .Include(static session => session.Authorization)
                    .AsTracking()
                 where session.Authorization!.Id!.Equals(key)
                 select session).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return session;
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TSession?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var context = await Context.GetDbContextAsync(cancellationToken);
        var key = ConvertIdentifierFromString(identifier);

        return await context.Set<TSession>().FindAsync([key], cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TSession> FindByLoginIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            await foreach (var session in
                (from session in context.Set<TSession>()
                    .Include(static session => session.Application)
                    .Include(static session => session.Authorization)
                    .AsTracking()
                 where session.LoginId == identifier
                 select session).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return session;
            }
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TSession> FindBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            await foreach (var session in
                (from session in context.Set<TSession>()
                    .Include(static session => session.Application)
                    .Include(static session => session.Authorization)
                    .AsTracking()
                 where session.Subject == subject
                 select session).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return session;
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<string?> GetApplicationIdAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        // If the application is not attached to the session, try to load it manually.
        if (session.Application is null)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            var reference = context.Entry(session).Reference(static entry => entry.Application);
            if (reference.EntityEntry.State is EntityState.Detached)
            {
                return null;
            }

            await reference.LoadAsync(cancellationToken);
        }

        if (session.Application is null)
        {
            return null;
        }

        return ConvertIdentifierToString(session.Application.Id);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TSession>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return await query(context.Set<TSession>().AsTracking(), state).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<string?> GetAuthorizationIdAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        // If the authorization is not attached to the session, try to load it manually.
        if (session.Authorization is null)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            var reference = context.Entry(session).Reference(static entry => entry.Authorization);
            if (reference.EntityEntry.State is EntityState.Detached)
            {
                return null;
            }

            await reference.LoadAsync(cancellationToken);
        }

        if (session.Authorization is null)
        {
            return null;
        }

        return ConvertIdentifierToString(session.Authorization.Id);
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetCreationDateAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return new(session.CreationDate is DateTime date ? new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Utc)) : null);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetIdAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return new(ConvertIdentifierToString(session.Id));
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetLoginIdAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return new(session.LoginId);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return new(session.Properties is { Count: > 0 } properties ? [.. properties] : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetStatusAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return new(session.Status);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetSubjectAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return new(session.Subject);
    }

    /// <inheritdoc/>
    public virtual ValueTask<TSession> InstantiateAsync(CancellationToken cancellationToken)
    {
        try
        {
            return new(Activator.CreateInstance<TSession>());
        }

        catch (MemberAccessException exception)
        {
            return new(Task.FromException<TSession>(
                new InvalidOperationException(SR.GetResourceString(SR.ID0240), exception)));
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TSession> ListAsync(int? count, int? offset,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        var query = context.Set<TSession>().OrderBy(static session => session.Id!).AsTracking();

        if (offset is not null)
        {
            query = query.Skip(offset.Value);
        }

        if (count is not null)
        {
            query = query.Take(count.Value);
        }

        await foreach (var session in query.AsAsyncEnumerable().WithCancellation(cancellationToken))
        {
            yield return session;
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<TSession>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TResult> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            await foreach (var session in query(context.Set<TSession>().AsTracking(), state).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return session;
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        List<Exception>? exceptions = null;

        var result = 0L;

        // Note: the Oracle MySQL provider doesn't support DateTimeOffset and is unable
        // to create a SQL query with an expression calling DateTimeOffset.UtcDateTime.
        // To work around this limitation, the threshold represented as a DateTimeOffset
        // instance is manually converted to a UTC DateTime instance outside the query.
        var date = threshold.UtcDateTime;

        // Note: to avoid sending too many queries, the maximum number of elements
        // that can be removed by a single call to PruneAsync() is deliberately limited.
        for (var index = 0; index < 1_000; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!Options.CurrentValue.DisableBulkOperations)
            {
                try
                {
                    var count = await
                        (from session in context.Set<TSession>()
                         where session.CreationDate < date
                         where session.Status != Statuses.Valid
                         where !session.Tokens.Any()
                         orderby session.Id
                         select session).Take(1_000).ExecuteDeleteAsync(cancellationToken);

                    if (count is 0)
                    {
                        break;
                    }

                    // Note: calling DbContext.SaveChangesAsync() is not necessary
                    // with bulk delete operations as they are executed immediately.

                    result += count;
                }

                catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                {
                    exceptions ??= new List<Exception>(capacity: 1);
                    exceptions.Add(exception);
                }
            }

            else
            {
                var strategy = context.Database.CreateExecutionStrategy();
                var count = await strategy.ExecuteAsync(async () =>
                {
                    // To prevent concurrency exceptions from being thrown if an entry is modified
                    // after it was retrieved from the database, the following logic is executed in
                    // a repeatable read transaction, that will put a lock on the retrieved entries
                    // and thus prevent them from being concurrently modified outside this block.
                    await using var transaction = await CreateTransactionAsync(context,
                        IsolationLevel.RepeatableRead, cancellationToken);

                    var sessions = await
                        (from session in context.Set<TSession>()
                            .Include(static session => session.Tokens)
                            .AsTracking()
                         where session.CreationDate < date
                         where session.Status != Statuses.Valid
                         where !session.Tokens.Any()
                         orderby session.Id
                         select session).Take(1_000).ToListAsync(cancellationToken);

                    if (sessions.Count is not 0)
                    {
                        // Note: new tokens may be attached after the sessions were retrieved
                        // from the database since the transaction level is deliberately limited to
                        // repeatable read instead of serializable for performance reasons). In this
                        // case, the operation will fail, which is considered an acceptable risk.
                        context.RemoveRange(sessions);

                        try
                        {
                            await context.SaveChangesAsync(cancellationToken);

                            if (transaction is not null)
                            {
                                await transaction.CommitAsync(cancellationToken);
                            }
                        }

                        catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                        {
                            exceptions ??= new List<Exception>(capacity: 1);
                            exceptions.Add(exception);
                        }
                    }

                    return sessions.Count;
                });

                if (count is 0)
                {
                    break;
                }

                result += count;
            }
        }

        if (exceptions is { Count: > 0 })
        {
            throw new AggregateException(exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask SetApplicationIdAsync(TSession session, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        if (!string.IsNullOrEmpty(identifier))
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            session.Application = await context.Set<TApplication>()
                .FindAsync([ConvertIdentifierFromString(identifier)], cancellationToken)
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0244));
        }

        else
        {
            // If the application is not attached to the session, try to load it manually.
            if (session.Application is null)
            {
                var context = await Context.GetDbContextAsync(cancellationToken);

                var reference = context.Entry(session).Reference(static entry => entry.Application);
                if (reference.EntityEntry.State is EntityState.Detached)
                {
                    return;
                }

                await reference.LoadAsync(cancellationToken);
            }

            session.Application = null;
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask SetAuthorizationIdAsync(TSession session, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        if (!string.IsNullOrEmpty(identifier))
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            session.Authorization = await context.Set<TAuthorization>()
                .FindAsync([ConvertIdentifierFromString(identifier)], cancellationToken)
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0244));
        }

        else
        {
            // If the authorization is not attached to the session, try to load it manually.
            if (session.Authorization is null)
            {
                var context = await Context.GetDbContextAsync(cancellationToken);

                var reference = context.Entry(session).Reference(static entry => entry.Authorization);
                if (reference.EntityEntry.State is EntityState.Detached)
                {
                    return;
                }

                await reference.LoadAsync(cancellationToken);
            }

            session.Authorization = null;
        }
    }

    /// <inheritdoc/>
    public virtual ValueTask SetCreationDateAsync(TSession session, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        session.CreationDate = date?.UtcDateTime;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPropertiesAsync(TSession session,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        session.Properties = properties;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetLoginIdAsync(TSession session, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        session.LoginId = identifier;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetStatusAsync(TSession session, string? status, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        session.Status = status;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetSubjectAsync(TSession session, string? subject, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        session.Subject = subject;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual async ValueTask UpdateAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Attach(session);

        // Generate a new concurrency token and attach it
        // to the session before persisting the changes.
        session.ConcurrencyToken = Guid.NewGuid().ToString();

        context.Update(session);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the updated entities to prevents future calls from failing.
            context.Entry(session).State = EntityState.Unchanged;

            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239), exception);
        }
    }

    /// <summary>
    /// Converts the provided identifier to a strongly typed key object.
    /// </summary>
    /// <param name="identifier">The identifier to convert.</param>
    /// <returns>An instance of <typeparamref name="TKey"/> representing the provided identifier.</returns>
    public virtual TKey? ConvertIdentifierFromString(string? identifier)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            return default;
        }

        // Optimization: if the key is a string, directly return it as-is.
        if (typeof(TKey) == typeof(string))
        {
            return (TKey?) (object?) identifier;
        }

        var converter = TypeDescriptor.GetConverterFromRegisteredType(typeof(TKey));

        return (TKey?) converter.ConvertFromInvariantString(identifier);
    }

    /// <summary>
    /// Converts the provided identifier to its string representation.
    /// </summary>
    /// <param name="identifier">The identifier to convert.</param>
    /// <returns>A <see cref="string"/> representation of the provided identifier.</returns>
    public virtual string? ConvertIdentifierToString(TKey? identifier)
    {
        if (Equals(identifier, default(TKey)))
        {
            return null;
        }

        // Optimization: if the key is a string, directly return it as-is.
        if (identifier is string value)
        {
            return value;
        }

        var converter = TypeDescriptor.GetConverterFromRegisteredType(typeof(TKey));

        return converter.ConvertToInvariantString(identifier);
    }

    /// <summary>
    /// Tries to create a new <see cref="IDbContextTransaction"/> with the specified <paramref name="level"/>.
    /// </summary>
    /// <param name="context">The Entity Framework Core context.</param>
    /// <param name="level">The desired level of isolation.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The <see cref="IDbContextTransaction"/> if it could be created, <see langword="null"/> otherwise.</returns>
    protected virtual async ValueTask<IDbContextTransaction?> CreateTransactionAsync(
        DbContext context, IsolationLevel level, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Note: transactions that specify an explicit isolation level are only supported by
        // relational providers and trying to use them with a different provider results in
        // an invalid operation exception being thrown at runtime. To prevent that, a manual
        // check is made to ensure the underlying transaction manager is relational.
        var manager = context.GetService<IDbContextTransactionManager>();
        if (manager is IRelationalTransactionManager)
        {
            try
            {
                return await context.Database.BeginTransactionAsync(level, cancellationToken);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                return null;
            }
        }

        return null;
    }
}
