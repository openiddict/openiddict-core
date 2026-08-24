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
/// Provides methods allowing to manage the tokens stored in a database.
/// </summary>
public class OpenIddictEntityFrameworkCoreTokenStore :
    OpenIddictEntityFrameworkCoreTokenStore<OpenIddictEntityFrameworkCoreToken,
                                            OpenIddictEntityFrameworkCoreApplication,
                                            OpenIddictEntityFrameworkCoreAuthorization,
                                            OpenIddictEntityFrameworkCoreSession, string>
{
    public OpenIddictEntityFrameworkCoreTokenStore(
        IOpenIddictEntityFrameworkCoreContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the tokens stored in a database.
/// </summary>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkCoreTokenStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> :
    OpenIddictEntityFrameworkCoreTokenStore<OpenIddictEntityFrameworkCoreToken<TKey>,
                                            OpenIddictEntityFrameworkCoreApplication<TKey>,
                                            OpenIddictEntityFrameworkCoreAuthorization<TKey>,
                                            OpenIddictEntityFrameworkCoreSession<TKey>, TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkCoreTokenStore(
        IOpenIddictEntityFrameworkCoreContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the tokens stored in a database.
/// </summary>
/// <typeparam name="TToken">The type of the token entity.</typeparam>
/// <typeparam name="TApplication">The type of the application entity.</typeparam>
/// <typeparam name="TAuthorization">The type of the authorization entity.</typeparam>
/// <typeparam name="TSession">The type of the session entity.</typeparam>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkCoreTokenStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TSession,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IOpenIddictTokenStore<TToken>
    where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization, TSession>
    where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TSession, TToken>
    where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TSession, TToken>
    where TSession : OpenIddictEntityFrameworkCoreSession<TKey, TApplication, TAuthorization, TToken>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkCoreTokenStore(
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

        return await context.Set<TToken>().AsQueryable().LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync<TState, TResult>(
        Func<IQueryable<TToken>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return await query(context.Set<TToken>(), state).LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask CreateAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Add(token);

        await context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Remove(token);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the updated entities to prevents future calls from failing.
            context.Entry(token).State = EntityState.Unchanged;

            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239), exception);
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TToken> FindAsync(
        (string? Subject, string? ApplicationId, string? Status, string? Type) query,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        IQueryable<TToken> tokens = context.Set<TToken>()
            .Include(static token => token.Application)
            .Include(static token => token.Authorization)
            .AsTracking();

        if (!string.IsNullOrEmpty(query.Subject))
        {
            tokens = tokens.Where(token => token.Subject == query.Subject);
        }

        if (!string.IsNullOrEmpty(query.ApplicationId))
        {
            var key = ConvertIdentifierFromString(query.ApplicationId);
            tokens = tokens.Where(token => token.Application!.Id!.Equals(key));
        }

        if (!string.IsNullOrEmpty(query.Status))
        {
            tokens = tokens.Where(token => token.Status == query.Status);
        }

        if (!string.IsNullOrEmpty(query.Type))
        {
            tokens = tokens.Where(token => token.Type == query.Type);
        }

        await foreach (var token in tokens.AsAsyncEnumerable().WithCancellation(cancellationToken))
        {
            yield return token;
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TToken> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);
            var key = ConvertIdentifierFromString(identifier);

            await foreach (var token in
                (from token in context.Set<TToken>()
                    .Include(static token => token.Application)
                    .Include(static token => token.Authorization)
                    .AsTracking()
                 where token.Application!.Id!.Equals(key)
                 select token).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return token;
            }
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TToken> FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);
            var key = ConvertIdentifierFromString(identifier);

            await foreach (var token in
                (from token in context.Set<TToken>()
                    .Include(static token => token.Application)
                    .Include(static token => token.Authorization)
                    .AsTracking()
                 where token.Authorization!.Id!.Equals(key)
                 select token).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return token;
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TToken?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var context = await Context.GetDbContextAsync(cancellationToken);
        var key = ConvertIdentifierFromString(identifier);

        return await context.Set<TToken>().FindAsync([key], cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TToken?> FindByReferenceIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return GetTrackedEntity() is TToken token ? token : await QueryAsync();

        TToken? GetTrackedEntity() =>
            (from entry in context.ChangeTracker.Entries<TToken>()
             where string.Equals(entry.Entity.ReferenceId, identifier, StringComparison.Ordinal)
             select entry.Entity).FirstOrDefault();

        Task<TToken?> QueryAsync() =>
            (from token in context.Set<TToken>()
                .Include(static token => token.Application)
                .Include(static token => token.Authorization)
                .AsTracking()
             where token.ReferenceId == identifier
             select token).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TToken> FindBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            await foreach (var token in
                (from token in context.Set<TToken>()
                    .Include(static token => token.Application)
                    .Include(static token => token.Authorization)
                    .AsTracking()
                 where token.Subject == subject
                 select token).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return token;
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<string?> GetApplicationIdAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        // If the application is not attached to the token, try to load it manually.
        if (token.Application is null)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            var reference = context.Entry(token).Reference(static entry => entry.Application);
            if (reference.EntityEntry.State is EntityState.Detached)
            {
                return null;
            }

            await reference.LoadAsync(cancellationToken);
        }

        if (token.Application is null)
        {
            return null;
        }

        return ConvertIdentifierToString(token.Application.Id);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TToken>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return await query(context.Set<TToken>()
            .Include(static token => token.Application)
            .Include(static token => token.Authorization)
            .AsTracking(), state).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<string?> GetAuthorizationIdAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        // If the authorization is not attached to the token, try to load it manually.
        if (token.Authorization is null)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            var reference = context.Entry(token).Reference(static entry => entry.Authorization);
            if (reference.EntityEntry.State is EntityState.Detached)
            {
                return null;
            }

            await reference.LoadAsync(cancellationToken);
        }

        if (token.Authorization is null)
        {
            return null;
        }

        return ConvertIdentifierToString(token.Authorization.Id);
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetCreationDateAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.CreationDate is DateTime date ? new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Utc)) : null);
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetExpirationDateAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.ExpirationDate is DateTime date ? new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Utc)) : null);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetIdAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(ConvertIdentifierToString(token.Id));
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetPayloadAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.Payload);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.Properties is { Count: > 0 } properties ? [.. properties] : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetRedemptionDateAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.RedemptionDate is DateTime date ? new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Utc)) : null);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetReferenceIdAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.ReferenceId);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetStatusAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.Status);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetSubjectAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.Subject);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetTypeAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.Type);
    }

    /// <inheritdoc/>
    public virtual ValueTask<TToken> InstantiateAsync(CancellationToken cancellationToken)
    {
        try
        {
            return new(Activator.CreateInstance<TToken>());
        }

        catch (MemberAccessException exception)
        {
            return new(Task.FromException<TToken>(
                new InvalidOperationException(SR.GetResourceString(SR.ID0240), exception)));
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TToken> ListAsync(int? count, int? offset,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        var query = context.Set<TToken>()
            .Include(static token => token.Application)
            .Include(static token => token.Authorization)
            .OrderBy(static token => token.Id!)
            .AsTracking();

        if (offset is not null)
        {
            query = query.Skip(offset.Value);
        }

        if (count is not null)
        {
            query = query.Take(count.Value);
        }

        await foreach (var token in query.AsAsyncEnumerable().WithCancellation(cancellationToken))
        {
            yield return token;
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<TToken>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TResult> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            await foreach (var token in query(context.Set<TToken>()
                .Include(static token => token.Application)
                .Include(static token => token.Authorization)
                .AsTracking(), state).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return token;
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
                        (from token in context.Set<TToken>()
                         where token.CreationDate < date
                         where (token.Status != Statuses.Inactive && token.Status != Statuses.Valid) ||
                               (token.Authorization != null && token.Authorization.Status != Statuses.Valid) ||
                                token.ExpirationDate < DateTime.UtcNow
                         orderby token.Id
                         select token).Take(1_000).ExecuteDeleteAsync(cancellationToken);

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

                    var tokens = await
                        (from token in context.Set<TToken>().AsTracking()
                         where token.CreationDate < date
                         where (token.Status != Statuses.Inactive && token.Status != Statuses.Valid) ||
                               (token.Authorization != null && token.Authorization.Status != Statuses.Valid) ||
                                token.ExpirationDate < DateTime.UtcNow
                         orderby token.Id
                         select token).Take(1_000).ToListAsync(cancellationToken);

                    if (tokens.Count is not 0)
                    {
                        context.RemoveRange(tokens);

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

                    return tokens.Count;
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
    public virtual async ValueTask<long> RevokeAsync(string? subject, string? client, string? status, string ?type, CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        IQueryable<TToken> query = Options.CurrentValue.DisableBulkOperations
            ? context.Set<TToken>().Include(static token => token.Application).Include(static token => token.Authorization).AsTracking()
            : context.Set<TToken>();

        if (!string.IsNullOrEmpty(subject))
        {
            query = query.Where(token => token.Subject == subject);
        }

        if (!string.IsNullOrEmpty(client))
        {
            var key = ConvertIdentifierFromString(client);

            query = query.Where(token => token.Application!.Id!.Equals(key));
        }

        if (!string.IsNullOrEmpty(status))
        {
            query = query.Where(token => token.Status == status);
        }

        if (!string.IsNullOrEmpty(type))
        {
            query = query.Where(token => token.Type == type);
        }

        if (!Options.CurrentValue.DisableBulkOperations)
        {
            return await query.ExecuteUpdateAsync(entity => entity.SetProperty(
                token => token.Status, Statuses.Revoked), cancellationToken);

            // Note: calling DbContext.SaveChangesAsync() is not necessary
            // with bulk update operations as they are executed immediately.
        }

        List<Exception>? exceptions = null;

        var result = 0L;

        foreach (var token in await query.ToListAsync(cancellationToken))
        {
            token.Status = Statuses.Revoked;

            try
            {
                await context.SaveChangesAsync(cancellationToken);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                // Reset the state of the updated entities to prevents future calls from failing.
                context.Entry(token).State = EntityState.Unchanged;

                exceptions ??= new List<Exception>(capacity: 1);
                exceptions.Add(exception);

                continue;
            }

            result++;
        }

        if (exceptions is { Count: > 0 })
        {
            throw new AggregateException(exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var context = await Context.GetDbContextAsync(cancellationToken);
        var key = ConvertIdentifierFromString(identifier);

        if (!Options.CurrentValue.DisableBulkOperations)
        {
            return await (
                from token in context.Set<TToken>()
                where token.Application!.Id!.Equals(key)
                where token.Status != Statuses.Revoked
                select token).ExecuteUpdateAsync(entity => entity.SetProperty(
                    token => token.Status, Statuses.Revoked), cancellationToken);

            // Note: calling DbContext.SaveChangesAsync() is not necessary
            // with bulk update operations as they are executed immediately.
        }

        List<Exception>? exceptions = null;

        var result = 0L;

        foreach (var token in await (from token in context.Set<TToken>()
                                        .Include(static token => token.Application)
                                        .Include(static token => token.Authorization)
                                        .AsTracking()
                                     where token.Application!.Id!.Equals(key)
                                     where token.Status != Statuses.Revoked
                                     select token).ToListAsync(cancellationToken))
        {
            token.Status = Statuses.Revoked;

            try
            {
                await context.SaveChangesAsync(cancellationToken);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                // Reset the state of the updated entities to prevents future calls from failing.
                context.Entry(token).State = EntityState.Unchanged;

                exceptions ??= new List<Exception>(capacity: 1);
                exceptions.Add(exception);

                continue;
            }

            result++;
        }

        if (exceptions is { Count: > 0 })
        {
            throw new AggregateException(exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var context = await Context.GetDbContextAsync(cancellationToken);
        var key = ConvertIdentifierFromString(identifier);

        if (!Options.CurrentValue.DisableBulkOperations)
        {
            return await (
                from token in context.Set<TToken>()
                where token.Authorization!.Id!.Equals(key)
                where token.Status != Statuses.Revoked
                select token).ExecuteUpdateAsync(entity => entity.SetProperty(
                    token => token.Status, Statuses.Revoked), cancellationToken);

            // Note: calling DbContext.SaveChangesAsync() is not necessary
            // with bulk update operations as they are executed immediately.
        }

        List<Exception>? exceptions = null;

        var result = 0L;

        foreach (var token in await (from token in context.Set<TToken>()
                                        .Include(static token => token.Application)
                                        .Include(static token => token.Authorization)
                                        .AsTracking()
                                     where token.Authorization!.Id!.Equals(key)
                                     where token.Status != Statuses.Revoked
                                     select token).ToListAsync(cancellationToken))
        {
            token.Status = Statuses.Revoked;

            try
            {
                await context.SaveChangesAsync(cancellationToken);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                // Reset the state of the updated entities to prevents future calls from failing.
                context.Entry(token).State = EntityState.Unchanged;

                exceptions ??= new List<Exception>(capacity: 1);
                exceptions.Add(exception);

                continue;
            }

            result++;
        }

        if (exceptions is { Count: > 0 })
        {
            throw new AggregateException(exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        var context = await Context.GetDbContextAsync(cancellationToken);

        if (!Options.CurrentValue.DisableBulkOperations)
        {
            return await (
                from token in context.Set<TToken>()
                where token.Subject == subject
                where token.Status != Statuses.Revoked
                select token).ExecuteUpdateAsync(entity => entity.SetProperty(
                    token => token.Status, Statuses.Revoked), cancellationToken);

            // Note: calling DbContext.SaveChangesAsync() is not necessary
            // with bulk update operations as they are executed immediately.
        }

        List<Exception>? exceptions = null;

        var result = 0L;

        foreach (var token in await (from token in context.Set<TToken>()
                                        .Include(static token => token.Application)
                                        .Include(static token => token.Authorization)
                                        .AsTracking()
                                     where token.Subject == subject
                                     where token.Status != Statuses.Revoked
                                     select token).ToListAsync(cancellationToken))
        {
            token.Status = Statuses.Revoked;

            try
            {
                await context.SaveChangesAsync(cancellationToken);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                // Reset the state of the updated entities to prevents future calls from failing.
                context.Entry(token).State = EntityState.Unchanged;

                exceptions ??= new List<Exception>(capacity: 1);
                exceptions.Add(exception);

                continue;
            }

            result++;
        }

        if (exceptions is { Count: > 0 })
        {
            throw new AggregateException(exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask SetApplicationIdAsync(TToken token, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        if (!string.IsNullOrEmpty(identifier))
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            token.Application = await context.Set<TApplication>()
                .FindAsync([ConvertIdentifierFromString(identifier)], cancellationToken)
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0244));
        }

        else
        {
            // If the application is not attached to the token, try to load it manually.
            if (token.Application is null)
            {
                var context = await Context.GetDbContextAsync(cancellationToken);

                var reference = context.Entry(token).Reference(static entry => entry.Application);
                if (reference.EntityEntry.State is EntityState.Detached)
                {
                    return;
                }

                await reference.LoadAsync(cancellationToken);
            }

            token.Application = null;
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask SetAuthorizationIdAsync(TToken token, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        if (!string.IsNullOrEmpty(identifier))
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            token.Authorization = await context.Set<TAuthorization>()
                .FindAsync([ConvertIdentifierFromString(identifier)], cancellationToken)
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0251));
        }

        else
        {
            // If the authorization is not attached to the token, try to load it manually.
            if (token.Authorization is null)
            {
                var context = await Context.GetDbContextAsync(cancellationToken);

                var reference = context.Entry(token).Reference(static entry => entry.Authorization);
                if (reference.EntityEntry.State is EntityState.Detached)
                {
                    return;
                }

                await reference.LoadAsync(cancellationToken);
            }

            token.Authorization = null;
        }
    }

    /// <inheritdoc/>
    public virtual ValueTask SetCreationDateAsync(TToken token, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.CreationDate = date?.UtcDateTime;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetExpirationDateAsync(TToken token, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.ExpirationDate = date?.UtcDateTime;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPayloadAsync(TToken token, string? payload, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.Payload = payload;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPropertiesAsync(TToken token,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.Properties = properties;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetRedemptionDateAsync(TToken token, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.RedemptionDate = date?.UtcDateTime;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetReferenceIdAsync(TToken token, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.ReferenceId = identifier;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetStatusAsync(TToken token, string? status, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.Status = status;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetSubjectAsync(TToken token, string? subject, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.Subject = subject;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetTypeAsync(TToken token, string? type, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.Type = type;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual async ValueTask UpdateAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Attach(token);

        // Generate a new concurrency token and attach it
        // to the token before persisting the changes.
        token.ConcurrencyToken = Guid.NewGuid().ToString();

        context.Update(token);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the updated entities to prevents future calls from failing.
            context.Entry(token).State = EntityState.Unchanged;

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
