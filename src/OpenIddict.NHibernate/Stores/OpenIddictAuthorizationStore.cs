/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NHibernate;
using NHibernate.Linq;
using OpenIddict.Abstractions;
using OpenIddict.NHibernate.Models;

namespace OpenIddict.NHibernate
{
    /// <summary>
    /// Provides methods allowing to manage the authorizations stored in a database.
    /// </summary>
    public class OpenIddictAuthorizationStore : OpenIddictAuthorizationStore<OpenIddictAuthorization,
                                                                             OpenIddictApplication,
                                                                             OpenIddictToken, string>
    {
        public OpenIddictAuthorizationStore(
            [NotNull] IMemoryCache cache,
            [NotNull] IOpenIddictNHibernateContext context,
            [NotNull] IOptionsMonitor<OpenIddictNHibernateOptions> options)
            : base(cache, context, options)
        {
        }
    }

    /// <summary>
    /// Provides methods allowing to manage the authorizations stored in a database.
    /// </summary>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public class OpenIddictAuthorizationStore<TKey> : OpenIddictAuthorizationStore<OpenIddictAuthorization<TKey>,
                                                                                   OpenIddictApplication<TKey>,
                                                                                   OpenIddictToken<TKey>, TKey>
        where TKey : IEquatable<TKey>
    {
        public OpenIddictAuthorizationStore(
            [NotNull] IMemoryCache cache,
            [NotNull] IOpenIddictNHibernateContext context,
            [NotNull] IOptionsMonitor<OpenIddictNHibernateOptions> options)
            : base(cache, context, options)
        {
        }
    }

    /// <summary>
    /// Provides methods allowing to manage the authorizations stored in a database.
    /// </summary>
    /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public class OpenIddictAuthorizationStore<TAuthorization, TApplication, TToken, TKey> : IOpenIddictAuthorizationStore<TAuthorization>
        where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>
        where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>
        where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>
        where TKey : IEquatable<TKey>
    {
        public OpenIddictAuthorizationStore(
            [NotNull] IMemoryCache cache,
            [NotNull] IOpenIddictNHibernateContext context,
            [NotNull] IOptionsMonitor<OpenIddictNHibernateOptions> options)
        {
            Cache = cache;
            Context = context;
            Options = options;
        }

        /// <summary>
        /// Gets the memory cache associated with the current store.
        /// </summary>
        protected IMemoryCache Cache { get; }

        /// <summary>
        /// Gets the database context associated with the current store.
        /// </summary>
        protected IOpenIddictNHibernateContext Context { get; }

        /// <summary>
        /// Gets the options associated with the current store.
        /// </summary>
        protected IOptionsMonitor<OpenIddictNHibernateOptions> Options { get; }

        /// <summary>
        /// Determines the number of authorizations that exist in the database.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of authorizations in the database.
        /// </returns>
        public virtual async Task<long> CountAsync(CancellationToken cancellationToken)
        {
            var session = await Context.GetSessionAsync(cancellationToken);
            return await session.Query<TAuthorization>().LongCountAsync(cancellationToken);
        }

        /// <summary>
        /// Determines the number of authorizations that match the specified query.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of authorizations that match the specified query.
        /// </returns>
        public virtual async Task<long> CountAsync<TResult>([NotNull] Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            var session = await Context.GetSessionAsync(cancellationToken);
            return await query(session.Query<TAuthorization>()).LongCountAsync(cancellationToken);
        }

        /// <summary>
        /// Creates a new authorization.
        /// </summary>
        /// <param name="authorization">The authorization to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task CreateAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var session = await Context.GetSessionAsync(cancellationToken);
            await session.SaveAsync(authorization, cancellationToken);
            await session.FlushAsync(cancellationToken);
        }

        /// <summary>
        /// Removes an existing authorization.
        /// </summary>
        /// <param name="authorization">The authorization to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task DeleteAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var session = await Context.GetSessionAsync(cancellationToken);

            try
            {
                // Delete all the tokens associated with the authorization.
                await (from token in session.Query<TToken>()
                        where token.Authorization.Id.Equals(authorization.Id)
                        select token).DeleteAsync(cancellationToken);

                await session.DeleteAsync(authorization, cancellationToken);
                await session.FlushAsync(cancellationToken);
            }

            catch (StaleObjectStateException exception)
            {
                throw new OpenIddictExceptions.ConcurrencyException(new StringBuilder()
                    .AppendLine("The authorization was concurrently updated and cannot be persisted in its current state.")
                    .Append("Reload the authorization from the database and retry the operation.")
                    .ToString(), exception);
            }
        }

        /// <summary>
        /// Retrieves the authorizations corresponding to the specified
        /// subject and associated with the application identifier.
        /// </summary>
        /// <param name="subject">The subject associated with the authorization.</param>
        /// <param name="client">The client associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorizations corresponding to the subject/client.
        /// </returns>
        public virtual async Task<ImmutableArray<TAuthorization>> FindAsync(
            [NotNull] string subject, [NotNull] string client, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.", nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException("The client cannot be null or empty.", nameof(client));
            }

            var session = await Context.GetSessionAsync(cancellationToken);

            var key = ConvertIdentifierFromString(client);

            return ImmutableArray.CreateRange(
                await (from authorization in session.Query<TAuthorization>().Fetch(authorization => authorization.Application)
                       where authorization.Application != null &&
                             authorization.Application.Id.Equals(key) &&
                             authorization.Subject == subject
                       select authorization).ToListAsync(cancellationToken));
        }

        /// <summary>
        /// Retrieves the authorizations matching the specified parameters.
        /// </summary>
        /// <param name="subject">The subject associated with the authorization.</param>
        /// <param name="client">The client associated with the authorization.</param>
        /// <param name="status">The authorization status.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorizations corresponding to the criteria.
        /// </returns>
        public virtual async Task<ImmutableArray<TAuthorization>> FindAsync(
            [NotNull] string subject, [NotNull] string client,
            [NotNull] string status, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.", nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException("The client cannot be null or empty.", nameof(client));
            }

            if (string.IsNullOrEmpty(status))
            {
                throw new ArgumentException("The status cannot be null or empty.", nameof(status));
            }

            var session = await Context.GetSessionAsync(cancellationToken);

            var key = ConvertIdentifierFromString(client);

            return ImmutableArray.CreateRange(
                await (from authorization in session.Query<TAuthorization>().Fetch(authorization => authorization.Application)
                       where authorization.Application != null &&
                             authorization.Application.Id.Equals(key) &&
                             authorization.Subject == subject &&
                             authorization.Status == status
                       select authorization).ToListAsync(cancellationToken));
        }

        /// <summary>
        /// Retrieves the authorizations matching the specified parameters.
        /// </summary>
        /// <param name="subject">The subject associated with the authorization.</param>
        /// <param name="client">The client associated with the authorization.</param>
        /// <param name="status">The authorization status.</param>
        /// <param name="type">The authorization type.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorizations corresponding to the criteria.
        /// </returns>
        public virtual async Task<ImmutableArray<TAuthorization>> FindAsync(
            [NotNull] string subject, [NotNull] string client,
            [NotNull] string status, [NotNull] string type, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.", nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException("The client identifier cannot be null or empty.", nameof(client));
            }

            if (string.IsNullOrEmpty(status))
            {
                throw new ArgumentException("The status cannot be null or empty.", nameof(status));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The type cannot be null or empty.", nameof(type));
            }

            var session = await Context.GetSessionAsync(cancellationToken);

            var key = ConvertIdentifierFromString(client);

            return ImmutableArray.CreateRange(
                await (from authorization in session.Query<TAuthorization>().Fetch(authorization => authorization.Application)
                       where authorization.Application != null &&
                             authorization.Application.Id.Equals(key) &&
                             authorization.Subject == subject &&
                             authorization.Status == status &&
                             authorization.Type == type
                       select authorization).ToListAsync(cancellationToken));
        }

        /// <summary>
        /// Retrieves the authorizations matching the specified parameters.
        /// </summary>
        /// <param name="subject">The subject associated with the authorization.</param>
        /// <param name="client">The client associated with the authorization.</param>
        /// <param name="status">The authorization status.</param>
        /// <param name="type">The authorization type.</param>
        /// <param name="scopes">The minimal scopes associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorizations corresponding to the criteria.
        /// </returns>
        public virtual async Task<ImmutableArray<TAuthorization>> FindAsync(
            [NotNull] string subject, [NotNull] string client,
            [NotNull] string status, [NotNull] string type,
            ImmutableArray<string> scopes, CancellationToken cancellationToken)
        {
            var authorizations = await FindAsync(subject, client, status, type, cancellationToken);
            if (authorizations.IsEmpty)
            {
                return ImmutableArray.Create<TAuthorization>();
            }

            var builder = ImmutableArray.CreateBuilder<TAuthorization>(authorizations.Length);

            foreach (var authorization in authorizations)
            {
                async Task<bool> HasScopesAsync()
                    => (await GetScopesAsync(authorization, cancellationToken))
                        .ToImmutableHashSet(StringComparer.Ordinal)
                        .IsSupersetOf(scopes);

                if (await HasScopesAsync())
                {
                    builder.Add(authorization);
                }
            }

            return builder.Count == builder.Capacity ?
                builder.MoveToImmutable() :
                builder.ToImmutable();
        }

        /// <summary>
        /// Retrieves the list of authorizations corresponding to the specified application identifier.
        /// </summary>
        /// <param name="identifier">The application identifier associated with the authorizations.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorizations corresponding to the specified application.
        /// </returns>
        public virtual async Task<ImmutableArray<TAuthorization>> FindByApplicationIdAsync(
            [NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            var session = await Context.GetSessionAsync(cancellationToken);

            var key = ConvertIdentifierFromString(identifier);

            return ImmutableArray.CreateRange(
                await (from authorization in session.Query<TAuthorization>().Fetch(authorization => authorization.Application)
                       where authorization.Application != null &&
                             authorization.Application.Id.Equals(key)
                       select authorization).ToListAsync(cancellationToken));
        }

        /// <summary>
        /// Retrieves an authorization using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorization corresponding to the identifier.
        /// </returns>
        public virtual async Task<TAuthorization> FindByIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            var session = await Context.GetSessionAsync(cancellationToken);
            return await session.GetAsync<TAuthorization>(ConvertIdentifierFromString(identifier), cancellationToken);
        }

        /// <summary>
        /// Retrieves all the authorizations corresponding to the specified subject.
        /// </summary>
        /// <param name="subject">The subject associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorizations corresponding to the specified subject.
        /// </returns>
        public virtual async Task<ImmutableArray<TAuthorization>> FindBySubjectAsync(
            [NotNull] string subject, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.", nameof(subject));
            }

            var session = await Context.GetSessionAsync(cancellationToken);

            return ImmutableArray.CreateRange(
                await (from authorization in session.Query<TAuthorization>().Fetch(authorization => authorization.Application)
                       where authorization.Subject == subject
                       select authorization).ToListAsync(cancellationToken));
        }

        /// <summary>
        /// Retrieves the optional application identifier associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the application identifier associated with the authorization.
        /// </returns>
        public virtual ValueTask<string> GetApplicationIdAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (authorization.Application == null)
            {
                return new ValueTask<string>(result: null);
            }

            return new ValueTask<string>(ConvertIdentifierToString(authorization.Application.Id));
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
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the first element returned when executing the query.
        /// </returns>
        public virtual async Task<TResult> GetAsync<TState, TResult>(
            [NotNull] Func<IQueryable<TAuthorization>, TState, IQueryable<TResult>> query,
            [CanBeNull] TState state, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            var session = await Context.GetSessionAsync(cancellationToken);

            return await query(session.Query<TAuthorization>()
                .Fetch(authorization => authorization.Application), state).FirstOrDefaultAsync(cancellationToken);
        }

        /// <summary>
        /// Retrieves the unique identifier associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the authorization.
        /// </returns>
        public virtual ValueTask<string> GetIdAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return new ValueTask<string>(ConvertIdentifierToString(authorization.Id));
        }

        /// <summary>
        /// Retrieves the additional properties associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the additional properties associated with the authorization.
        /// </returns>
        public virtual ValueTask<JObject> GetPropertiesAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (string.IsNullOrEmpty(authorization.Properties))
            {
                return new ValueTask<JObject>(new JObject());
            }

            return new ValueTask<JObject>(JObject.Parse(authorization.Properties));
        }

        /// <summary>
        /// Retrieves the scopes associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scopes associated with the specified authorization.
        /// </returns>
        public virtual ValueTask<ImmutableArray<string>> GetScopesAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (string.IsNullOrEmpty(authorization.Scopes))
            {
                return new ValueTask<ImmutableArray<string>>(ImmutableArray.Create<string>());
            }

            return new ValueTask<ImmutableArray<string>>(JArray.Parse(authorization.Scopes).Select(element => (string) element).ToImmutableArray());
        }

        /// <summary>
        /// Retrieves the status associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the status associated with the specified authorization.
        /// </returns>
        public virtual ValueTask<string> GetStatusAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return new ValueTask<string>(authorization.Status);
        }

        /// <summary>
        /// Retrieves the subject associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the subject associated with the specified authorization.
        /// </returns>
        public virtual ValueTask<string> GetSubjectAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return new ValueTask<string>(authorization.Subject);
        }

        /// <summary>
        /// Retrieves the type associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the type associated with the specified authorization.
        /// </returns>
        public virtual ValueTask<string> GetTypeAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return new ValueTask<string>(authorization.Type);
        }

        /// <summary>
        /// Instantiates a new authorization.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the instantiated authorization, that can be persisted in the database.
        /// </returns>
        public virtual ValueTask<TAuthorization> InstantiateAsync(CancellationToken cancellationToken)
        {
            try
            {
                return new ValueTask<TAuthorization>(Activator.CreateInstance<TAuthorization>());
            }

            catch (MemberAccessException exception)
            {
                return new ValueTask<TAuthorization>(Task.FromException<TAuthorization>(
                    new InvalidOperationException(new StringBuilder()
                        .AppendLine("An error occurred while trying to create a new authorization instance.")
                        .Append("Make sure that the authorization entity is not abstract and has a public parameterless constructor ")
                        .Append("or create a custom authorization store that overrides 'InstantiateAsync()' to use a custom factory.")
                        .ToString(), exception)));
            }
        }

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <param name="count">The number of results to return.</param>
        /// <param name="offset">The number of results to skip.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the elements returned when executing the specified query.
        /// </returns>
        public virtual async Task<ImmutableArray<TAuthorization>> ListAsync(
            [CanBeNull] int? count, [CanBeNull] int? offset, CancellationToken cancellationToken)
        {
            var session = await Context.GetSessionAsync(cancellationToken);
            var query = session.Query<TAuthorization>()
                               .Fetch(authorization => authorization.Application)
                               .OrderBy(authorization => authorization.Id)
                               .AsQueryable();

            if (offset.HasValue)
            {
                query = query.Skip(offset.Value);
            }

            if (count.HasValue)
            {
                query = query.Take(count.Value);
            }

            return ImmutableArray.CreateRange(await query.ToListAsync(cancellationToken));
        }

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <typeparam name="TState">The state type.</typeparam>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="state">The optional state.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the elements returned when executing the specified query.
        /// </returns>
        public virtual async Task<ImmutableArray<TResult>> ListAsync<TState, TResult>(
            [NotNull] Func<IQueryable<TAuthorization>, TState, IQueryable<TResult>> query,
            [CanBeNull] TState state, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            var session = await Context.GetSessionAsync(cancellationToken);

            return ImmutableArray.CreateRange(await query(
                session.Query<TAuthorization>().Fetch(authorization => authorization.Application), state).ToListAsync(cancellationToken));
        }

        /// <summary>
        /// Removes the authorizations that are marked as invalid and the ad-hoc ones that have no valid/nonexpired token attached.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task PruneAsync(CancellationToken cancellationToken)
        {
            var session = await Context.GetSessionAsync(cancellationToken);

            await (from token in session.Query<TToken>()
                   where token.Status != OpenIddictConstants.Statuses.Valid ||
                         token.ExpirationDate < DateTimeOffset.UtcNow
                   select token).DeleteAsync(cancellationToken);

            await (from authorization in session.Query<TAuthorization>()
                   where authorization.Status != OpenIddictConstants.Statuses.Valid ||
                        (authorization.Type == OpenIddictConstants.AuthorizationTypes.AdHoc && !authorization.Tokens.Any())
                   select authorization).DeleteAsync(cancellationToken);

            await session.FlushAsync(cancellationToken);
        }

        /// <summary>
        /// Sets the application identifier associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="identifier">The unique identifier associated with the client application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task SetApplicationIdAsync([NotNull] TAuthorization authorization,
            [CanBeNull] string identifier, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var session = await Context.GetSessionAsync(cancellationToken);

            if (!string.IsNullOrEmpty(identifier))
            {
                authorization.Application = await session.LoadAsync<TApplication>(ConvertIdentifierFromString(identifier), cancellationToken);
            }

            else
            {
                authorization.Application = null;
            }
        }

        /// <summary>
        /// Sets the additional properties associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="properties">The additional properties associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetPropertiesAsync([NotNull] TAuthorization authorization, [CanBeNull] JObject properties, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (properties == null)
            {
                authorization.Properties = null;

                return Task.CompletedTask;
            }

            authorization.Properties = properties.ToString(Formatting.None);

            return Task.CompletedTask;
        }

        /// <summary>
        /// Sets the scopes associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="scopes">The scopes associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetScopesAsync([NotNull] TAuthorization authorization,
            ImmutableArray<string> scopes, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (scopes.IsDefaultOrEmpty)
            {
                authorization.Scopes = null;

                return Task.CompletedTask;
            }

            authorization.Scopes = new JArray(scopes.ToArray()).ToString(Formatting.None);

            return Task.CompletedTask;
        }

        /// <summary>
        /// Sets the status associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="status">The status associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetStatusAsync([NotNull] TAuthorization authorization,
            [CanBeNull] string status, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            authorization.Status = status;

            return Task.CompletedTask;
        }

        /// <summary>
        /// Sets the subject associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="subject">The subject associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetSubjectAsync([NotNull] TAuthorization authorization,
            [CanBeNull] string subject, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            authorization.Subject = subject;

            return Task.CompletedTask;
        }

        /// <summary>
        /// Sets the type associated with an authorization.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <param name="type">The type associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetTypeAsync([NotNull] TAuthorization authorization,
            [CanBeNull] string type, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            authorization.Type = type;

            return Task.CompletedTask;
        }

        /// <summary>
        /// Updates an existing authorization.
        /// </summary>
        /// <param name="authorization">The authorization to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task UpdateAsync([NotNull] TAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var session = await Context.GetSessionAsync(cancellationToken);

            try
            {
                await session.UpdateAsync(authorization, cancellationToken);
                await session.FlushAsync(cancellationToken);
            }

            catch (StaleObjectStateException exception)
            {
                throw new OpenIddictExceptions.ConcurrencyException(new StringBuilder()
                    .AppendLine("The authorization was concurrently updated and cannot be persisted in its current state.")
                    .Append("Reload the authorization from the database and retry the operation.")
                    .ToString(), exception);
            }
        }

        /// <summary>
        /// Converts the provided identifier to a strongly typed key object.
        /// </summary>
        /// <param name="identifier">The identifier to convert.</param>
        /// <returns>An instance of <typeparamref name="TKey"/> representing the provided identifier.</returns>
        public virtual TKey ConvertIdentifierFromString([CanBeNull] string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                return default;
            }

            return (TKey) TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(identifier);
        }

        /// <summary>
        /// Converts the provided identifier to its string representation.
        /// </summary>
        /// <param name="identifier">The identifier to convert.</param>
        /// <returns>A <see cref="string"/> representation of the provided identifier.</returns>
        public virtual string ConvertIdentifierToString([CanBeNull] TKey identifier)
        {
            if (Equals(identifier, default(TKey)))
            {
                return null;
            }

            return TypeDescriptor.GetConverter(typeof(TKey)).ConvertToInvariantString(identifier);
        }
    }
}