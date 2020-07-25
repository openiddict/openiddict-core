/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.EntityFramework.Models;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.EntityFramework
{
    /// <summary>
    /// Provides methods allowing to manage the applications stored in a database.
    /// </summary>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    public class OpenIddictEntityFrameworkApplicationStore<TContext> :
        OpenIddictEntityFrameworkApplicationStore<OpenIddictEntityFrameworkApplication,
                                                  OpenIddictEntityFrameworkAuthorization,
                                                  OpenIddictEntityFrameworkToken, TContext, string>
        where TContext : DbContext
    {
        public OpenIddictEntityFrameworkApplicationStore(
            [NotNull] IMemoryCache cache,
            [NotNull] TContext context,
            [NotNull] IOptionsMonitor<OpenIddictEntityFrameworkOptions> options)
            : base(cache, context, options)
        {
        }
    }

    /// <summary>
    /// Provides methods allowing to manage the applications stored in a database.
    /// </summary>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public class OpenIddictEntityFrameworkApplicationStore<TApplication, TAuthorization, TToken, TContext, TKey> : IOpenIddictApplicationStore<TApplication>
        where TApplication : OpenIddictEntityFrameworkApplication<TKey, TAuthorization, TToken>
        where TAuthorization : OpenIddictEntityFrameworkAuthorization<TKey, TApplication, TToken>
        where TToken : OpenIddictEntityFrameworkToken<TKey, TApplication, TAuthorization>
        where TContext : DbContext
        where TKey : IEquatable<TKey>
    {
        public OpenIddictEntityFrameworkApplicationStore(
            [NotNull] IMemoryCache cache,
            [NotNull] TContext context,
            [NotNull] IOptionsMonitor<OpenIddictEntityFrameworkOptions> options)
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
        protected TContext Context { get; }

        /// <summary>
        /// Gets the options associated with the current store.
        /// </summary>
        protected IOptionsMonitor<OpenIddictEntityFrameworkOptions> Options { get; }

        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="TApplication"/> entity.
        /// </summary>
        private DbSet<TApplication> Applications => Context.Set<TApplication>();

        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="TAuthorization"/> entity.
        /// </summary>
        private DbSet<TAuthorization> Authorizations => Context.Set<TAuthorization>();

        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="TToken"/> entity.
        /// </summary>
        private DbSet<TToken> Tokens => Context.Set<TToken>();

        /// <summary>
        /// Determines the number of applications that exist in the database.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of applications in the database.
        /// </returns>
        public virtual async ValueTask<long> CountAsync(CancellationToken cancellationToken)
            => await Applications.LongCountAsync(cancellationToken);

        /// <summary>
        /// Determines the number of applications that match the specified query.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of applications that match the specified query.
        /// </returns>
        public virtual async ValueTask<long> CountAsync<TResult>([NotNull] Func<IQueryable<TApplication>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return await query(Applications).LongCountAsync(cancellationToken);
        }

        /// <summary>
        /// Creates a new application.
        /// </summary>
        /// <param name="application">The application to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual async ValueTask CreateAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            Applications.Add(application);

            await Context.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// Removes an existing application.
        /// </summary>
        /// <param name="application">The application to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual async ValueTask DeleteAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            DbContextTransaction CreateTransaction()
            {
                try
                {
                    return Context.Database.BeginTransaction(IsolationLevel.Serializable);
                }

                catch
                {
                    return null;
                }
            }

            Task<List<TAuthorization>> ListAuthorizationsAsync()
                => (from authorization in Authorizations.Include(authorization => authorization.Tokens)
                    where authorization.Application.Id.Equals(application.Id)
                    select authorization).ToListAsync(cancellationToken);

            Task<List<TToken>> ListTokensAsync()
                => (from token in Tokens
                    where token.Authorization == null
                    where token.Application.Id.Equals(application.Id)
                    select token).ToListAsync(cancellationToken);

            // To prevent an SQL exception from being thrown if a new associated entity is
            // created after the existing entries have been listed, the following logic is
            // executed in a serializable transaction, that will lock the affected tables.
            using var transaction = CreateTransaction();

            // Remove all the authorizations associated with the application and
            // the tokens attached to these implicit or explicit authorizations.
            var authorizations = await ListAuthorizationsAsync();
            foreach (var authorization in authorizations)
            {
                foreach (var token in authorization.Tokens)
                {
                    Tokens.Remove(token);
                }

                Authorizations.Remove(authorization);
            }

            // Remove all the tokens associated with the application.
            var tokens = await ListTokensAsync();
            foreach (var token in tokens)
            {
                Tokens.Remove(token);
            }

            Applications.Remove(application);

            try
            {
                await Context.SaveChangesAsync(cancellationToken);
                transaction?.Commit();
            }

            catch (DbUpdateConcurrencyException exception)
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.Entry(application).State = EntityState.Unchanged;

                foreach (var authorization in authorizations)
                {
                    Context.Entry(authorization).State = EntityState.Unchanged;
                }

                foreach (var token in tokens)
                {
                    Context.Entry(token).State = EntityState.Unchanged;
                }

                throw new OpenIddictExceptions.ConcurrencyException(SR.GetResourceString(SR.ID1238), exception);
            }
        }

        /// <summary>
        /// Retrieves an application using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client application corresponding to the identifier.
        /// </returns>
        public virtual async ValueTask<TApplication> FindByIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1194), nameof(identifier));
            }

            var key = ConvertIdentifierFromString(identifier);

            return await (from application in Applications
                          where application.Id.Equals(key)
                          select application).FirstOrDefaultAsync(cancellationToken);
        }

        /// <summary>
        /// Retrieves an application using its client identifier.
        /// </summary>
        /// <param name="identifier">The client identifier associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client application corresponding to the identifier.
        /// </returns>
        public virtual async ValueTask<TApplication> FindByClientIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1194), nameof(identifier));
            }

            return await (from application in Applications
                          where application.ClientId == identifier
                          select application).FirstOrDefaultAsync(cancellationToken);
        }

        /// <summary>
        /// Retrieves all the applications associated with the specified post_logout_redirect_uri.
        /// </summary>
        /// <param name="address">The post_logout_redirect_uri associated with the applications.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>The client applications corresponding to the specified post_logout_redirect_uri.</returns>
        public virtual IAsyncEnumerable<TApplication> FindByPostLogoutRedirectUriAsync(
            [NotNull] string address, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1142), nameof(address));
            }

            // To optimize the efficiency of the query a bit, only applications whose stringified
            // PostLogoutRedirectUris contains the specified URL are returned. Once the applications
            // are retrieved, a second pass is made to ensure only valid elements are returned.
            // Implementers that use this method in a hot path may want to override this method
            // to use SQL Server 2016 functions like JSON_VALUE to make the query more efficient.

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TApplication> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var applications = (from application in Applications
                                    where application.PostLogoutRedirectUris.Contains(address)
                                    select application).AsAsyncEnumerable(cancellationToken);

                await foreach (var application in applications)
                {
                    var addresses = await GetPostLogoutRedirectUrisAsync(application, cancellationToken);
                    if (addresses.Contains(address, StringComparer.Ordinal))
                    {
                        yield return application;
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves all the applications associated with the specified redirect_uri.
        /// </summary>
        /// <param name="address">The redirect_uri associated with the applications.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>The client applications corresponding to the specified redirect_uri.</returns>
        public virtual IAsyncEnumerable<TApplication> FindByRedirectUriAsync(
            [NotNull] string address, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1142), nameof(address));
            }

            // To optimize the efficiency of the query a bit, only applications whose stringified
            // RedirectUris property contains the specified URL are returned. Once the applications
            // are retrieved, a second pass is made to ensure only valid elements are returned.
            // Implementers that use this method in a hot path may want to override this method
            // to use SQL Server 2016 functions like JSON_VALUE to make the query more efficient.

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TApplication> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var applications = (from application in Applications
                                    where application.RedirectUris.Contains(address)
                                    select application).AsAsyncEnumerable(cancellationToken);

                await foreach (var application in applications)
                {
                    var addresses = await GetRedirectUrisAsync(application, cancellationToken);
                    if (addresses.Contains(address, StringComparer.Ordinal))
                    {
                        yield return application;
                    }
                }
            }
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
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the first element returned when executing the query.
        /// </returns>
        public virtual async ValueTask<TResult> GetAsync<TState, TResult>(
            [NotNull] Func<IQueryable<TApplication>, TState, IQueryable<TResult>> query,
            [CanBeNull] TState state, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return await query(Applications, state).FirstOrDefaultAsync(cancellationToken);
        }

        /// <summary>
        /// Retrieves the client identifier associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client identifier associated with the application.
        /// </returns>
        public virtual ValueTask<string> GetClientIdAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string>(application.ClientId);
        }

        /// <summary>
        /// Retrieves the client secret associated with an application.
        /// Note: depending on the manager used to create the application,
        /// the client secret may be hashed for security reasons.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client secret associated with the application.
        /// </returns>
        public virtual ValueTask<string> GetClientSecretAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string>(application.ClientSecret);
        }

        /// <summary>
        /// Retrieves the client type associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client type of the application (by default, "public").
        /// </returns>
        public virtual ValueTask<string> GetClientTypeAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string>(application.Type);
        }

        /// <summary>
        /// Retrieves the consent type associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the consent type of the application (by default, "explicit").
        /// </returns>
        public virtual ValueTask<string> GetConsentTypeAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string>(application.ConsentType);
        }

        /// <summary>
        /// Retrieves the display name associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the display name associated with the application.
        /// </returns>
        public virtual ValueTask<string> GetDisplayNameAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string>(application.DisplayName);
        }

        /// <summary>
        /// Retrieves the localized display names associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the localized display names associated with the application.
        /// </returns>
        public virtual ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (string.IsNullOrEmpty(application.DisplayNames))
            {
                return new ValueTask<ImmutableDictionary<CultureInfo, string>>(ImmutableDictionary.Create<CultureInfo, string>());
            }

            // Note: parsing the stringified display names is an expensive operation.
            // To mitigate that, the resulting object is stored in the memory cache.
            var key = string.Concat("7762c378-c113-4564-b14b-1402b3949aaa", "\x1e", application.DisplayNames);
            var names = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                return JsonSerializer.Deserialize<Dictionary<string, string>>(application.DisplayNames)
                    .ToImmutableDictionary(name => CultureInfo.GetCultureInfo(name.Key), name => name.Value);
            });

            return new ValueTask<ImmutableDictionary<CultureInfo, string>>(names);
        }

        /// <summary>
        /// Retrieves the unique identifier associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the application.
        /// </returns>
        public virtual ValueTask<string> GetIdAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string>(ConvertIdentifierToString(application.Id));
        }

        /// <summary>
        /// Retrieves the permissions associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the permissions associated with the application.
        /// </returns>
        public virtual ValueTask<ImmutableArray<string>> GetPermissionsAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (string.IsNullOrEmpty(application.Permissions))
            {
                return new ValueTask<ImmutableArray<string>>(ImmutableArray.Create<string>());
            }

            // Note: parsing the stringified permissions is an expensive operation.
            // To mitigate that, the resulting array is stored in the memory cache.
            var key = string.Concat("0347e0aa-3a26-410a-97e8-a83bdeb21a1f", "\x1e", application.Permissions);
            var permissions = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                return JsonSerializer.Deserialize<ImmutableArray<string>>(application.Permissions);
            });

            return new ValueTask<ImmutableArray<string>>(permissions);
        }

        /// <summary>
        /// Retrieves the logout callback addresses associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the post_logout_redirect_uri associated with the application.
        /// </returns>
        public virtual ValueTask<ImmutableArray<string>> GetPostLogoutRedirectUrisAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (string.IsNullOrEmpty(application.PostLogoutRedirectUris))
            {
                return new ValueTask<ImmutableArray<string>>(ImmutableArray.Create<string>());
            }

            // Note: parsing the stringified addresses is an expensive operation.
            // To mitigate that, the resulting array is stored in the memory cache.
            var key = string.Concat("fb14dfb9-9216-4b77-bfa9-7e85f8201ff4", "\x1e", application.PostLogoutRedirectUris);
            var addresses = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                return JsonSerializer.Deserialize<ImmutableArray<string>>(application.PostLogoutRedirectUris);
            });

            return new ValueTask<ImmutableArray<string>>(addresses);
        }

        /// <summary>
        /// Retrieves the additional properties associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the additional properties associated with the application.
        /// </returns>
        public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (string.IsNullOrEmpty(application.Properties))
            {
                return new ValueTask<ImmutableDictionary<string, JsonElement>>(ImmutableDictionary.Create<string, JsonElement>());
            }

            // Note: parsing the stringified properties is an expensive operation.
            // To mitigate that, the resulting object is stored in the memory cache.
            var key = string.Concat("2e3e9680-5654-48d8-a27d-b8bb4f0f1d50", "\x1e", application.Properties);
            var properties = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                return JsonSerializer.Deserialize<ImmutableDictionary<string, JsonElement>>(application.Properties);
            });

            return new ValueTask<ImmutableDictionary<string, JsonElement>>(properties);
        }

        /// <summary>
        /// Retrieves the callback addresses associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the redirect_uri associated with the application.
        /// </returns>
        public virtual ValueTask<ImmutableArray<string>> GetRedirectUrisAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (string.IsNullOrEmpty(application.RedirectUris))
            {
                return new ValueTask<ImmutableArray<string>>(ImmutableArray.Create<string>());
            }

            // Note: parsing the stringified addresses is an expensive operation.
            // To mitigate that, the resulting array is stored in the memory cache.
            var key = string.Concat("851d6f08-2ee0-4452-bbe5-ab864611ecaa", "\x1e", application.RedirectUris);
            var addresses = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                return JsonSerializer.Deserialize<ImmutableArray<string>>(application.RedirectUris);
            });

            return new ValueTask<ImmutableArray<string>>(addresses);
        }

        /// <summary>
        /// Retrieves the requirements associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the requirements associated with the application.
        /// </returns>
        public virtual ValueTask<ImmutableArray<string>> GetRequirementsAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (string.IsNullOrEmpty(application.Requirements))
            {
                return new ValueTask<ImmutableArray<string>>(ImmutableArray.Create<string>());
            }

            // Note: parsing the stringified requirements is an expensive operation.
            // To mitigate that, the resulting array is stored in the memory cache.
            var key = string.Concat("b4808a89-8969-4512-895f-a909c62a8995", "\x1e", application.Requirements);
            var requirements = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                return JsonSerializer.Deserialize<ImmutableArray<string>>(application.Requirements);
            });

            return new ValueTask<ImmutableArray<string>>(requirements);
        }

        /// <summary>
        /// Instantiates a new application.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the instantiated application, that can be persisted in the database.
        /// </returns>
        public virtual ValueTask<TApplication> InstantiateAsync(CancellationToken cancellationToken)
        {
            try
            {
                return new ValueTask<TApplication>(Activator.CreateInstance<TApplication>());
            }

            catch (MemberAccessException exception)
            {
                return new ValueTask<TApplication>(Task.FromException<TApplication>(
                    new InvalidOperationException(SR.GetResourceString(SR.ID1239), exception)));
            }
        }

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <param name="count">The number of results to return.</param>
        /// <param name="offset">The number of results to skip.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>All the elements returned when executing the specified query.</returns>
        public virtual IAsyncEnumerable<TApplication> ListAsync(
            [CanBeNull] int? count, [CanBeNull] int? offset, CancellationToken cancellationToken)
        {
            var query = Applications.OrderBy(application => application.Id).AsQueryable();

            if (offset.HasValue)
            {
                query = query.Skip(offset.Value);
            }

            if (count.HasValue)
            {
                query = query.Take(count.Value);
            }

            return query.AsAsyncEnumerable(cancellationToken);
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
            [NotNull] Func<IQueryable<TApplication>, TState, IQueryable<TResult>> query,
            [CanBeNull] TState state, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return query(Applications, state).AsAsyncEnumerable(cancellationToken);
        }

        /// <summary>
        /// Sets the client identifier associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="identifier">The client identifier associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual ValueTask SetClientIdAsync([NotNull] TApplication application,
            [CanBeNull] string identifier, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            application.ClientId = identifier;

            return default;
        }

        /// <summary>
        /// Sets the client secret associated with an application.
        /// Note: depending on the manager used to create the application,
        /// the client secret may be hashed for security reasons.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="secret">The client secret associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual ValueTask SetClientSecretAsync([NotNull] TApplication application,
            [CanBeNull] string secret, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            application.ClientSecret = secret;

            return default;
        }

        /// <summary>
        /// Sets the client type associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="type">The client type associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual ValueTask SetClientTypeAsync([NotNull] TApplication application,
            [CanBeNull] string type, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            application.Type = type;

            return default;
        }

        /// <summary>
        /// Sets the consent type associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="type">The consent type associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual ValueTask SetConsentTypeAsync([NotNull] TApplication application,
            [CanBeNull] string type, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            application.ConsentType = type;

            return default;
        }

        /// <summary>
        /// Sets the display name associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="name">The display name associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual ValueTask SetDisplayNameAsync([NotNull] TApplication application,
            [CanBeNull] string name, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            application.DisplayName = name;

            return default;
        }

        /// <summary>
        /// Sets the localized display names associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="names">The localized display names associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual ValueTask SetDisplayNamesAsync([NotNull] TApplication application,
            [CanBeNull] ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (names == null || names.IsEmpty)
            {
                application.DisplayNames = null;

                return default;
            }

            using var stream = new MemoryStream();
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                Indented = false
            });

            writer.WriteStartObject();

            foreach (var name in names)
            {
                writer.WritePropertyName(name.Key.Name);
                writer.WriteStringValue(name.Value);
            }

            writer.WriteEndObject();
            writer.Flush();

            application.DisplayNames = Encoding.UTF8.GetString(stream.ToArray());

            return default;
        }

        /// <summary>
        /// Sets the permissions associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="permissions">The permissions associated with the application </param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual ValueTask SetPermissionsAsync([NotNull] TApplication application, ImmutableArray<string> permissions, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (permissions.IsDefaultOrEmpty)
            {
                application.Permissions = null;

                return default;
            }

            application.Permissions = JsonSerializer.Serialize(permissions, new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                WriteIndented = false
            });

            return default;
        }

        /// <summary>
        /// Sets the logout callback addresses associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="addresses">The logout callback addresses associated with the application </param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual ValueTask SetPostLogoutRedirectUrisAsync([NotNull] TApplication application,
            ImmutableArray<string> addresses, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (addresses.IsDefaultOrEmpty)
            {
                application.PostLogoutRedirectUris = null;

                return default;
            }

            application.PostLogoutRedirectUris = JsonSerializer.Serialize(addresses, new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                WriteIndented = false
            });

            return default;
        }

        /// <summary>
        /// Sets the additional properties associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="properties">The additional properties associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual ValueTask SetPropertiesAsync([NotNull] TApplication application,
            [CanBeNull] ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (properties == null || properties.IsEmpty)
            {
                application.Properties = null;

                return default;
            }

            application.Properties = JsonSerializer.Serialize(properties, new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                WriteIndented = false
            });

            return default;
        }

        /// <summary>
        /// Sets the callback addresses associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="addresses">The callback addresses associated with the application </param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual ValueTask SetRedirectUrisAsync([NotNull] TApplication application,
            ImmutableArray<string> addresses, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (addresses.IsDefaultOrEmpty)
            {
                application.RedirectUris = null;

                return default;
            }

            application.RedirectUris = JsonSerializer.Serialize(addresses, new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                WriteIndented = false
            });

            return default;
        }

        /// <summary>
        /// Sets the requirements associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="requirements">The requirements associated with the application </param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual ValueTask SetRequirementsAsync([NotNull] TApplication application, ImmutableArray<string> requirements, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (requirements.IsDefaultOrEmpty)
            {
                application.Requirements = null;

                return default;
            }

            application.Requirements = JsonSerializer.Serialize(requirements, new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                WriteIndented = false
            });

            return default;
        }

        /// <summary>
        /// Updates an existing application.
        /// </summary>
        /// <param name="application">The application to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual async ValueTask UpdateAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            Applications.Attach(application);

            // Generate a new concurrency token and attach it
            // to the application before persisting the changes.
            application.ConcurrencyToken = Guid.NewGuid().ToString();

            Context.Entry(application).State = EntityState.Modified;

            try
            {
                await Context.SaveChangesAsync(cancellationToken);
            }

            catch (DbUpdateConcurrencyException exception)
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.Entry(application).State = EntityState.Unchanged;

                throw new OpenIddictExceptions.ConcurrencyException(SR.GetResourceString(SR.ID1238), exception);
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