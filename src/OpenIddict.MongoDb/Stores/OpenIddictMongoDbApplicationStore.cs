/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;
using MongoDB.Driver.Linq;
using OpenIddict.Abstractions;
using OpenIddict.MongoDb.Models;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.MongoDb
{
    /// <summary>
    /// Provides methods allowing to manage the applications stored in a database.
    /// </summary>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    public class OpenIddictMongoDbApplicationStore<TApplication> : IOpenIddictApplicationStore<TApplication>
        where TApplication : OpenIddictMongoDbApplication
    {
        public OpenIddictMongoDbApplicationStore(
            IOpenIddictMongoDbContext context,
            IOptionsMonitor<OpenIddictMongoDbOptions> options)
        {
            Context = context;
            Options = options;
        }

        /// <summary>
        /// Gets the database context associated with the current store.
        /// </summary>
        protected IOpenIddictMongoDbContext Context { get; }

        /// <summary>
        /// Gets the options associated with the current store.
        /// </summary>
        protected IOptionsMonitor<OpenIddictMongoDbOptions> Options { get; }

        /// <inheritdoc/>
        public virtual async ValueTask<long> CountAsync(CancellationToken cancellationToken)
        {
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

            return await collection.CountDocumentsAsync(FilterDefinition<TApplication>.Empty, null, cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask<long> CountAsync<TResult>(
            Func<IQueryable<TApplication>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

            return await ((IMongoQueryable<TApplication>) query(collection.AsQueryable())).LongCountAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask CreateAsync(TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

            await collection.InsertOneAsync(application, null, cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask DeleteAsync(TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

            if ((await collection.DeleteOneAsync(entity =>
                entity.Id == application.Id &&
                entity.ConcurrencyToken == application.ConcurrencyToken)).DeletedCount == 0)
            {
                throw new OpenIddictExceptions.ConcurrencyException(SR.GetResourceString(SR.ID1238));
            }

            // Delete the authorizations associated with the application.
            await database.GetCollection<OpenIddictMongoDbAuthorization>(Options.CurrentValue.AuthorizationsCollectionName)
                .DeleteManyAsync(authorization => authorization.ApplicationId == application.Id, cancellationToken);

            // Delete the tokens associated with the application.
            await database.GetCollection<OpenIddictMongoDbToken>(Options.CurrentValue.TokensCollectionName)
                .DeleteManyAsync(token => token.ApplicationId == application.Id, cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask<TApplication?> FindByClientIdAsync(string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1194), nameof(identifier));
            }

            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

            return await collection.Find(application => application.ClientId == identifier).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask<TApplication?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1194), nameof(identifier));
            }

            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

            return await collection.Find(application => application.Id ==
                ObjectId.Parse(identifier)).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TApplication> FindByPostLogoutRedirectUriAsync(
            string address, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1142), nameof(address));
            }

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TApplication> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var database = await Context.GetDatabaseAsync(cancellationToken);
                var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

                await foreach (var application in collection.Find(application =>
                    application.PostLogoutRedirectUris.Contains(address)).ToAsyncEnumerable(cancellationToken))
                {
                    yield return application;
                }
            }
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TApplication> FindByRedirectUriAsync(
            string address, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1142), nameof(address));
            }

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TApplication> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var database = await Context.GetDatabaseAsync(cancellationToken);
                var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

                await foreach (var application in collection.Find(application =>
                    application.RedirectUris.Contains(address)).ToAsyncEnumerable(cancellationToken))
                {
                    yield return application;
                }
            }
        }

        /// <inheritdoc/>
        public virtual async ValueTask<TResult> GetAsync<TState, TResult>(
            Func<IQueryable<TApplication>, TState, IQueryable<TResult>> query,
            TState state, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

            return await ((IMongoQueryable<TResult>) query(collection.AsQueryable(), state)).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetClientIdAsync(TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string?>(application.ClientId);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetClientSecretAsync(TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string?>(application.ClientSecret);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetClientTypeAsync(TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string?>(application.Type);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetConsentTypeAsync(TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string?>(application.ConsentType);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetDisplayNameAsync(TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string?>(application.DisplayName);
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (application.DisplayNames == null || application.DisplayNames.Count == 0)
            {
                return new ValueTask<ImmutableDictionary<CultureInfo, string>>(ImmutableDictionary.Create<CultureInfo, string>());
            }

            return new ValueTask<ImmutableDictionary<CultureInfo, string>>(application.DisplayNames.ToImmutableDictionary());
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetIdAsync(TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string?>(application.Id.ToString());
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableArray<string>> GetPermissionsAsync(
            TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (application.Permissions == null || application.Permissions.Count == 0)
            {
                return new ValueTask<ImmutableArray<string>>(ImmutableArray.Create<string>());
            }

            return new ValueTask<ImmutableArray<string>>(application.Permissions.ToImmutableArray());
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableArray<string>> GetPostLogoutRedirectUrisAsync(
            TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (application.PostLogoutRedirectUris == null || application.PostLogoutRedirectUris.Count == 0)
            {
                return new ValueTask<ImmutableArray<string>>(ImmutableArray.Create<string>());
            }

            return new ValueTask<ImmutableArray<string>>(application.PostLogoutRedirectUris.ToImmutableArray());
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (application.Properties == null)
            {
                return new ValueTask<ImmutableDictionary<string, JsonElement>>(ImmutableDictionary.Create<string, JsonElement>());
            }

            return new ValueTask<ImmutableDictionary<string, JsonElement>>(
                JsonSerializer.Deserialize<ImmutableDictionary<string, JsonElement>>(application.Properties.ToJson()));
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableArray<string>> GetRedirectUrisAsync(
            TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (application.RedirectUris == null || application.RedirectUris.Count == 0)
            {
                return new ValueTask<ImmutableArray<string>>(ImmutableArray.Create<string>());
            }

            return new ValueTask<ImmutableArray<string>>(application.RedirectUris.ToImmutableArray());
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableArray<string>> GetRequirementsAsync(TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (application.Requirements == null || application.Requirements.Count == 0)
            {
                return new ValueTask<ImmutableArray<string>>(ImmutableArray.Create<string>());
            }

            return new ValueTask<ImmutableArray<string>>(application.Requirements.ToImmutableArray());
        }

        /// <inheritdoc/>
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

        /// <inheritdoc/>
        public virtual async IAsyncEnumerable<TApplication> ListAsync(
            int? count, int? offset, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

            var query = (IMongoQueryable<TApplication>) collection.AsQueryable().OrderBy(application => application.Id);

            if (offset.HasValue)
            {
                query = query.Skip(offset.Value);
            }

            if (count.HasValue)
            {
                query = query.Take(count.Value);
            }

            await foreach (var application in ((IAsyncCursorSource<TApplication>) query).ToAsyncEnumerable(cancellationToken))
            {
                yield return application;
            }
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
            Func<IQueryable<TApplication>, TState, IQueryable<TResult>> query,
            TState state, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TResult> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var database = await Context.GetDatabaseAsync(cancellationToken);
                var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

                await foreach (var element in query(collection.AsQueryable(), state).ToAsyncEnumerable(cancellationToken))
                {
                    yield return element;
                }
            }
        }

        /// <inheritdoc/>
        public virtual ValueTask SetClientIdAsync(TApplication application,
            string? identifier, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            application.ClientId = identifier;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetClientSecretAsync(TApplication application,
            string? secret, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            application.ClientSecret = secret;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetClientTypeAsync(TApplication application,
            string? type, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            application.Type = type;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetConsentTypeAsync(TApplication application,
            string? type, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            application.ConsentType = type;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetDisplayNameAsync(TApplication application,
            string? name, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            application.DisplayName = name;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetDisplayNamesAsync(TApplication application,
            ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            application.DisplayNames = names;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetPermissionsAsync(TApplication application, ImmutableArray<string> permissions, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (permissions.IsDefaultOrEmpty)
            {
                application.Permissions = ImmutableArray.Create<string>();

                return default;
            }

            application.Permissions = permissions.ToArray();

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetPostLogoutRedirectUrisAsync(TApplication application,
            ImmutableArray<string> addresses, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (addresses.IsDefaultOrEmpty)
            {
                application.PostLogoutRedirectUris = ImmutableArray.Create<string>();

                return default;
            }

            application.PostLogoutRedirectUris = addresses.ToArray();

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetPropertiesAsync(TApplication application,
            ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
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

            application.Properties = BsonDocument.Parse(JsonSerializer.Serialize(properties, new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                WriteIndented = false
            }));

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetRedirectUrisAsync(TApplication application,
            ImmutableArray<string> addresses, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (addresses.IsDefaultOrEmpty)
            {
                application.RedirectUris = ImmutableArray.Create<string>();

                return default;
            }

            application.RedirectUris = addresses.ToArray();

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetRequirementsAsync(TApplication application,
            ImmutableArray<string> requirements, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (requirements.IsDefaultOrEmpty)
            {
                application.Requirements = ImmutableArray.Create<string>();

                return default;
            }

            application.Requirements = requirements.ToArray();

            return default;
        }

        /// <inheritdoc/>
        public virtual async ValueTask UpdateAsync(TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            // Generate a new concurrency token and attach it
            // to the application before persisting the changes.
            var timestamp = application.ConcurrencyToken;
            application.ConcurrencyToken = Guid.NewGuid().ToString();

            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

            if ((await collection.ReplaceOneAsync(entity =>
                entity.Id == application.Id &&
                entity.ConcurrencyToken == timestamp, application, null as ReplaceOptions, cancellationToken)).MatchedCount == 0)
            {
                throw new OpenIddictExceptions.ConcurrencyException(SR.GetResourceString(SR.ID1238));
            }
        }
    }
}