/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using OpenIddict.MongoDb.Models;

namespace OpenIddict.MongoDb
{
    /// <summary>
    /// Exposes the MongoDB database used by the OpenIddict stores.
    /// </summary>
    public class OpenIddictMongoDbContext : IOpenIddictMongoDbContext
    {
        private readonly IOptionsMonitor<OpenIddictMongoDbOptions> _options;
        private readonly IServiceProvider _provider;
        private readonly SemaphoreSlim _semaphore;
        private IMongoDatabase _database;

        public OpenIddictMongoDbContext(
            [NotNull] IOptionsMonitor<OpenIddictMongoDbOptions> options,
            [NotNull] IServiceProvider provider)
        {
            _options = options;
            _provider = provider;
            _semaphore = new SemaphoreSlim(1);
        }

        /// <summary>
        /// Gets the <see cref="IMongoDatabase"/>.
        /// </summary>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the
        /// asynchronous operation, whose result returns the MongoDB database.
        /// </returns>
        public ValueTask<IMongoDatabase> GetDatabaseAsync(CancellationToken cancellationToken)
        {
            if (_database != null)
            {
                return new ValueTask<IMongoDatabase>(_database);
            }

            async Task<IMongoDatabase> ExecuteAsync()
            {
                var options = _options.CurrentValue;
                if (options == null)
                {
                    throw new InvalidOperationException("The OpenIddict MongoDB options cannot be retrieved.");
                }

                if (!await _semaphore.WaitAsync(options.InitializationTimeout, cancellationToken))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The MongoDB database couldn't be initialized within a reasonable timeframe.")
                        .Append("Make sure that the MongoDB server is ready and accepts connections from this machine ")
                        .Append("or use 'options.UseMongoDb().SetInitializationTimeout()' to manually adjust the timeout.")
                        .ToString());
                }

                try
                {
                    var database = options.Database;
                    if (database == null)
                    {
                        database = _provider.GetService<IMongoDatabase>();
                    }

                    if (database == null)
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .AppendLine("No suitable MongoDB database service can be found.")
                            .Append("To configure the OpenIddict MongoDB stores to use a specific database, use ")
                            .Append("'services.AddOpenIddict().AddCore().UseMongoDb().UseDatabase()' or register an ")
                            .Append("'IMongoDatabase' in the dependency injection container in 'ConfigureServices()'.")
                            .ToString());
                    }

                    // Note: the cancellation token passed as a parameter is deliberately not used here to ensure
                    // the cancellation of a single store operation doesn't prevent the indexes from being created.
                    var applications = database.GetCollection<OpenIddictApplication>(options.ApplicationsCollectionName);
                    await applications.Indexes.CreateOneAsync(
                        Builders<OpenIddictApplication>.IndexKeys.Ascending(application => application.ClientId),
                        new CreateIndexOptions
                        {
                            Unique = true
                        });

                    await applications.Indexes.CreateOneAsync(
                        Builders<OpenIddictApplication>.IndexKeys.Ascending(application => application.PostLogoutRedirectUris));

                    await applications.Indexes.CreateOneAsync(
                        Builders<OpenIddictApplication>.IndexKeys.Ascending(application => application.RedirectUris));

                    var scopes = database.GetCollection<OpenIddictScope>(options.ScopesCollectionName);
                    await scopes.Indexes.CreateOneAsync(
                        Builders<OpenIddictScope>.IndexKeys.Ascending(scope => scope.Name),
                        new CreateIndexOptions
                        {
                            Unique = true
                        });

                    var tokens = database.GetCollection<OpenIddictToken>(options.TokensCollectionName);
                    await tokens.Indexes.CreateOneAsync(
                        Builders<OpenIddictToken>.IndexKeys.Ascending(token => token.ReferenceId),
                        new CreateIndexOptions<OpenIddictToken>
                        {
                            PartialFilterExpression = Builders<OpenIddictToken>.Filter.Exists(token => token.ReferenceId),
                            Unique = true
                        });

                    return _database = database;
                }

                finally
                {
                    _semaphore.Release();
                }
            }

            return new ValueTask<IMongoDatabase>(ExecuteAsync());
        }
    }
}
