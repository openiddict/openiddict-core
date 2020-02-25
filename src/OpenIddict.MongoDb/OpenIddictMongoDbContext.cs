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
    public class OpenIddictMongoDbContext : IOpenIddictMongoDbContext, IDisposable
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
        /// Disposes the semaphore held by this instance.
        /// </summary>
        public void Dispose() => _semaphore.Dispose();

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

            if (cancellationToken.IsCancellationRequested)
            {
                return new ValueTask<IMongoDatabase>(Task.FromCanceled<IMongoDatabase>(cancellationToken));
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
                        .Append("Make sure that the MongoDB server is ready and accepts connections from this machine or use ")
                        .Append("'services.AddOpenIddict().AddCore().UseMongoDb().SetInitializationTimeout()' to adjust the timeout.")
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

                    if (!options.DisableInitialization)
                    {
                        // Note: the cancellation token passed as a parameter is deliberately not used here to ensure
                        // the cancellation of a single store operation doesn't prevent the indexes from being created.
                        var applications = database.GetCollection<OpenIddictMongoDbApplication>(options.ApplicationsCollectionName);
                        await applications.Indexes.CreateManyAsync(new[]
                        {
                            new CreateIndexModel<OpenIddictMongoDbApplication>(
                                Builders<OpenIddictMongoDbApplication>.IndexKeys.Ascending(application => application.ClientId),
                                new CreateIndexOptions
                                {
                                    Unique = true
                                }),

                            new CreateIndexModel<OpenIddictMongoDbApplication>(
                                Builders<OpenIddictMongoDbApplication>.IndexKeys.Ascending(application => application.PostLogoutRedirectUris),
                                new CreateIndexOptions
                                {
                                    Background = true
                                }),

                            new CreateIndexModel<OpenIddictMongoDbApplication>(
                                Builders<OpenIddictMongoDbApplication>.IndexKeys.Ascending(application => application.RedirectUris),
                                new CreateIndexOptions
                                {
                                    Background = true
                                })
                        });

                        var authorizations = database.GetCollection<OpenIddictMongoDbAuthorization>(options.AuthorizationsCollectionName);
                        await authorizations.Indexes.CreateOneAsync(new CreateIndexModel<OpenIddictMongoDbAuthorization>(
                            Builders<OpenIddictMongoDbAuthorization>.IndexKeys
                                .Ascending(authorization => authorization.ApplicationId)
                                .Ascending(authorization => authorization.Scopes)
                                .Ascending(authorization => authorization.Status)
                                .Ascending(authorization => authorization.Subject)
                                .Ascending(authorization => authorization.Type),
                            new CreateIndexOptions
                            {
                                Background = true
                            }));

                        var scopes = database.GetCollection<OpenIddictMongoDbScope>(options.ScopesCollectionName);
                        await scopes.Indexes.CreateOneAsync(new CreateIndexModel<OpenIddictMongoDbScope>(
                            Builders<OpenIddictMongoDbScope>.IndexKeys.Ascending(scope => scope.Name),
                            new CreateIndexOptions
                            {
                                Unique = true
                            }));

                        var tokens = database.GetCollection<OpenIddictMongoDbToken>(options.TokensCollectionName);
                        await tokens.Indexes.CreateManyAsync(new[]
                        {
                            new CreateIndexModel<OpenIddictMongoDbToken>(
                                Builders<OpenIddictMongoDbToken>.IndexKeys.Ascending(token => token.ReferenceId),
                                new CreateIndexOptions<OpenIddictMongoDbToken>
                                {
                                    PartialFilterExpression = Builders<OpenIddictMongoDbToken>.Filter.Exists(token => token.ReferenceId),
                                    Unique = true
                                }),

                            new CreateIndexModel<OpenIddictMongoDbToken>(
                                Builders<OpenIddictMongoDbToken>.IndexKeys
                                    .Ascending(token => token.ApplicationId)
                                    .Ascending(token => token.Status)
                                    .Ascending(token => token.Subject)
                                    .Ascending(token => token.Type),
                                new CreateIndexOptions
                                {
                                    Background = true
                                })
                        });
                    }

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
