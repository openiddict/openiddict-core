/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.MongoDb
{
    /// <summary>
    /// Exposes the MongoDB database used by the OpenIddict stores.
    /// </summary>
    public class OpenIddictMongoDbContext : IOpenIddictMongoDbContext
    {
        private readonly IOptionsMonitor<OpenIddictMongoDbOptions> _options;
        private readonly IServiceProvider _provider;

        public OpenIddictMongoDbContext(
            [NotNull] IOptionsMonitor<OpenIddictMongoDbOptions> options,
            [NotNull] IServiceProvider provider)
        {
            _options = options;
            _provider = provider;
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
            if (cancellationToken.IsCancellationRequested)
            {
                return new ValueTask<IMongoDatabase>(Task.FromCanceled<IMongoDatabase>(cancellationToken));
            }

            var database = _options.CurrentValue.Database;
            if (database == null)
            {
                database = _provider.GetService<IMongoDatabase>();
            }

            if (database == null)
            {
                return new ValueTask<IMongoDatabase>(Task.FromException<IMongoDatabase>(
                    new InvalidOperationException(SR.GetResourceString(SR.ID1261))));
            }

            return new ValueTask<IMongoDatabase>(database);
        }
    }
}
