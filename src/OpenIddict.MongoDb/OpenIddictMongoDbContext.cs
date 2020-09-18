/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.MongoDb
{
    /// <inheritdoc/>
    public class OpenIddictMongoDbContext : IOpenIddictMongoDbContext
    {
        private readonly IOptionsMonitor<OpenIddictMongoDbOptions> _options;
        private readonly IServiceProvider _provider;

        public OpenIddictMongoDbContext(
            IOptionsMonitor<OpenIddictMongoDbOptions> options,
            IServiceProvider provider)
        {
            _options = options;
            _provider = provider;
        }

        /// <inheritdoc/>
        public ValueTask<IMongoDatabase> GetDatabaseAsync(CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return new ValueTask<IMongoDatabase>(Task.FromCanceled<IMongoDatabase>(cancellationToken));
            }

            var database = _options.CurrentValue.Database;
            if (database is null)
            {
                database = _provider.GetService<IMongoDatabase>();
            }

            if (database is null)
            {
                return new ValueTask<IMongoDatabase>(Task.FromException<IMongoDatabase>(
                    new InvalidOperationException(SR.GetResourceString(SR.ID0262))));
            }

            return new ValueTask<IMongoDatabase>(database);
        }
    }
}
