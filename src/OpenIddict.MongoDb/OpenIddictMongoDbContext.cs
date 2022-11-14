/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpenIddict.MongoDb;

/// <inheritdoc/>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictMongoDbContext : IOpenIddictMongoDbContext
{
    private readonly IOptionsMonitor<OpenIddictMongoDbOptions> _options;
    private readonly IServiceProvider _provider;

    public OpenIddictMongoDbContext(
        IOptionsMonitor<OpenIddictMongoDbOptions> options,
        IServiceProvider provider)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <inheritdoc/>
    public ValueTask<IMongoDatabase> GetDatabaseAsync(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return new(Task.FromCanceled<IMongoDatabase>(cancellationToken));
        }

        var database = _options.CurrentValue.Database ?? _provider.GetService<IMongoDatabase>();
        if (database is null)
        {
            return new(Task.FromException<IMongoDatabase>(
                new InvalidOperationException(SR.GetResourceString(SR.ID0262))));
        }

        return new(database);
    }
}
