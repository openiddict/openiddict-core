/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.MongoDb;

/// <summary>
/// Exposes the MongoDB database used by the OpenIddict stores.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public interface IOpenIddictMongoDbContext
{
    /// <summary>
    /// Gets the <see cref="IMongoDatabase"/>.
    /// </summary>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the
    /// asynchronous operation, whose result returns the MongoDB database.
    /// </returns>
    ValueTask<IMongoDatabase> GetDatabaseAsync(CancellationToken cancellationToken);
}
