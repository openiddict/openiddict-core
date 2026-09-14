/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.MongoDb;

/// <summary>
/// Exposes extensions simplifying the management of the MongoDB database used by OpenIddict.
/// </summary>
public static class OpenIddictMongoDbHelpers
{
    /// <summary>
    /// Creates the indexes required by the OpenIddict MongoDB stores, if they don't already exist:
    /// <list type="bullet">
    ///   <item><description>unique indexes on the application client identifiers and on the resource/scope names;</description></item>
    ///   <item><description>a unique partial index on the token reference identifiers, which ensures reference
    ///   tokens and single-use values like DPoP proofs cannot be concurrently stored twice;</description></item>
    ///   <item><description>non-unique indexes used by the authorization, session and token lookups.</description></item>
    /// </list>
    /// </summary>
    /// <remarks>
    /// Note: this method can be safely called multiple times (e.g when the application starts) as creating
    /// an index that already exists with the same options is a no-op. Partial indexes are not supported
    /// by all the MongoDB-compatible databases (e.g Azure Cosmos DB): in this case, the indexes must be
    /// manually created and the replay protection of DPoP proofs is not guaranteed under concurrent requests.
    /// </remarks>
    /// <param name="database">The MongoDB database.</param>
    /// <param name="options">The OpenIddict MongoDB options, used to resolve the collection names.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
    public static async Task CreateIndexesAsync(this IMongoDatabase database,
        OpenIddictMongoDbOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(database);

        options ??= new OpenIddictMongoDbOptions();

        await CreateAsync(options.ApplicationsCollectionName,
        [
            Unique("client_id")
        ]);

        await CreateAsync(options.AuthorizationsCollectionName,
        [
            new CreateIndexModel<BsonDocument>(Builders<BsonDocument>.IndexKeys
                .Ascending("application_id")
                .Ascending("scopes")
                .Ascending("status")
                .Ascending("subject")
                .Ascending("type"))
        ]);

        await CreateAsync(options.ResourcesCollectionName,
        [
            Unique("name")
        ]);

        await CreateAsync(options.ScopesCollectionName,
        [
            Unique("name")
        ]);

        await CreateAsync(options.SessionsCollectionName,
        [
            new CreateIndexModel<BsonDocument>(Builders<BsonDocument>.IndexKeys.Ascending("login_id")),
            new CreateIndexModel<BsonDocument>(Builders<BsonDocument>.IndexKeys
                .Ascending("application_id")
                .Ascending("status")
                .Ascending("subject"))
        ]);

        await CreateAsync(options.TokensCollectionName,
        [
            Unique("reference_id"),
            new CreateIndexModel<BsonDocument>(Builders<BsonDocument>.IndexKeys.Ascending("authorization_id")),
            new CreateIndexModel<BsonDocument>(Builders<BsonDocument>.IndexKeys
                .Ascending("application_id")
                .Ascending("status")
                .Ascending("subject")
                .Ascending("type"))
        ]);

        async Task CreateAsync(string name, IEnumerable<CreateIndexModel<BsonDocument>> models)
        {
            var collection = database.GetCollection<BsonDocument>(name);

            await collection.Indexes.CreateManyAsync(models, cancellationToken);
        }

        // Note: the unique indexes are partial indexes that only apply to the documents that contain
        // a string value for the indexed element, so that documents without value are not constrained.
        static CreateIndexModel<BsonDocument> Unique(string element) => new(
            Builders<BsonDocument>.IndexKeys.Ascending(element),
            new CreateIndexOptions<BsonDocument>
            {
                PartialFilterExpression = Builders<BsonDocument>.Filter.Type(element, BsonType.String),
                Unique = true
            });
    }
}
