/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Driver;
using Moq;
using Xunit;

namespace OpenIddict.MongoDb.Tests;

public class OpenIddictMongoDbHelpersTests
{
    [Fact]
    public async Task CreateIndexesAsync_ThrowsAnExceptionForNullDatabase()
    {
        // Arrange
        var database = (IMongoDatabase) null!;

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(() => database.CreateIndexesAsync());

        Assert.Equal("database", exception.ParamName);
    }

    [Fact]
    public async Task CreateIndexesAsync_CreatesUniquePartialIndexOnTokenReferenceIdentifiers()
    {
        // Arrange
        var models = new Dictionary<string, List<CreateIndexModel<BsonDocument>>>(StringComparer.Ordinal);
        var database = CreateDatabase(models);

        // Act
        await database.CreateIndexesAsync(new OpenIddictMongoDbOptions { TokensCollectionName = "custom.tokens" });

        // Assert
        var index = Assert.Single(models["custom.tokens"], static model => Render(model.Keys) == new BsonDocument("reference_id", 1));
        var options = Assert.IsType<CreateIndexOptions<BsonDocument>>(index.Options);

        Assert.True(options.Unique);
        Assert.Equal(new BsonDocument("reference_id", new BsonDocument("$type", 2)),
            options.PartialFilterExpression.Render(new RenderArgs<BsonDocument>(
                BsonSerializer.LookupSerializer<BsonDocument>(), BsonSerializer.SerializerRegistry)));
    }

    [Fact]
    public async Task CreateIndexesAsync_CreatesIndexesForAllCollections()
    {
        // Arrange
        var models = new Dictionary<string, List<CreateIndexModel<BsonDocument>>>(StringComparer.Ordinal);
        var database = CreateDatabase(models);
        var options = new OpenIddictMongoDbOptions();

        // Act
        await database.CreateIndexesAsync(options);

        // Assert
        Assert.Contains(models[options.ApplicationsCollectionName], static model =>
            Render(model.Keys) == new BsonDocument("client_id", 1) && model.Options is { Unique: true });
        Assert.Contains(models[options.ScopesCollectionName], static model =>
            Render(model.Keys) == new BsonDocument("name", 1) && model.Options is { Unique: true });
        Assert.Contains(models[options.ResourcesCollectionName], static model =>
            Render(model.Keys) == new BsonDocument("name", 1) && model.Options is { Unique: true });
        Assert.NotEmpty(models[options.AuthorizationsCollectionName]);
        Assert.NotEmpty(models[options.SessionsCollectionName]);
        Assert.All(models[options.AuthorizationsCollectionName], static model => Assert.Null(model.Options));
    }

    private static BsonDocument Render(IndexKeysDefinition<BsonDocument> keys)
        => keys.Render(new RenderArgs<BsonDocument>(BsonSerializer.LookupSerializer<BsonDocument>(), BsonSerializer.SerializerRegistry));

    private static IMongoDatabase CreateDatabase(Dictionary<string, List<CreateIndexModel<BsonDocument>>> models)
    {
        var database = new Mock<IMongoDatabase>();

        database.Setup(mock => mock.GetCollection<BsonDocument>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()))
            .Returns((string name, MongoCollectionSettings _) =>
            {
                var manager = new Mock<IMongoIndexManager<BsonDocument>>();
                manager.Setup(mock => mock.CreateManyAsync(It.IsAny<IEnumerable<CreateIndexModel<BsonDocument>>>(), It.IsAny<CancellationToken>()))
                    .Callback((IEnumerable<CreateIndexModel<BsonDocument>> values, CancellationToken _) =>
                        models[name] = [.. values])
                    .ReturnsAsync([]);

                var collection = new Mock<IMongoCollection<BsonDocument>>();
                collection.SetupGet(mock => mock.Indexes).Returns(manager.Object);

                return collection.Object;
            });

        return database.Object;
    }
}
