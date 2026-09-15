/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Driver;
using MongoDB.Driver.Core.Clusters;
using MongoDB.Driver.Core.Connections;
using MongoDB.Driver.Core.Servers;
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
        Assert.Equal("openiddict_reference_id", options.Name);
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
        Assert.All(models.Values.SelectMany(static values => values), static model =>
            Assert.StartsWith("openiddict_", model.Options.Name, StringComparison.Ordinal));
        Assert.All(models[options.AuthorizationsCollectionName], static model => Assert.NotEqual(true, model.Options.Unique));
    }

    [Theory]
    [InlineData(85)]
    [InlineData(86)]
    public async Task CreateIndexesAsync_IgnoresConflictsWithExistingIndexes(int code)
    {
        // Arrange
        var models = new Dictionary<string, List<CreateIndexModel<BsonDocument>>>(StringComparer.Ordinal);
        var options = new OpenIddictMongoDbOptions();
        var database = CreateDatabase(models, model => model.Options.Name is "openiddict_reference_id" ? code : null);

        // Act
        await database.CreateIndexesAsync(options);

        // Assert
        Assert.DoesNotContain(models[options.TokensCollectionName], static model => model.Options.Name is "openiddict_reference_id");
        Assert.Contains(models[options.TokensCollectionName], static model => model.Options.Name is "openiddict_authorization_id");
    }

    [Fact]
    public async Task CreateIndexesAsync_DoesNotIgnoreOtherErrors()
    {
        // Arrange
        var models = new Dictionary<string, List<CreateIndexModel<BsonDocument>>>(StringComparer.Ordinal);
        var database = CreateDatabase(models, model => model.Options.Name is "openiddict_reference_id" ? 13 : null);

        // Act and assert
        var exception = await Assert.ThrowsAsync<MongoCommandException>(() => database.CreateIndexesAsync());
        Assert.Equal(13, exception.Code);
    }

    private static BsonDocument Render(IndexKeysDefinition<BsonDocument> keys)
        => keys.Render(new RenderArgs<BsonDocument>(BsonSerializer.LookupSerializer<BsonDocument>(), BsonSerializer.SerializerRegistry));

    private static IMongoDatabase CreateDatabase(
        Dictionary<string, List<CreateIndexModel<BsonDocument>>> models,
        Func<CreateIndexModel<BsonDocument>, int?>? error = null)
    {
        var database = new Mock<IMongoDatabase>();

        database.Setup(mock => mock.GetCollection<BsonDocument>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()))
            .Returns((string name, MongoCollectionSettings _) =>
            {
                var manager = new Mock<IMongoIndexManager<BsonDocument>>();
                manager.Setup(mock => mock.CreateOneAsync(It.IsAny<CreateIndexModel<BsonDocument>>(),
                    It.IsAny<CreateOneIndexOptions>(), It.IsAny<CancellationToken>()))
                    .Returns((CreateIndexModel<BsonDocument> model, CreateOneIndexOptions _, CancellationToken _) =>
                    {
                        if (error?.Invoke(model) is int code)
                        {
                            throw new MongoCommandException(
                                new ConnectionId(new ServerId(new ClusterId(), new DnsEndPoint("localhost", 27017))),
                                "Index conflict.", new BsonDocument(), new BsonDocument { ["ok"] = 0, ["code"] = code });
                        }

                        if (!models.TryGetValue(name, out var values))
                        {
                            models[name] = values = [];
                        }

                        values.Add(model);

                        return Task.FromResult(model.Options.Name);
                    });

                var collection = new Mock<IMongoCollection<BsonDocument>>();
                collection.SetupGet(mock => mock.Indexes).Returns(manager.Object);

                return collection.Object;
            });

        return database.Object;
    }
}
