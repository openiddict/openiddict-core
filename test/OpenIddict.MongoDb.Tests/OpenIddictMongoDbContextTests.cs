/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using Moq;
using OpenIddict.MongoDb.Models;
using Xunit;

namespace OpenIddict.MongoDb.Tests
{
    public class OpenIddictMongoDbContextTests
    {
        [Fact]
        public async Task GetDatabaseAsync_ThrowsAnExceptionForNullOptions()
        {
            // Arrange
            var services = new ServiceCollection();
            var provider = services.BuildServiceProvider();

            var database = GetDatabase();
            var options = Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>();

            var context = new OpenIddictMongoDbContext(options, provider);

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(async delegate
            {
                await context.GetDatabaseAsync(CancellationToken.None);
            });

            Assert.Equal("The OpenIddict MongoDB options cannot be retrieved.", exception.Message);
        }

        [Fact]
        public async Task GetDatabaseAsync_ThrowsAnExceptionForConcurrentCallsWhenInitializationTimesOut()
        {
            // Arrange
            var services = new ServiceCollection();
            var provider = services.BuildServiceProvider();

            var manager = new Mock<IMongoIndexManager<OpenIddictApplication>>();
            manager.Setup(mock => mock.CreateOneAsync(It.IsAny<IndexKeysDefinition<OpenIddictApplication>>(), It.IsAny<CreateIndexOptions>(), It.IsAny<CancellationToken>()))
                .Returns(async delegate
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(1000));
                    return nameof(OpenIddictMongoDbContextTests);
                });

            var collection = new Mock<IMongoCollection<OpenIddictApplication>>();
            collection.SetupGet(mock => mock.Indexes)
                .Returns(manager.Object);

            var database = GetDatabase();
            database.Setup(mock => mock.GetCollection<OpenIddictApplication>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()))
                .Returns(collection.Object);

            var options = Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>(
                mock => mock.CurrentValue == new OpenIddictMongoDbOptions
                {
                    Database = database.Object,
                    InitializationTimeout = TimeSpan.FromMilliseconds(50)
                });

            var context = new OpenIddictMongoDbContext(options, provider);

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return Task.WhenAll(
                    context.GetDatabaseAsync(CancellationToken.None).AsTask(),
                    context.GetDatabaseAsync(CancellationToken.None).AsTask(),
                    context.GetDatabaseAsync(CancellationToken.None).AsTask(),
                    context.GetDatabaseAsync(CancellationToken.None).AsTask());
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("The MongoDB database couldn't be initialized within a reasonable timeframe.")
                .Append("Make sure that the MongoDB server is ready and accepts connections from this machine ")
                .Append("or use 'options.UseMongoDb().SetInitializationTimeout()' to manually adjust the timeout.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task GetDatabaseAsync_PrefersDatabaseRegisteredInOptionsToDatabaseRegisteredInDependencyInjectionContainer()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<IMongoDatabase>());

            var provider = services.BuildServiceProvider();

            var database = GetDatabase();
            var options = Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>(
                mock => mock.CurrentValue == new OpenIddictMongoDbOptions
                {
                    Database = database.Object
                });

            var context = new OpenIddictMongoDbContext(options, provider);

            // Act and assert
            Assert.Same(database.Object, await context.GetDatabaseAsync(CancellationToken.None));
        }

        [Fact]
        public async Task GetDatabaseAsync_ThrowsAnExceptionWhenDatabaseCannotBeFound()
        {
            // Arrange
            var services = new ServiceCollection();
            var provider = services.BuildServiceProvider();

            var database = GetDatabase();
            var options = Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>(
                mock => mock.CurrentValue == new OpenIddictMongoDbOptions
                {
                    Database = null
                });

            var context = new OpenIddictMongoDbContext(options, provider);

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(async delegate
            {
                await context.GetDatabaseAsync(CancellationToken.None);
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("No suitable MongoDB database service can be found.")
                .Append("To configure the OpenIddict MongoDB stores to use a specific database, use ")
                .Append("'services.AddOpenIddict().AddCore().UseMongoDb().UseDatabase()' or register an ")
                .Append("'IMongoDatabase' in the dependency injection container in 'ConfigureServices()'.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task GetDatabaseAsync_UsesDatabaseRegisteredInDependencyInjectionContainer()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<IMongoDatabase>());

            var database = GetDatabase();
            services.AddSingleton(database.Object);

            var provider = services.BuildServiceProvider();

            var options = Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>(
                mock => mock.CurrentValue == new OpenIddictMongoDbOptions
                {
                    Database = null
                });

            var context = new OpenIddictMongoDbContext(options, provider);

            // Act and assert
            Assert.Same(database.Object, await context.GetDatabaseAsync(CancellationToken.None));
        }

        [Fact]
        public async Task GetDatabaseAsync_ReturnsCachedDatabase()
        {
            // Arrange
            var services = new ServiceCollection();
            var provider = services.BuildServiceProvider();

            var database = GetDatabase();
            var options = Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>(
                mock => mock.CurrentValue == new OpenIddictMongoDbOptions
                {
                    Database = database.Object
                });

            var context = new OpenIddictMongoDbContext(options, provider);

            // Act and assert
            Assert.Same(database.Object, await context.GetDatabaseAsync(CancellationToken.None));
            Assert.Same(database.Object, await context.GetDatabaseAsync(CancellationToken.None));

            database.Verify(mock => mock.GetCollection<OpenIddictApplication>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Once());
            database.Verify(mock => mock.GetCollection<OpenIddictScope>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Once());
            database.Verify(mock => mock.GetCollection<OpenIddictToken>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Once());
        }

        [Fact]
        public async Task GetDatabaseAsync_FailedInvocationDoesNotPreventFutureInvocations()
        {
            // Arrange
            var services = new ServiceCollection();
            var provider = services.BuildServiceProvider();

            var count = 0;

            var collection = new Mock<IMongoCollection<OpenIddictApplication>>();
            collection.SetupGet(mock => mock.Indexes)
                .Returns(Mock.Of<IMongoIndexManager<OpenIddictApplication>>());

            var database = GetDatabase();
            database.Setup(mock => mock.GetCollection<OpenIddictApplication>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()))
                .Callback(() => count++)
                .Returns(delegate
                {
                    if (count == 1)
                    {
                        throw new Exception();
                    }

                    return collection.Object;
                });

            var options = Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>(
                mock => mock.CurrentValue == new OpenIddictMongoDbOptions
                {
                    Database = database.Object
                });

            var context = new OpenIddictMongoDbContext(options, provider);

            // Act and assert
            await Assert.ThrowsAsync<Exception>(async () => await context.GetDatabaseAsync(CancellationToken.None));
            Assert.Same(database.Object, await context.GetDatabaseAsync(CancellationToken.None));

            database.Verify(mock => mock.GetCollection<OpenIddictApplication>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Exactly(2));
            database.Verify(mock => mock.GetCollection<OpenIddictScope>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Once());
            database.Verify(mock => mock.GetCollection<OpenIddictToken>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Once());
        }

        private static Mock<IMongoDatabase> GetDatabase()
        {
            var applications = new Mock<IMongoCollection<OpenIddictApplication>>();
            applications.SetupGet(mock => mock.Indexes)
                .Returns(Mock.Of<IMongoIndexManager<OpenIddictApplication>>());

            var scopes = new Mock<IMongoCollection<OpenIddictScope>>();
            scopes.SetupGet(mock => mock.Indexes)
                .Returns(Mock.Of<IMongoIndexManager<OpenIddictScope>>());

            var tokens = new Mock<IMongoCollection<OpenIddictToken>>();
            tokens.SetupGet(mock => mock.Indexes)
                .Returns(Mock.Of<IMongoIndexManager<OpenIddictToken>>());

            var database = new Mock<IMongoDatabase>();
            database.Setup(mock => mock.GetCollection<OpenIddictApplication>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()))
                .Returns(applications.Object);
            database.Setup(mock => mock.GetCollection<OpenIddictScope>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()))
                .Returns(scopes.Object);
            database.Setup(mock => mock.GetCollection<OpenIddictToken>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()))
                .Returns(tokens.Object);

            return database;
        }
    }
}
