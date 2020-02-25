/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
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
        public async Task GetDatabaseAsync_ThrowsAnExceptionForCanceledToken()
        {
            // Arrange
            var services = new ServiceCollection();
            var provider = services.BuildServiceProvider();

            var options = Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>();
            var token = new CancellationToken(canceled: true);

            var context = new OpenIddictMongoDbContext(options, provider);

            // Act and assert
            var exception = await Assert.ThrowsAsync<TaskCanceledException>(async delegate
            {
                await context.GetDatabaseAsync(token);
            });

            Assert.Equal(token, exception.CancellationToken);
        }

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

            var manager = new Mock<IMongoIndexManager<OpenIddictMongoDbApplication>>();
            manager.Setup(mock => mock.CreateManyAsync(It.IsAny<IEnumerable<CreateIndexModel<OpenIddictMongoDbApplication>>>(), It.IsAny<CancellationToken>()))
                .Returns(async delegate
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(1000));
                    return new[] { string.Empty };
                });

            var collection = new Mock<IMongoCollection<OpenIddictMongoDbApplication>>();
            collection.SetupGet(mock => mock.Indexes)
                .Returns(manager.Object);

            var database = GetDatabase();
            database.Setup(mock => mock.GetCollection<OpenIddictMongoDbApplication>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()))
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
                .Append("Make sure that the MongoDB server is ready and accepts connections from this machine or use ")
                .Append("'services.AddOpenIddict().AddCore().UseMongoDb().SetInitializationTimeout()' to adjust the timeout.")
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
        public async Task GetDatabaseAsync_SkipsInitializationWhenDisabled()
        {
            // Arrange
            var services = new ServiceCollection();
            var provider = services.BuildServiceProvider();

            var database = GetDatabase();
            var options = Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>(
                mock => mock.CurrentValue == new OpenIddictMongoDbOptions
                {
                    Database = database.Object,
                    DisableInitialization = true
                });

            var context = new OpenIddictMongoDbContext(options, provider);

            // Act
            await context.GetDatabaseAsync(CancellationToken.None);

            // Assert
            database.Verify(mock => mock.GetCollection<OpenIddictMongoDbApplication>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Never());
            database.Verify(mock => mock.GetCollection<OpenIddictMongoDbAuthorization>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Never());
            database.Verify(mock => mock.GetCollection<OpenIddictMongoDbScope>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Never());
            database.Verify(mock => mock.GetCollection<OpenIddictMongoDbToken>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Never());
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

            database.Verify(mock => mock.GetCollection<OpenIddictMongoDbApplication>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Once());
            database.Verify(mock => mock.GetCollection<OpenIddictMongoDbAuthorization>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Once());
            database.Verify(mock => mock.GetCollection<OpenIddictMongoDbScope>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Once());
            database.Verify(mock => mock.GetCollection<OpenIddictMongoDbToken>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Once());
        }

        [Fact]
        public async Task GetDatabaseAsync_FailedInvocationDoesNotPreventFutureInvocations()
        {
            // Arrange
            var services = new ServiceCollection();
            var provider = services.BuildServiceProvider();

            var count = 0;

            var collection = new Mock<IMongoCollection<OpenIddictMongoDbApplication>>();
            collection.SetupGet(mock => mock.Indexes)
                .Returns(Mock.Of<IMongoIndexManager<OpenIddictMongoDbApplication>>());

            var database = GetDatabase();
            database.Setup(mock => mock.GetCollection<OpenIddictMongoDbApplication>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()))
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

            database.Verify(mock => mock.GetCollection<OpenIddictMongoDbApplication>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Exactly(2));
            database.Verify(mock => mock.GetCollection<OpenIddictMongoDbAuthorization>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Once());
            database.Verify(mock => mock.GetCollection<OpenIddictMongoDbScope>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Once());
            database.Verify(mock => mock.GetCollection<OpenIddictMongoDbToken>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()), Times.Once());
        }

        private static Mock<IMongoDatabase> GetDatabase()
        {
            var applications = new Mock<IMongoCollection<OpenIddictMongoDbApplication>>();
            applications.SetupGet(mock => mock.Indexes)
                .Returns(Mock.Of<IMongoIndexManager<OpenIddictMongoDbApplication>>());

            var authorizations = new Mock<IMongoCollection<OpenIddictMongoDbAuthorization>>();
            authorizations.SetupGet(mock => mock.Indexes)
                .Returns(Mock.Of<IMongoIndexManager<OpenIddictMongoDbAuthorization>>());

            var scopes = new Mock<IMongoCollection<OpenIddictMongoDbScope>>();
            scopes.SetupGet(mock => mock.Indexes)
                .Returns(Mock.Of<IMongoIndexManager<OpenIddictMongoDbScope>>());

            var tokens = new Mock<IMongoCollection<OpenIddictMongoDbToken>>();
            tokens.SetupGet(mock => mock.Indexes)
                .Returns(Mock.Of<IMongoIndexManager<OpenIddictMongoDbToken>>());

            var database = new Mock<IMongoDatabase>();
            database.Setup(mock => mock.GetCollection<OpenIddictMongoDbApplication>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()))
                .Returns(applications.Object);
            database.Setup(mock => mock.GetCollection<OpenIddictMongoDbAuthorization>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()))
                .Returns(authorizations.Object);
            database.Setup(mock => mock.GetCollection<OpenIddictMongoDbScope>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()))
                .Returns(scopes.Object);
            database.Setup(mock => mock.GetCollection<OpenIddictMongoDbToken>(It.IsAny<string>(), It.IsAny<MongoCollectionSettings>()))
                .Returns(tokens.Object);

            return database;
        }
    }
}
