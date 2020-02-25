/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.MongoDb.Models;
using Xunit;

namespace OpenIddict.MongoDb.Tests
{
    public class OpenIddictMongoDbExtensionsTests
    {
        [Fact]
        public void UseMongoDb_ThrowsAnExceptionForNullBuilder()
        {
            // Arrange
            var builder = (OpenIddictCoreBuilder) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.UseMongoDb());

            Assert.Equal("builder", exception.ParamName);
        }

        [Fact]
        public void UseMongoDb_ThrowsAnExceptionForNullConfiguration()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictCoreBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.UseMongoDb(configuration: null));

            Assert.Equal("configuration", exception.ParamName);
        }

        [Fact]
        public void UseMongoDb_RegistersDefaultEntities()
        {
            // Arrange
            var services = new ServiceCollection().AddOptions();
            var builder = new OpenIddictCoreBuilder(services);

            // Act
            builder.UseMongoDb();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

            Assert.Equal(typeof(OpenIddictMongoDbApplication), options.DefaultApplicationType);
            Assert.Equal(typeof(OpenIddictMongoDbAuthorization), options.DefaultAuthorizationType);
            Assert.Equal(typeof(OpenIddictMongoDbScope), options.DefaultScopeType);
            Assert.Equal(typeof(OpenIddictMongoDbToken), options.DefaultTokenType);
        }

        [Theory]
        [InlineData(typeof(IOpenIddictApplicationStoreResolver), typeof(OpenIddictMongoDbApplicationStoreResolver))]
        [InlineData(typeof(IOpenIddictAuthorizationStoreResolver), typeof(OpenIddictMongoDbAuthorizationStoreResolver))]
        [InlineData(typeof(IOpenIddictScopeStoreResolver), typeof(OpenIddictMongoDbScopeStoreResolver))]
        [InlineData(typeof(IOpenIddictTokenStoreResolver), typeof(OpenIddictMongoDbTokenStoreResolver))]
        public void UseMongoDb_RegistersMongoDbStoreResolvers(Type serviceType, Type implementationType)
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictCoreBuilder(services);

            // Act
            builder.UseMongoDb();

            // Assert
            Assert.Contains(services, service => service.ServiceType == serviceType &&
                                                 service.ImplementationType == implementationType);
        }

        [Theory]
        [InlineData(typeof(OpenIddictMongoDbApplicationStore<>))]
        [InlineData(typeof(OpenIddictMongoDbAuthorizationStore<>))]
        [InlineData(typeof(OpenIddictMongoDbScopeStore<>))]
        [InlineData(typeof(OpenIddictMongoDbTokenStore<>))]
        public void UseMongoDb_RegistersMongoDbStore(Type type)
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictCoreBuilder(services);

            // Act
            builder.UseMongoDb();

            // Assert
            Assert.Contains(services, service => service.ServiceType == type && service.ImplementationType == type);
        }

        [Fact]
        public void UseMongoDb_RegistersMongoDbContext()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictCoreBuilder(services);

            // Act
            builder.UseMongoDb();

            // Assert
            Assert.Contains(services, service => service.Lifetime == ServiceLifetime.Singleton &&
                                                 service.ServiceType == typeof(IOpenIddictMongoDbContext) &&
                                                 service.ImplementationType == typeof(OpenIddictMongoDbContext));
        }
    }
}
