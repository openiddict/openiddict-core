/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Abstractions;
using OpenIddict.MongoDb.Models;
using Xunit;

namespace OpenIddict.MongoDb.Tests
{
    public class OpenIddictMongoDbAuthorizationStoreResolverTests
    {
        [Fact]
        public void Get_ReturnsCustomStoreCorrespondingToTheSpecifiedTypeWhenAvailable()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>());

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictMongoDbAuthorizationStoreResolver(provider);

            // Act and assert
            Assert.NotNull(resolver.Get<CustomAuthorization>());
        }

        [Fact]
        public void Get_ThrowsAnExceptionForInvalidEntityType()
        {
            // Arrange
            var services = new ServiceCollection();

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictMongoDbAuthorizationStoreResolver(provider);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => resolver.Get<CustomAuthorization>());

            Assert.Equal(new StringBuilder()
                .AppendLine("The specified authorization type is not compatible with the MongoDB stores.")
                .Append("When enabling the MongoDB stores, make sure you use the built-in ")
                .Append("'OpenIddictMongoDbAuthorization' entity or a custom entity that inherits ")
                .Append("from the 'OpenIddictMongoDbAuthorization' entity.")
                .ToString(), exception.Message);
        }

        [Fact]
        public void Get_ReturnsDefaultStoreCorrespondingToTheSpecifiedTypeWhenAvailable()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>());
            services.AddSingleton(CreateStore());

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictMongoDbAuthorizationStoreResolver(provider);

            // Act and assert
            Assert.NotNull(resolver.Get<MyAuthorization>());
        }

        private static OpenIddictMongoDbAuthorizationStore<MyAuthorization> CreateStore()
            => new Mock<OpenIddictMongoDbAuthorizationStore<MyAuthorization>>(
                Mock.Of<IOpenIddictMongoDbContext>(),
                Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>()).Object;

        public class CustomAuthorization { }

        public class MyAuthorization : OpenIddictMongoDbAuthorization { }
    }
}
