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
    public class OpenIddictTokenStoreResolverTests
    {
        [Fact]
        public void Get_ReturnsCustomStoreCorrespondingToTheSpecifiedTypeWhenAvailable()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<IOpenIddictTokenStore<CustomToken>>());

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictTokenStoreResolver(provider);

            // Act and assert
            Assert.NotNull(resolver.Get<CustomToken>());
        }

        [Fact]
        public void Get_ThrowsAnExceptionForInvalidEntityType()
        {
            // Arrange
            var services = new ServiceCollection();

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictTokenStoreResolver(provider);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => resolver.Get<CustomToken>());

            Assert.Equal(new StringBuilder()
                .AppendLine("The specified token type is not compatible with the MongoDB stores.")
                .Append("When enabling the MongoDB stores, make sure you use the built-in 'OpenIddictToken' ")
                .Append("entity (from the 'OpenIddict.MongoDb.Models' package) or a custom entity ")
                .Append("that inherits from the 'OpenIddictToken' entity.")
                .ToString(), exception.Message);
        }

        [Fact]
        public void Get_ReturnsDefaultStoreCorrespondingToTheSpecifiedTypeWhenAvailable()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<IOpenIddictTokenStore<CustomToken>>());
            services.AddSingleton(CreateStore());

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictTokenStoreResolver(provider);

            // Act and assert
            Assert.NotNull(resolver.Get<MyToken>());
        }

        private static OpenIddictTokenStore<MyToken> CreateStore()
            => new Mock<OpenIddictTokenStore<MyToken>>(
                Mock.Of<IOpenIddictMongoDbContext>(),
                Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>()).Object;

        public class CustomToken { }

        public class MyToken : OpenIddictToken { }
    }
}
