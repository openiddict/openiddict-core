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
    public class OpenIddictScopeStoreResolverTests
    {
        [Fact]
        public void Get_ReturnsCustomStoreCorrespondingToTheSpecifiedTypeWhenAvailable()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<IOpenIddictScopeStore<CustomScope>>());

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictScopeStoreResolver(provider);

            // Act and assert
            Assert.NotNull(resolver.Get<CustomScope>());
        }

        [Fact]
        public void Get_ThrowsAnExceptionForInvalidEntityType()
        {
            // Arrange
            var services = new ServiceCollection();

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictScopeStoreResolver(provider);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => resolver.Get<CustomScope>());

            Assert.Equal(new StringBuilder()
                .AppendLine("The specified scope type is not compatible with the MongoDB stores.")
                .Append("When enabling the MongoDB stores, make sure you use the built-in 'OpenIddictScope' ")
                .Append("entity (from the 'OpenIddict.MongoDb.Models' package) or a custom entity ")
                .Append("that inherits from the 'OpenIddictScope' entity.")
                .ToString(), exception.Message);
        }

        [Fact]
        public void Get_ReturnsDefaultStoreCorrespondingToTheSpecifiedTypeWhenAvailable()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<IOpenIddictScopeStore<CustomScope>>());
            services.AddSingleton(CreateStore());

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictScopeStoreResolver(provider);

            // Act and assert
            Assert.NotNull(resolver.Get<MyScope>());
        }

        private static OpenIddictScopeStore<MyScope> CreateStore()
            => new Mock<OpenIddictScopeStore<MyScope>>(
                Mock.Of<IOpenIddictMongoDbContext>(),
                Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>()).Object;

        public class CustomScope { }

        public class MyScope : OpenIddictScope { }
    }
}
