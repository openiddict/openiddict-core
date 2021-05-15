﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Abstractions;
using OpenIddict.MongoDb.KeyGenerators;
using OpenIddict.MongoDb.Models;
using Xunit;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.MongoDb.Tests
{
    public class OpenIddictMongoDbScopeStoreResolverTests
    {
        [Fact]
        public void Get_ReturnsCustomStoreCorrespondingToTheSpecifiedTypeWhenAvailable()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<IOpenIddictScopeStore<CustomScope>>());

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictMongoDbScopeStoreResolver(provider);

            // Act and assert
            Assert.NotNull(resolver.Get<CustomScope>());
        }

        [Fact]
        public void Get_ThrowsAnExceptionForInvalidEntityType()
        {
            // Arrange
            var services = new ServiceCollection();

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictMongoDbScopeStoreResolver(provider);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => resolver.Get<CustomScope>());

            Assert.Equal(SR.GetResourceString(SR.ID0259), exception.Message);
        }

        [Fact]
        public void Get_ReturnsDefaultStoreCorrespondingToTheSpecifiedTypeWhenAvailable()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<IOpenIddictScopeStore<CustomScope>>());
            services.AddSingleton(CreateStore());

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictMongoDbScopeStoreResolver(provider);

            // Act and assert
            Assert.NotNull(resolver.Get<MyScope>());
        }

        [Fact]
        public void Get_StringKey_ReturnsDefaultStoreCorrespondingToTheSpecifiedTypeWhenAvailable()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<IOpenIddictScopeStore<CustomScope>>());
            services.AddSingleton(CreateStoreWithStringKey());

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictMongoDbScopeStoreResolver(provider);

            // Act and assert
            Assert.NotNull(resolver.Get<MyScopeWithStringKey>());
        }

        private static OpenIddictMongoDbScopeStore<MyScope> CreateStore()
            => new Mock<OpenIddictMongoDbScopeStore<MyScope>>(
                Mock.Of<IOpenIddictMongoDbContext>(),
                Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>()).Object;

        private static OpenIddictMongoDbScopeStore<MyScopeWithStringKey, string> CreateStoreWithStringKey()
            => new Mock<OpenIddictMongoDbScopeStore<MyScopeWithStringKey, string>>(
                StringKeyGenerator.Default,
                Mock.Of<IOpenIddictMongoDbContext>(),
                Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>()).Object;

        public class CustomScope { }

        public class MyScope : OpenIddictMongoDbScope { }

        public class MyScopeWithStringKey : OpenIddictMongoDbScope<string> { }
    }
}
