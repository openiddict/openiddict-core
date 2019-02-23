/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Abstractions;
using OpenIddict.NHibernate.Models;
using Xunit;
using static OpenIddict.NHibernate.OpenIddictTokenStoreResolver;

namespace OpenIddict.NHibernate.Tests
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
            var resolver = new OpenIddictTokenStoreResolver(new TypeResolutionCache(), provider);

            // Act and assert
            Assert.NotNull(resolver.Get<CustomToken>());
        }

        [Fact]
        public void Get_ThrowsAnExceptionForInvalidEntityType()
        {
            // Arrange
            var services = new ServiceCollection();

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictTokenStoreResolver(new TypeResolutionCache(), provider);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => resolver.Get<CustomToken>());

            Assert.Equal(new StringBuilder()
                .AppendLine("The specified token type is not compatible with the NHibernate stores.")
                .Append("When enabling the NHibernate stores, make sure you use the built-in ")
                .Append("'OpenIddictToken' entity (from the 'OpenIddict.NHibernate.Models' package) ")
                .Append("or a custom entity that inherits from the generic 'OpenIddictToken' entity.")
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
            var resolver = new OpenIddictTokenStoreResolver(new TypeResolutionCache(), provider);

            // Act and assert
            Assert.NotNull(resolver.Get<MyToken>());
        }

        private static OpenIddictTokenStore<MyToken, MyApplication, MyAuthorization, long> CreateStore()
            => new Mock<OpenIddictTokenStore<MyToken, MyApplication, MyAuthorization, long>>(
                Mock.Of<IMemoryCache>(),
                Mock.Of<IOpenIddictNHibernateContext>(),
                Mock.Of<IOptionsMonitor<OpenIddictNHibernateOptions>>()).Object;

        public class CustomToken { }

        public class MyApplication : OpenIddictApplication<long, MyAuthorization, MyToken> { }
        public class MyAuthorization : OpenIddictAuthorization<long, MyApplication, MyToken> { }
        public class MyScope : OpenIddictScope<long> { }
        public class MyToken : OpenIddictToken<long, MyApplication, MyAuthorization> { }
    }
}
