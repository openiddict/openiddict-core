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
using static OpenIddict.NHibernate.OpenIddictAuthorizationStoreResolver;

namespace OpenIddict.NHibernate.Tests
{
    public class OpenIddictAuthorizationStoreResolverTests
    {
        [Fact]
        public void Get_ReturnsCustomStoreCorrespondingToTheSpecifiedTypeWhenAvailable()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>());

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictAuthorizationStoreResolver(new TypeResolutionCache(), provider);

            // Act and assert
            Assert.NotNull(resolver.Get<CustomAuthorization>());
        }

        [Fact]
        public void Get_ThrowsAnExceptionForInvalidEntityType()
        {
            // Arrange
            var services = new ServiceCollection();

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictAuthorizationStoreResolver(new TypeResolutionCache(), provider);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => resolver.Get<CustomAuthorization>());

            Assert.Equal(new StringBuilder()
                .AppendLine("The specified authorization type is not compatible with the NHibernate stores.")
                .Append("When enabling the NHibernate stores, make sure you use the built-in ")
                .Append("'OpenIddictAuthorization' entity (from the 'OpenIddict.NHibernate.Models' package) ")
                .Append("or a custom entity that inherits from the generic 'OpenIddictAuthorization' entity.")
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
            var resolver = new OpenIddictAuthorizationStoreResolver(new TypeResolutionCache(), provider);

            // Act and assert
            Assert.NotNull(resolver.Get<MyAuthorization>());
        }

        private static OpenIddictAuthorizationStore<MyAuthorization, MyApplication, MyToken, long> CreateStore()
            => new Mock<OpenIddictAuthorizationStore<MyAuthorization, MyApplication, MyToken, long>>(
                Mock.Of<IMemoryCache>(),
                Mock.Of<IOpenIddictNHibernateContext>(),
                Mock.Of<IOptionsMonitor<OpenIddictNHibernateOptions>>()).Object;

        public class CustomAuthorization { }

        public class MyApplication : OpenIddictApplication<long, MyAuthorization, MyToken> { }
        public class MyAuthorization : OpenIddictAuthorization<long, MyApplication, MyToken> { }
        public class MyScope : OpenIddictScope<long> { }
        public class MyToken : OpenIddictToken<long, MyApplication, MyAuthorization> { }
    }
}
