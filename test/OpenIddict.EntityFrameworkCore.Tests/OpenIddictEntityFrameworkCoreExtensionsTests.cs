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
using OpenIddict.EntityFrameworkCore.Models;
using Xunit;

namespace OpenIddict.EntityFrameworkCore.Tests
{
    public class OpenIddictEntityFrameworkCoreExtensionsTests
    {
        [Fact]
        public void UseEntityFrameworkCore_ThrowsAnExceptionForNullBuilder()
        {
            // Arrange
            var builder = (OpenIddictCoreBuilder) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.UseEntityFrameworkCore());

            Assert.Equal("builder", exception.ParamName);
        }

        [Fact]
        public void UseEntityFrameworkCore_ThrowsAnExceptionForNullConfiguration()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictCoreBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.UseEntityFrameworkCore(configuration: null));

            Assert.Equal("configuration", exception.ParamName);
        }

        [Fact]
        public void UseEntityFrameworkCore_RegistersDefaultEntities()
        {
            // Arrange
            var services = new ServiceCollection().AddOptions();
            var builder = new OpenIddictCoreBuilder(services);

            // Act
            builder.UseEntityFrameworkCore();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

            Assert.Equal(typeof(OpenIddictApplication), options.DefaultApplicationType);
            Assert.Equal(typeof(OpenIddictAuthorization), options.DefaultAuthorizationType);
            Assert.Equal(typeof(OpenIddictScope), options.DefaultScopeType);
            Assert.Equal(typeof(OpenIddictToken), options.DefaultTokenType);
        }

        [Theory]
        [InlineData(typeof(IOpenIddictApplicationStoreResolver), typeof(OpenIddictApplicationStoreResolver))]
        [InlineData(typeof(IOpenIddictAuthorizationStoreResolver), typeof(OpenIddictAuthorizationStoreResolver))]
        [InlineData(typeof(IOpenIddictScopeStoreResolver), typeof(OpenIddictScopeStoreResolver))]
        [InlineData(typeof(IOpenIddictTokenStoreResolver), typeof(OpenIddictTokenStoreResolver))]
        public void UseEntityFrameworkCore_RegistersEntityFrameworkCoreStoreResolvers(Type serviceType, Type implementationType)
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictCoreBuilder(services);

            // Act
            builder.UseEntityFrameworkCore();

            // Assert
            Assert.Contains(services, service => service.ServiceType == serviceType &&
                                                 service.ImplementationType == implementationType);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationStoreResolver.TypeResolutionCache))]
        [InlineData(typeof(OpenIddictAuthorizationStoreResolver.TypeResolutionCache))]
        [InlineData(typeof(OpenIddictScopeStoreResolver.TypeResolutionCache))]
        [InlineData(typeof(OpenIddictTokenStoreResolver.TypeResolutionCache))]
        public void UseEntityFrameworkCore_RegistersEntityFrameworkCoreStoreResolverCaches(Type type)
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictCoreBuilder(services);

            // Act
            builder.UseEntityFrameworkCore();

            // Assert
            Assert.Contains(services, service => service.ServiceType == type &&
                                                 service.ImplementationType == type);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationStore<,,,,>))]
        [InlineData(typeof(OpenIddictAuthorizationStore<,,,,>))]
        [InlineData(typeof(OpenIddictScopeStore<,,>))]
        [InlineData(typeof(OpenIddictTokenStore<,,,,>))]
        public void UseEntityFrameworkCore_RegistersEntityFrameworkCoreStore(Type type)
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictCoreBuilder(services);

            // Act
            builder.UseEntityFrameworkCore();

            // Assert
            Assert.Contains(services, service => service.ServiceType == type && service.ImplementationType == type);
        }
    }
}
