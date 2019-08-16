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
using OpenIddict.EntityFramework.Models;
using Xunit;

namespace OpenIddict.EntityFramework.Tests
{
    public class OpenIddictEntityFrameworkExtensionsTests
    {
        [Fact]
        public void UseEntityFramework_ThrowsAnExceptionForNullBuilder()
        {
            // Arrange
            var builder = (OpenIddictCoreBuilder) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.UseEntityFramework());

            Assert.Equal("builder", exception.ParamName);
        }

        [Fact]
        public void UseEntityFramework_ThrowsAnExceptionForNullConfiguration()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictCoreBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.UseEntityFramework(configuration: null));

            Assert.Equal("configuration", exception.ParamName);
        }

        [Fact]
        public void UseEntityFramework_RegistersDefaultEntities()
        {
            // Arrange
            var services = new ServiceCollection().AddOptions();
            var builder = new OpenIddictCoreBuilder(services);

            // Act
            builder.UseEntityFramework();

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
        public void UseEntityFramework_RegistersEntityFrameworkStoreResolvers(Type serviceType, Type implementationType)
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictCoreBuilder(services);

            // Act
            builder.UseEntityFramework();

            // Assert
            Assert.Contains(services, service => service.ServiceType == serviceType &&
                                                 service.ImplementationType == implementationType);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationStore<,,,,>))]
        [InlineData(typeof(OpenIddictAuthorizationStore<,,,,>))]
        [InlineData(typeof(OpenIddictScopeStore<,,>))]
        [InlineData(typeof(OpenIddictTokenStore<,,,,>))]
        public void UseEntityFramework_RegistersEntityFrameworkStore(Type type)
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictCoreBuilder(services);

            // Act
            builder.UseEntityFramework();

            // Assert
            Assert.Contains(services, service => service.ServiceType == type && service.ImplementationType == type);
        }
    }
}
