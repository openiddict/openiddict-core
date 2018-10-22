/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Conventions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
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
            var options = provider.GetRequiredService<IOptions<OpenIddictCoreOptions>>().Value;

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

        [Fact]
        public void UseOpenIddict_RegistersDefaultEntityConfigurations()
        {
            // Arrange
            var builder = new ModelBuilder(new ConventionSet());

            // Act
            builder.UseOpenIddict();

            // Assert
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictApplication)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictAuthorization)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictScope)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictToken)));
        }

        [Fact]
        public void UseOpenIddict_RegistersDefaultEntityConfigurationsWithCustomKeyType()
        {
            // Arrange
            var builder = new ModelBuilder(new ConventionSet());

            // Act
            builder.UseOpenIddict<long>();

            // Assert
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictApplication<long>)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictAuthorization<long>)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictScope<long>)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictToken<long>)));
        }

        [Fact]
        public void UseOpenIddict_RegistersCustomEntityConfigurations()
        {
            // Arrange
            var builder = new ModelBuilder(new ConventionSet());

            // Act
            builder.UseOpenIddict<CustomApplication, CustomAuthorization, CustomScope, CustomToken, Guid>();

            // Assert
            Assert.NotNull(builder.Model.FindEntityType(typeof(CustomApplication)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(CustomAuthorization)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(CustomScope)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(CustomToken)));
        }

        public class CustomApplication : OpenIddictApplication<Guid, CustomAuthorization, CustomToken> { }
        public class CustomAuthorization : OpenIddictAuthorization<Guid, CustomApplication, CustomToken> { }
        public class CustomScope : OpenIddictScope<Guid> { }
        public class CustomToken : OpenIddictToken<Guid, CustomApplication, CustomAuthorization> { }
    }
}
