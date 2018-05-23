/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore.Models;
using Xunit;

namespace OpenIddict.EntityFrameworkCore.Tests
{
    public class OpenIddictEntityFrameworkCoreExtensionsTests
    {
        [Theory]
        [InlineData(typeof(OpenIddictApplicationStoreResolver))]
        [InlineData(typeof(OpenIddictAuthorizationStoreResolver))]
        [InlineData(typeof(OpenIddictScopeStoreResolver))]
        [InlineData(typeof(OpenIddictTokenStoreResolver))]
        public void UseEntityFrameworkCore_RegistersEntityFrameworkCoreStoreFactories(Type type)
        {
            // Arrange
            var services = new ServiceCollection().AddOptions();
            var builder = new OpenIddictCoreBuilder(services);

            // Act
            builder.UseEntityFrameworkCore();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }

        [Fact]
        public void UseEntityFrameworkCore_KeyTypeDefaultsToString()
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

        [Fact]
        public void UseEntityFrameworkCore_KeyTypeCanBeOverriden()
        {
            // Arrange
            var services = new ServiceCollection().AddOptions();
            var builder = new OpenIddictCoreBuilder(services);

            // Act
            builder.UseEntityFrameworkCore().ReplaceDefaultEntities<Guid>();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

            Assert.Equal(typeof(OpenIddictApplication<Guid>), options.DefaultApplicationType);
            Assert.Equal(typeof(OpenIddictAuthorization<Guid>), options.DefaultAuthorizationType);
            Assert.Equal(typeof(OpenIddictScope<Guid>), options.DefaultScopeType);
            Assert.Equal(typeof(OpenIddictToken<Guid>), options.DefaultTokenType);
        }
    }
}
