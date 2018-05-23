/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Core;
using OpenIddict.EntityFramework.Models;
using Xunit;

namespace OpenIddict.EntityFramework.Tests
{
    public class OpenIddictEntityFrameworkExtensionsTests
    {
        [Theory]
        [InlineData(typeof(OpenIddictApplicationStoreResolver))]
        [InlineData(typeof(OpenIddictAuthorizationStoreResolver))]
        [InlineData(typeof(OpenIddictScopeStoreResolver))]
        [InlineData(typeof(OpenIddictTokenStoreResolver))]
        public void AddEntityFrameworkStores_RegistersEntityFrameworkStoreFactories(Type type)
        {
            // Arrange
            var services = new ServiceCollection().AddOptions();
            var builder = new OpenIddictCoreBuilder(services);

            // Act
            builder.UseEntityFramework();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }

        [Fact]
        public void UseEntityFrameworkModels_KeyTypeDefaultsToString()
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
    }
}
