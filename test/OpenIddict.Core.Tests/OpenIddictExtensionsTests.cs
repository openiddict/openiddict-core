/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace OpenIddict.Core.Tests
{
    public class OpenIddictExtensionsTests
    {
        [Fact]
        public void AddOpenIddict_CustomEntitiesAreCorrectlySet()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            var builder = services.AddOpenIddict<object, object, object, object>();

            // Assert
            Assert.Equal(typeof(object), builder.ApplicationType);
            Assert.Equal(typeof(object), builder.AuthorizationType);
            Assert.Equal(typeof(object), builder.ScopeType);
            Assert.Equal(typeof(object), builder.TokenType);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationManager<object>))]
        [InlineData(typeof(OpenIddictAuthorizationManager<object>))]
        [InlineData(typeof(OpenIddictScopeManager<object>))]
        [InlineData(typeof(OpenIddictTokenManager<object>))]
        public void AddOpenIddict_ManagersForCustomEntitiesAreCorrectlyRegistered(Type type)
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict<object, object, object, object>();

            // Assert
            Assert.Contains(services, service => service.ServiceType == type);
        }
    }
}
