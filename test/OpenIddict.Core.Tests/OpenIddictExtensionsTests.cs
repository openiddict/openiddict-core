using System;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Models;
using Xunit;

namespace OpenIddict.Core.Tests {
    public class OpenIddictExtensionsTests {
        [Theory]
        [InlineData(typeof(OpenIddictApplicationManager<OpenIddictApplication>))]
        [InlineData(typeof(OpenIddictAuthorizationManager<OpenIddictAuthorization>))]
        [InlineData(typeof(OpenIddictScopeManager<OpenIddictScope>))]
        [InlineData(typeof(OpenIddictTokenManager<OpenIddictToken>))]
        public void AddOpenIddict_KeyTypeDefaultsToString(Type type) {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationManager<OpenIddictApplication<Guid, OpenIddictToken<Guid>>>))]
        [InlineData(typeof(OpenIddictAuthorizationManager<OpenIddictAuthorization<Guid, OpenIddictToken<Guid>>>))]
        [InlineData(typeof(OpenIddictScopeManager<OpenIddictScope<Guid>>))]
        [InlineData(typeof(OpenIddictTokenManager<OpenIddictToken<Guid>>))]
        public void AddOpenIddict_KeyTypeCanBeOverriden(Type type) {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict<Guid>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationManager<object>))]
        [InlineData(typeof(OpenIddictAuthorizationManager<object>))]
        [InlineData(typeof(OpenIddictScopeManager<object>))]
        [InlineData(typeof(OpenIddictTokenManager<object>))]
        public void AddOpenIddict_DefaultEntitiesCanBeReplaced(Type type) {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict<object, object, object, object>();

            // Assert
            Assert.Contains(services, service => service.ServiceType == type);
        }
    }
}
