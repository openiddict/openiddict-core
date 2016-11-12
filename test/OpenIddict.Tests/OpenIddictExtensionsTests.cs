using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace OpenIddict.Tests {
    public class OpenIddictExtensionsTests {
        [Theory]
        [InlineData(typeof(OpenIddictApplicationManager<OpenIddictApplication<Guid>>))]
        [InlineData(typeof(OpenIddictAuthorizationManager<OpenIddictAuthorization<Guid>>))]
        [InlineData(typeof(OpenIddictScopeManager<OpenIddictScope<Guid>>))]
        [InlineData(typeof(OpenIddictTokenManager<OpenIddictToken<Guid>>))]
        public void AddOpenIddict_RegistersCoreManagers(Type type) {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict<OpenIddictDbContext, Guid>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationStore<OpenIddictApplication<Guid>, OpenIddictToken<Guid>, OpenIddictDbContext, Guid>))]
        [InlineData(typeof(OpenIddictAuthorizationStore<OpenIddictAuthorization<Guid>, OpenIddictToken<Guid>, OpenIddictDbContext, Guid>))]
        [InlineData(typeof(OpenIddictScopeStore<OpenIddictScope<Guid>, OpenIddictDbContext, Guid>))]
        [InlineData(typeof(OpenIddictTokenStore<OpenIddictToken<Guid>, OpenIddictAuthorization<Guid>, OpenIddictDbContext, Guid>))]
        public void AddOpenIddict_RegistersEntityFrameworkStores(Type type) {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict<OpenIddictDbContext, Guid>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationManager<OpenIddictApplication>))]
        [InlineData(typeof(OpenIddictAuthorizationManager<OpenIddictAuthorization>))]
        [InlineData(typeof(OpenIddictScopeManager<OpenIddictScope>))]
        [InlineData(typeof(OpenIddictTokenManager<OpenIddictToken>))]
        [InlineData(typeof(OpenIddictApplicationStore<OpenIddictApplication, OpenIddictToken, OpenIddictDbContext, string>))]
        [InlineData(typeof(OpenIddictAuthorizationStore<OpenIddictAuthorization, OpenIddictToken, OpenIddictDbContext, string>))]
        [InlineData(typeof(OpenIddictScopeStore<OpenIddictScope, OpenIddictDbContext, string>))]
        [InlineData(typeof(OpenIddictTokenStore<OpenIddictToken, OpenIddictAuthorization, OpenIddictDbContext, string>))]
        public void AddOpenIddict_KeyTypeDefaultsToString(Type type) {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict<OpenIddictDbContext>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }
    }
}
