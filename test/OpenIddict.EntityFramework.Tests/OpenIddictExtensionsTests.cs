using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Models;
using Xunit;

namespace OpenIddict.EntityFramework.Tests {
    public class OpenIddictExtensionsTests {
        [Theory]
        [InlineData(typeof(OpenIddictApplicationStore<OpenIddictApplication<Guid, OpenIddictToken<Guid>>, OpenIddictToken<Guid>, DbContext, Guid>))]
        [InlineData(typeof(OpenIddictAuthorizationStore<OpenIddictAuthorization<Guid, OpenIddictToken<Guid>>, OpenIddictToken<Guid>, DbContext, Guid>))]
        [InlineData(typeof(OpenIddictScopeStore<OpenIddictScope<Guid>, DbContext, Guid>))]
        [InlineData(typeof(OpenIddictTokenStore<OpenIddictToken<Guid>, OpenIddictAuthorization<Guid, OpenIddictToken<Guid>>, DbContext, Guid>))]
        public void AddEntityFrameworkStores_RegistersEntityFrameworkStores(Type type) {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict<Guid>()
                .AddEntityFrameworkStores<DbContext, Guid>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationStore<OpenIddictApplication, OpenIddictToken, DbContext, string>))]
        [InlineData(typeof(OpenIddictAuthorizationStore<OpenIddictAuthorization, OpenIddictToken, DbContext, string>))]
        [InlineData(typeof(OpenIddictScopeStore<OpenIddictScope, DbContext, string>))]
        [InlineData(typeof(OpenIddictTokenStore<OpenIddictToken, OpenIddictAuthorization, DbContext, string>))]
        public void AddEntityFrameworkStores_KeyTypeDefaultsToString(Type type) {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict()
                .AddEntityFrameworkStores<DbContext>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }
    }
}
