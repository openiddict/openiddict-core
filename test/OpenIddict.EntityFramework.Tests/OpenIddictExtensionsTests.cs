using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace OpenIddict.EntityFramework.Tests {
    public class OpenIddictExtensionsTests {
        [Theory]
        [InlineData(typeof(OpenIddictApplicationStore<OpenIddictApplication<Guid>, OpenIddictToken<Guid>, OpenIddictDbContext, Guid>))]
        [InlineData(typeof(OpenIddictAuthorizationStore<OpenIddictAuthorization<Guid>, OpenIddictToken<Guid>, OpenIddictDbContext, Guid>))]
        [InlineData(typeof(OpenIddictScopeStore<OpenIddictScope<Guid>, OpenIddictDbContext, Guid>))]
        [InlineData(typeof(OpenIddictTokenStore<OpenIddictToken<Guid>, OpenIddictAuthorization<Guid>, OpenIddictDbContext, Guid>))]
        public void AddEntityFramework_RegistersEntityFrameworkStores(Type type) {
            // Arrange
            var services = new ServiceCollection();

            var builder = new OpenIddictBuilder(services) {
                ApplicationType = typeof(OpenIddictApplication<Guid>),
                AuthorizationType = typeof(OpenIddictAuthorization<Guid>),
                ScopeType = typeof(OpenIddictScope<Guid>),
                TokenType = typeof(OpenIddictToken<Guid>)
            };

            // Act
            builder.AddEntityFramework<OpenIddictDbContext, Guid>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationStore<OpenIddictApplication, OpenIddictToken, OpenIddictDbContext, string>))]
        [InlineData(typeof(OpenIddictAuthorizationStore<OpenIddictAuthorization, OpenIddictToken, OpenIddictDbContext, string>))]
        [InlineData(typeof(OpenIddictScopeStore<OpenIddictScope, OpenIddictDbContext, string>))]
        [InlineData(typeof(OpenIddictTokenStore<OpenIddictToken, OpenIddictAuthorization, OpenIddictDbContext, string>))]
        public void AddEntityFramework_KeyTypeDefaultsToString(Type type) {
            // Arrange
            var services = new ServiceCollection();

            var builder = new OpenIddictBuilder(services) {
                ApplicationType = typeof(OpenIddictApplication),
                AuthorizationType = typeof(OpenIddictAuthorization),
                ScopeType = typeof(OpenIddictScope),
                TokenType = typeof(OpenIddictToken)
            };

            // Act
            builder.AddEntityFramework<OpenIddictDbContext>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }
    }
}
