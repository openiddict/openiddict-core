using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Models;
using Xunit;

namespace OpenIddict.EntityFrameworkCore.Tests {
    public class OpenIddictExtensionsTests {
        [Fact]
        public void AddEntityFrameworkCoreStores_ThrowsAnExceptionForInvalidApplicationEntity() {
            // Arrange
            var services = new ServiceCollection();

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate {
                services.AddOpenIddict<object, OpenIddictAuthorization, OpenIddictScope, OpenIddictToken>()
                    .AddEntityFrameworkCoreStores<DbContext>();
            });

            Assert.Equal("The Entity Framework stores can only be used " +
                         "with the built-in OpenIddictApplication entity.", exception.Message);
        }

        [Fact]
        public void AddEntityFrameworkCoreStores_ThrowsAnExceptionForInvalidAuthorizationEntity() {
            // Arrange
            var services = new ServiceCollection();

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate {
                services.AddOpenIddict<OpenIddictApplication, object, OpenIddictScope, OpenIddictToken>()
                    .AddEntityFrameworkCoreStores<DbContext>();
            });

            Assert.Equal("The Entity Framework stores can only be used " +
                         "with the built-in OpenIddictAuthorization entity.", exception.Message);
        }

        [Fact]
        public void AddEntityFrameworkCoreStores_ThrowsAnExceptionForInvalidScopeEntity() {
            // Arrange
            var services = new ServiceCollection();

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate {
                services.AddOpenIddict<OpenIddictApplication, OpenIddictAuthorization, object, OpenIddictToken>()
                    .AddEntityFrameworkCoreStores<DbContext>();
            });

            Assert.Equal("The Entity Framework stores can only be used " +
                         "with the built-in OpenIddictScope entity.", exception.Message);
        }

        [Fact]
        public void AddEntityFrameworkCoreStores_ThrowsAnExceptionForInvalidTokenEntity() {
            // Arrange
            var services = new ServiceCollection();

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate {
                services.AddOpenIddict<OpenIddictApplication, OpenIddictAuthorization, OpenIddictScope, object>()
                    .AddEntityFrameworkCoreStores<DbContext>();
            });

            Assert.Equal("The Entity Framework stores can only be used " +
                         "with the built-in OpenIddictToken entity.", exception.Message);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationStore<OpenIddictApplication, OpenIddictToken, DbContext, string>))]
        [InlineData(typeof(OpenIddictAuthorizationStore<OpenIddictAuthorization, OpenIddictToken, DbContext, string>))]
        [InlineData(typeof(OpenIddictScopeStore<OpenIddictScope, DbContext, string>))]
        [InlineData(typeof(OpenIddictTokenStore<OpenIddictToken, OpenIddictAuthorization, DbContext, string>))]
        public void AddEntityFrameworkCoreStores_RegistersEntityFrameworkStores(Type type) {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict()
                .AddEntityFrameworkCoreStores<DbContext>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationStore<OpenIddictApplication<Guid>, OpenIddictToken<Guid>, DbContext, Guid>))]
        [InlineData(typeof(OpenIddictAuthorizationStore<OpenIddictAuthorization<Guid>, OpenIddictToken<Guid>, DbContext, Guid>))]
        [InlineData(typeof(OpenIddictScopeStore<OpenIddictScope<Guid>, DbContext, Guid>))]
        [InlineData(typeof(OpenIddictTokenStore<OpenIddictToken<Guid>, OpenIddictAuthorization<Guid>, DbContext, Guid>))]
        public void AddEntityFrameworkCoreStores_KeyTypeIsInferredFromEntities(Type type) {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict<Guid>()
                .AddEntityFrameworkCoreStores<DbContext>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationStore<CustomApplication, CustomToken, DbContext, long>))]
        [InlineData(typeof(OpenIddictAuthorizationStore<CustomAuthorization, CustomToken, DbContext, long>))]
        [InlineData(typeof(OpenIddictScopeStore<CustomScope, DbContext, long>))]
        [InlineData(typeof(OpenIddictTokenStore<CustomToken, CustomAuthorization, DbContext, long>))]
        public void AddEntityFrameworkCoreStores_DefaultEntitiesCanBeReplaced(Type type) {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict<CustomApplication, CustomAuthorization, CustomScope, CustomToken>()
                .AddEntityFrameworkCoreStores<DbContext>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }

        public class CustomApplication : OpenIddictApplication<long, CustomToken> { }
        public class CustomAuthorization : OpenIddictAuthorization<long, CustomToken> { }
        public class CustomScope : OpenIddictScope<long> { }
        public class CustomToken : OpenIddictToken<long> { }
    }
}
