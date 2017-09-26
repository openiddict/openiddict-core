using System;
using System.Data.Entity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.EntityFramework;
using OpenIddict.Models;
using Xunit;

namespace OpenIddict.EntityFrameworkCore.Tests
{
    public class OpenIddictExtensionsTests
    {
        [Fact]
        public void AddEntityFrameworkStores_ThrowsAnExceptionForInvalidApplicationEntity()
        {
            // Arrange
            var builder = new OpenIddictBuilder(new ServiceCollection())
            {
                ApplicationType = typeof(object)
            };

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate
            {
                builder.AddEntityFrameworkStores<DbContext>();
            });

            Assert.Equal("The Entity Framework stores can only be used " +
                         "with the built-in OpenIddictApplication entity.", exception.Message);
        }

        [Fact]
        public void AddEntityFrameworkStores_ThrowsAnExceptionForInvalidAuthorizationEntity()
        {
            // Arrange
            var builder = new OpenIddictBuilder(new ServiceCollection())
            {
                AuthorizationType = typeof(object)
            };

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate
            {
                builder.AddEntityFrameworkStores<DbContext>();
            });

            Assert.Equal("The Entity Framework stores can only be used " +
                         "with the built-in OpenIddictAuthorization entity.", exception.Message);
        }

        [Fact]
        public void AddEntityFrameworkStores_ThrowsAnExceptionForInvalidScopeEntity()
        {
            // Arrange
            var builder = new OpenIddictBuilder(new ServiceCollection())
            {
                ScopeType = typeof(object)
            };

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate
            {
                builder.AddEntityFrameworkStores<DbContext>();
            });

            Assert.Equal("The Entity Framework stores can only be used " +
                         "with the built-in OpenIddictScope entity.", exception.Message);
        }

        [Fact]
        public void AddEntityFrameworkStores_ThrowsAnExceptionForInvalidTokenEntity()
        {
            // Arrange
            var builder = new OpenIddictBuilder(new ServiceCollection())
            {
                TokenType = typeof(object)
            };

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(delegate
            {
                builder.AddEntityFrameworkStores<DbContext>();
            });

            Assert.Equal("The Entity Framework stores can only be used " +
                         "with the built-in OpenIddictToken entity.", exception.Message);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationStore<OpenIddictApplication, OpenIddictAuthorization, OpenIddictToken, DbContext, string>))]
        [InlineData(typeof(OpenIddictAuthorizationStore<OpenIddictAuthorization, OpenIddictApplication, OpenIddictToken, DbContext, string>))]
        [InlineData(typeof(OpenIddictScopeStore<OpenIddictScope, DbContext, string>))]
        [InlineData(typeof(OpenIddictTokenStore<OpenIddictToken, OpenIddictApplication, OpenIddictAuthorization, DbContext, string>))]
        public void AddEntityFrameworkStores_RegistersEntityFrameworkStores(Type type)
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddEntityFrameworkStores<DbContext>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationStore<OpenIddictApplication<Guid>, OpenIddictAuthorization<Guid>, OpenIddictToken<Guid>, DbContext, Guid>))]
        [InlineData(typeof(OpenIddictAuthorizationStore<OpenIddictAuthorization<Guid>, OpenIddictApplication<Guid>, OpenIddictToken<Guid>, DbContext, Guid>))]
        [InlineData(typeof(OpenIddictScopeStore<OpenIddictScope<Guid>, DbContext, Guid>))]
        [InlineData(typeof(OpenIddictTokenStore<OpenIddictToken<Guid>, OpenIddictApplication<Guid>, OpenIddictAuthorization<Guid>, DbContext, Guid>))]
        public void AddEntityFrameworkStores_KeyTypeIsInferredFromEntities(Type type)
        {
            // Arrange
            var services = new ServiceCollection();

            var builder = new OpenIddictBuilder(services)
            {
                ApplicationType = typeof(OpenIddictApplication<Guid>),
                AuthorizationType = typeof(OpenIddictAuthorization<Guid>),
                ScopeType = typeof(OpenIddictScope<Guid>),
                TokenType = typeof(OpenIddictToken<Guid>)
            };

            // Act
            builder.AddEntityFrameworkStores<DbContext>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationStore<CustomApplication, CustomAuthorization, CustomToken, DbContext, long>))]
        [InlineData(typeof(OpenIddictAuthorizationStore<CustomAuthorization, CustomApplication, CustomToken, DbContext, long>))]
        [InlineData(typeof(OpenIddictScopeStore<CustomScope, DbContext, long>))]
        [InlineData(typeof(OpenIddictTokenStore<CustomToken, CustomApplication, CustomAuthorization, DbContext, long>))]
        public void AddEntityFrameworkStores_DefaultEntitiesCanBeReplaced(Type type)
        {
            // Arrange
            var services = new ServiceCollection();

            var builder = new OpenIddictBuilder(services)
            {
                ApplicationType = typeof(CustomApplication),
                AuthorizationType = typeof(CustomAuthorization),
                ScopeType = typeof(CustomScope),
                TokenType = typeof(CustomToken)
            };

            // Act
            builder.AddEntityFrameworkStores<DbContext>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }

        public class CustomApplication : OpenIddictApplication<long, CustomAuthorization, CustomToken> { }
        public class CustomAuthorization : OpenIddictAuthorization<long, CustomApplication, CustomToken> { }
        public class CustomScope : OpenIddictScope<long> { }
        public class CustomToken : OpenIddictToken<long, CustomApplication, CustomAuthorization> { }
    }
}
