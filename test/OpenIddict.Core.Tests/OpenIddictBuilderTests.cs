using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace OpenIddict.Core.Tests {
    public class OpenIddictBuilderTests {
        [Fact]
        public void AddApplicationManager_ThrowsAnExceptionForInvalidManager() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.ApplicationType = typeof(object);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.AddApplicationManager(typeof(object)));

            Assert.Equal("Custom managers must be derived from OpenIddictApplicationManager.", exception.Message);
        }

        [Fact]
        public void AddApplicationManager_OverridesDefaultManager() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.ApplicationType = typeof(object);

            var type = new Mock<OpenIddictApplicationManager<object>>(
                Mock.Of<IOpenIddictApplicationStore<object>>(),
                Mock.Of<ILogger<OpenIddictApplicationManager<object>>>()).Object.GetType();

            // Act
            builder.AddApplicationManager(type);

            var provider = services.BuildServiceProvider();
            var manager = provider.GetRequiredService<OpenIddictApplicationManager<object>>();

            // Assert
            Assert.IsType(type, manager);
        }

        [Fact]
        public void AddApplicationStore_ThrowsAnExceptionForInvalidStore() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.ApplicationType = typeof(object);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.AddApplicationStore(typeof(object)));

            Assert.Equal("Custom stores must implement IOpenIddictApplicationStore.", exception.Message);
        }

        [Fact]
        public void AddApplicationStore_OverridesDefaultManager() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.ApplicationType = typeof(object);

            var type = Mock.Of<IOpenIddictApplicationStore<object>>().GetType();

            // Act
            builder.AddApplicationStore(type);

            var provider = services.BuildServiceProvider();
            var store = provider.GetRequiredService<IOpenIddictApplicationStore<object>>();

            // Assert
            Assert.IsType(type, store);
        }

        [Fact]
        public void AddAuthorizationManager_ThrowsAnExceptionForInvalidManager() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.AuthorizationType = typeof(object);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.AddAuthorizationManager(typeof(object)));

            Assert.Equal("Custom managers must be derived from OpenIddictAuthorizationManager.", exception.Message);
        }

        [Fact]
        public void AddAuthorizationManager_OverridesDefaultManager() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.AuthorizationType = typeof(object);

            var type = new Mock<OpenIddictAuthorizationManager<object>>(
                Mock.Of<IOpenIddictAuthorizationStore<object>>(),
                Mock.Of<ILogger<OpenIddictAuthorizationManager<object>>>()).Object.GetType();

            // Act
            builder.AddAuthorizationManager(type);

            var provider = services.BuildServiceProvider();
            var manager = provider.GetRequiredService<OpenIddictAuthorizationManager<object>>();

            // Assert
            Assert.IsType(type, manager);
        }

        [Fact]
        public void AddAuthorizationStore_ThrowsAnExceptionForInvalidStore() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.AuthorizationType = typeof(object);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.AddAuthorizationStore(typeof(object)));

            Assert.Equal("Custom stores must implement IOpenIddictAuthorizationStore.", exception.Message);
        }

        [Fact]
        public void AddAuthorizationStore_OverridesDefaultManager() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.AuthorizationType = typeof(object);

            var type = Mock.Of<IOpenIddictAuthorizationStore<object>>().GetType();

            // Act
            builder.AddAuthorizationStore(type);

            var provider = services.BuildServiceProvider();
            var store = provider.GetRequiredService<IOpenIddictAuthorizationStore<object>>();

            // Assert
            Assert.IsType(type, store);
        }

        [Fact]
        public void AddScopeManager_ThrowsAnExceptionForInvalidManager() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.ScopeType = typeof(object);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.AddScopeManager(typeof(object)));

            Assert.Equal("Custom managers must be derived from OpenIddictScopeManager.", exception.Message);
        }

        [Fact]
        public void AddScopeManager_OverridesDefaultManager() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.ScopeType = typeof(object);

            var type = new Mock<OpenIddictScopeManager<object>>(
                Mock.Of<IOpenIddictScopeStore<object>>(),
                Mock.Of<ILogger<OpenIddictScopeManager<object>>>()).Object.GetType();

            // Act
            builder.AddScopeManager(type);

            var provider = services.BuildServiceProvider();
            var manager = provider.GetRequiredService<OpenIddictScopeManager<object>>();

            // Assert
            Assert.IsType(type, manager);
        }

        [Fact]
        public void AddScopeStore_ThrowsAnExceptionForInvalidStore() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.ScopeType = typeof(object);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.AddScopeStore(typeof(object)));

            Assert.Equal("Custom stores must implement IOpenIddictScopeStore.", exception.Message);
        }

        [Fact]
        public void AddScopeStore_OverridesDefaultManager() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.ScopeType = typeof(object);

            var type = Mock.Of<IOpenIddictScopeStore<object>>().GetType();

            // Act
            builder.AddScopeStore(type);

            var provider = services.BuildServiceProvider();
            var store = provider.GetRequiredService<IOpenIddictScopeStore<object>>();

            // Assert
            Assert.IsType(type, store);
        }

        [Fact]
        public void AddTokenManager_ThrowsAnExceptionForInvalidManager() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.TokenType = typeof(object);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.AddTokenManager(typeof(object)));

            Assert.Equal("Custom managers must be derived from OpenIddictTokenManager.", exception.Message);
        }

        [Fact]
        public void AddTokenManager_OverridesDefaultManager() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.TokenType = typeof(object);

            var type = new Mock<OpenIddictTokenManager<object>>(
                Mock.Of<IOpenIddictTokenStore<object>>(),
                Mock.Of<ILogger<OpenIddictTokenManager<object>>>()).Object.GetType();

            // Act
            builder.AddTokenManager(type);

            var provider = services.BuildServiceProvider();
            var manager = provider.GetRequiredService<OpenIddictTokenManager<object>>();

            // Assert
            Assert.IsType(type, manager);
        }

        [Fact]
        public void AddTokenStore_ThrowsAnExceptionForInvalidStore() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.TokenType = typeof(object);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.AddTokenStore(typeof(object)));

            Assert.Equal("Custom stores must implement IOpenIddictTokenStore.", exception.Message);
        }

        [Fact]
        public void AddTokenStore_OverridesDefaultManager() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);
            builder.TokenType = typeof(object);

            var type = Mock.Of<IOpenIddictTokenStore<object>>().GetType();

            // Act
            builder.AddTokenStore(type);

            var provider = services.BuildServiceProvider();
            var store = provider.GetRequiredService<IOpenIddictTokenStore<object>>();

            // Assert
            Assert.IsType(type, store);
        }
    }
}
