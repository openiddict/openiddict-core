/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Abstractions;
using Xunit;

namespace OpenIddict.Core.Tests
{
    public class OpenIddictCoreBuilderTests
    {
        [Fact]
        public void ReplaceApplicationManager_ThrowsAnExceptionForInvalidManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceApplicationManager(typeof(object)));

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith("The specified type is invalid.", exception.Message);
        }

        [Fact]
        public void ReplaceApplicationManager_OverridesDefaultOpenGenericManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.ReplaceApplicationManager(typeof(OpenGenericApplicationManager<>));

            // Assert
            Assert.Contains(services, service =>
                service.ServiceType == typeof(OpenIddictApplicationManager<>) &&
                service.ImplementationType == typeof(OpenGenericApplicationManager<>));
            Assert.DoesNotContain(services, service =>
                service.ServiceType == typeof(OpenIddictApplicationManager<>) &&
                service.ImplementationType == typeof(OpenIddictApplicationManager<>));
        }

        [Fact]
        public void ReplaceApplicationManager_AddsClosedGenericManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.ReplaceApplicationManager(typeof(ClosedGenericApplicationManager));

            // Assert
            Assert.Contains(services, service =>
                service.ServiceType == typeof(OpenIddictApplicationManager<CustomApplication>) &&
                service.ImplementationType == typeof(ClosedGenericApplicationManager));
            Assert.Contains(services, service =>
                service.ServiceType == typeof(OpenIddictApplicationManager<>) &&
                service.ImplementationType == typeof(OpenIddictApplicationManager<>));
        }

        [Fact]
        public void ReplaceApplicationStoreResolver_ThrowsAnExceptionForInvalidStoreResolver()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceApplicationStoreResolver(typeof(object)));

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith("The specified type is invalid.", exception.Message);
        }

        [Fact]
        public void ReplaceApplicationStoreResolver_OverridesDefaultManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            var type = Mock.Of<IOpenIddictApplicationStoreResolver>().GetType();

            // Act
            builder.ReplaceApplicationStoreResolver(type);

            var provider = services.BuildServiceProvider();
            var store = provider.GetRequiredService<IOpenIddictApplicationStoreResolver>();

            // Assert
            Assert.IsType(type, store);
        }

        [Fact]
        public void ReplaceAuthorizationManager_ThrowsAnExceptionForInvalidManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceAuthorizationManager(typeof(object)));

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith("The specified type is invalid.", exception.Message);
        }

        [Fact]
        public void ReplaceAuthorizationManager_OverridesDefaultOpenGenericManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.ReplaceAuthorizationManager(typeof(OpenGenericAuthorizationManager<>));

            // Assert
            Assert.Contains(services, service =>
                service.ServiceType == typeof(OpenIddictAuthorizationManager<>) &&
                service.ImplementationType == typeof(OpenGenericAuthorizationManager<>));
            Assert.DoesNotContain(services, service =>
                service.ServiceType == typeof(OpenIddictAuthorizationManager<>) &&
                service.ImplementationType == typeof(OpenIddictAuthorizationManager<>));
        }

        [Fact]
        public void ReplaceAuthorizationManager_AddsClosedGenericManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.ReplaceAuthorizationManager(typeof(ClosedGenericAuthorizationManager));

            // Assert
            Assert.Contains(services, service =>
                service.ServiceType == typeof(OpenIddictAuthorizationManager<CustomAuthorization>) &&
                service.ImplementationType == typeof(ClosedGenericAuthorizationManager));
            Assert.Contains(services, service =>
                service.ServiceType == typeof(OpenIddictAuthorizationManager<>) &&
                service.ImplementationType == typeof(OpenIddictAuthorizationManager<>));
        }
        [Fact]
        public void ReplaceAuthorizationStoreResolver_ThrowsAnExceptionForInvalidStoreResolver()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceAuthorizationStoreResolver(typeof(object)));

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith("The specified type is invalid.", exception.Message);
        }

        [Fact]
        public void ReplaceAuthorizationStoreResolver_OverridesDefaultManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            var type = Mock.Of<IOpenIddictAuthorizationStoreResolver>().GetType();

            // Act
            builder.ReplaceAuthorizationStoreResolver(type);

            var provider = services.BuildServiceProvider();
            var store = provider.GetRequiredService<IOpenIddictAuthorizationStoreResolver>();

            // Assert
            Assert.IsType(type, store);
        }

        [Fact]
        public void ReplaceScopeManager_ThrowsAnExceptionForInvalidManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceScopeManager(typeof(object)));

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith("The specified type is invalid.", exception.Message);
        }

        [Fact]
        public void ReplaceScopeManager_OverridesDefaultOpenGenericManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.ReplaceScopeManager(typeof(OpenGenericScopeManager<>));

            // Assert
            Assert.Contains(services, service =>
                service.ServiceType == typeof(OpenIddictScopeManager<>) &&
                service.ImplementationType == typeof(OpenGenericScopeManager<>));
            Assert.DoesNotContain(services, service =>
                service.ServiceType == typeof(OpenIddictScopeManager<>) &&
                service.ImplementationType == typeof(OpenIddictScopeManager<>));
        }

        [Fact]
        public void ReplaceScopeManager_AddsClosedGenericManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.ReplaceScopeManager(typeof(ClosedGenericScopeManager));

            // Assert
            Assert.Contains(services, service =>
                service.ServiceType == typeof(OpenIddictScopeManager<CustomScope>) &&
                service.ImplementationType == typeof(ClosedGenericScopeManager));
            Assert.Contains(services, service =>
                service.ServiceType == typeof(OpenIddictScopeManager<>) &&
                service.ImplementationType == typeof(OpenIddictScopeManager<>));
        }

        [Fact]
        public void ReplaceScopeStoreResolver_ThrowsAnExceptionForInvalidStoreResolver()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceScopeStoreResolver(typeof(object)));

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith("The specified type is invalid.", exception.Message);
        }

        [Fact]
        public void ReplaceScopeStoreResolver_OverridesDefaultManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            var type = Mock.Of<IOpenIddictScopeStoreResolver>().GetType();

            // Act
            builder.ReplaceScopeStoreResolver(type);

            var provider = services.BuildServiceProvider();
            var store = provider.GetRequiredService<IOpenIddictScopeStoreResolver>();

            // Assert
            Assert.IsType(type, store);
        }

        [Fact]
        public void ReplaceTokenManager_ThrowsAnExceptionForInvalidManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceTokenManager(typeof(object)));

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith("The specified type is invalid.", exception.Message);
        }

        [Fact]
        public void ReplaceTokenManager_OverridesDefaultOpenGenericManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.ReplaceTokenManager(typeof(OpenGenericTokenManager<>));

            // Assert
            Assert.Contains(services, service =>
                service.ServiceType == typeof(OpenIddictTokenManager<>) &&
                service.ImplementationType == typeof(OpenGenericTokenManager<>));
            Assert.DoesNotContain(services, service =>
                service.ServiceType == typeof(OpenIddictTokenManager<>) &&
                service.ImplementationType == typeof(OpenIddictTokenManager<>));
        }

        [Fact]
        public void ReplaceTokenManager_AddsClosedGenericManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.ReplaceTokenManager(typeof(ClosedGenericTokenManager));

            // Assert
            Assert.Contains(services, service =>
                service.ServiceType == typeof(OpenIddictTokenManager<CustomToken>) &&
                service.ImplementationType == typeof(ClosedGenericTokenManager));
            Assert.Contains(services, service =>
                service.ServiceType == typeof(OpenIddictTokenManager<>) &&
                service.ImplementationType == typeof(OpenIddictTokenManager<>));
        }

        [Fact]
        public void ReplaceTokenStoreResolver_ThrowsAnExceptionForInvalidStoreResolver()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceTokenStoreResolver(typeof(object)));

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith("The specified type is invalid.", exception.Message);
        }

        [Fact]
        public void ReplaceTokenStoreResolver_OverridesDefaultManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            var type = Mock.Of<IOpenIddictTokenStoreResolver>().GetType();

            // Act
            builder.ReplaceTokenStoreResolver(type);

            var provider = services.BuildServiceProvider();
            var store = provider.GetRequiredService<IOpenIddictTokenStoreResolver>();

            // Assert
            Assert.IsType(type, store);
        }

        [Fact]
        public void UseCustomModels_CustomEntitiesAreCorrectlySet()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            services.AddOpenIddict().AddCore()
                .UseCustomModels<CustomApplication, CustomAuthorization, CustomScope, CustomToken>();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

            Assert.Equal(typeof(CustomApplication), options.DefaultApplicationType);
            Assert.Equal(typeof(CustomAuthorization), options.DefaultAuthorizationType);
            Assert.Equal(typeof(CustomScope), options.DefaultScopeType);
            Assert.Equal(typeof(CustomToken), options.DefaultTokenType);
        }

        private static OpenIddictCoreBuilder CreateBuilder(IServiceCollection services)
            => services.AddOpenIddict().AddCore();

        private static IServiceCollection CreateServices()
        {
            var services = new ServiceCollection();
            services.AddOptions();

            return services;
        }

        public class CustomApplication { }
        public class CustomAuthorization { }
        public class CustomScope { }
        public class CustomToken { }

        private class ClosedGenericApplicationManager : OpenIddictApplicationManager<CustomApplication>
        {
            public ClosedGenericApplicationManager(
                IOpenIddictApplicationStoreResolver resolver,
                ILogger<OpenIddictApplicationManager<CustomApplication>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options)
                : base(resolver, logger, options)
            {
            }
        }

        private class OpenGenericApplicationManager<TApplication> : OpenIddictApplicationManager<TApplication>
            where TApplication : class
        {
            public OpenGenericApplicationManager(
                IOpenIddictApplicationStoreResolver resolver,
                ILogger<OpenIddictApplicationManager<TApplication>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options)
                : base(resolver, logger, options)
            {
            }
        }

        private class ClosedGenericAuthorizationManager : OpenIddictAuthorizationManager<CustomAuthorization>
        {
            public ClosedGenericAuthorizationManager(
                IOpenIddictAuthorizationStoreResolver resolver,
                ILogger<OpenIddictAuthorizationManager<CustomAuthorization>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options)
                : base(resolver, logger, options)
            {
            }
        }

        private class OpenGenericAuthorizationManager<TAuthorization> : OpenIddictAuthorizationManager<TAuthorization>
            where TAuthorization : class
        {
            public OpenGenericAuthorizationManager(
                IOpenIddictAuthorizationStoreResolver resolver,
                ILogger<OpenIddictAuthorizationManager<TAuthorization>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options)
                : base(resolver, logger, options)
            {
            }
        }

        private class ClosedGenericScopeManager : OpenIddictScopeManager<CustomScope>
        {
            public ClosedGenericScopeManager(
                IOpenIddictScopeStoreResolver resolver,
                ILogger<OpenIddictScopeManager<CustomScope>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options)
                : base(resolver, logger, options)
            {
            }
        }

        private class OpenGenericScopeManager<TScope> : OpenIddictScopeManager<TScope>
            where TScope : class
        {
            public OpenGenericScopeManager(
                IOpenIddictScopeStoreResolver resolver,
                ILogger<OpenIddictScopeManager<TScope>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options)
                : base(resolver, logger, options)
            {
            }
        }

        private class ClosedGenericTokenManager : OpenIddictTokenManager<CustomToken>
        {
            public ClosedGenericTokenManager(
                IOpenIddictTokenStoreResolver resolver,
                ILogger<OpenIddictTokenManager<CustomToken>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options)
                : base(resolver, logger, options)
            {
            }
        }

        private class OpenGenericTokenManager<TToken> : OpenIddictTokenManager<TToken>
            where TToken : class
        {
            public OpenGenericTokenManager(
                IOpenIddictTokenStoreResolver resolver,
                ILogger<OpenIddictTokenManager<TToken>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options)
                : base(resolver, logger, options)
            {
            }
        }
    }
}
