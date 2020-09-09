/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Abstractions;
using Xunit;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Core.Tests
{
    public class OpenIddictCoreBuilderTests
    {
        [Fact]
        public void Constructor_ThrowsAnExceptionForNullServices()
        {
            // Arrange
            var services = (IServiceCollection) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictCoreBuilder(services));

            Assert.Equal("services", exception.ParamName);
        }

        [Fact]
        public void ReplaceApplicationManager_ThrowsAnExceptionForInvalidManager()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceApplicationManager(typeof(object)));

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith(SR.GetResourceString(SR.ID1231), exception.Message);
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
                service.ServiceType == typeof(OpenGenericApplicationManager<>) &&
                service.ImplementationType == typeof(OpenGenericApplicationManager<>));
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
                service.ServiceType == typeof(ClosedGenericApplicationManager) &&
                service.ImplementationFactory is not null);
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
            Assert.StartsWith(SR.GetResourceString(SR.ID1231), exception.Message);
        }

        [Fact]
        public void ReplaceApplicationStoreResolver_OverridesDefaultResolver()
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
            Assert.StartsWith(SR.GetResourceString(SR.ID1231), exception.Message);
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
                service.ServiceType == typeof(OpenGenericAuthorizationManager<>) &&
                service.ImplementationType == typeof(OpenGenericAuthorizationManager<>));
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
                service.ServiceType == typeof(ClosedGenericAuthorizationManager) &&
                service.ImplementationFactory is not null);
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
            Assert.StartsWith(SR.GetResourceString(SR.ID1231), exception.Message);
        }

        [Fact]
        public void ReplaceAuthorizationStoreResolver_OverridesDefaultResolver()
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
            Assert.StartsWith(SR.GetResourceString(SR.ID1231), exception.Message);
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
                service.ServiceType == typeof(OpenGenericScopeManager<>) &&
                service.ImplementationType == typeof(OpenGenericScopeManager<>));
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
                service.ServiceType == typeof(ClosedGenericScopeManager) &&
                service.ImplementationFactory is not null);
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
            Assert.StartsWith(SR.GetResourceString(SR.ID1231), exception.Message);
        }

        [Fact]
        public void ReplaceScopeStoreResolver_OverridesDefaultResolver()
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
            Assert.StartsWith(SR.GetResourceString(SR.ID1231), exception.Message);
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
                service.ServiceType == typeof(OpenGenericTokenManager<>) &&
                service.ImplementationType == typeof(OpenGenericTokenManager<>));
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
                service.ServiceType == typeof(ClosedGenericTokenManager) &&
                service.ImplementationFactory is not null);
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
            Assert.StartsWith(SR.GetResourceString(SR.ID1231), exception.Message);
        }

        [Fact]
        public void ReplaceTokenStoreResolver_OverridesDefaultResolver()
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
        public void DisableAdditionalFiltering_FilteringIsCorrectlyDisabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.DisableAdditionalFiltering();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

            Assert.True(options.DisableAdditionalFiltering);
        }

        [Fact]
        public void DisableEntityCaching_CachingIsCorrectlyDisabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.DisableEntityCaching();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

            Assert.True(options.DisableEntityCaching);
        }

        [Fact]
        public void SetDefaultApplicationEntity_ThrowsAnExceptionForNullType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                return builder.SetDefaultApplicationEntity(type: null);
            });

            Assert.Equal("type", exception.ParamName);
        }

        [Fact]
        public void SetDefaultApplicationEntity_ThrowsAnExceptionForInvalidType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                return builder.SetDefaultApplicationEntity(typeof(long));
            });

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith(SR.GetResourceString(SR.ID1231), exception.Message);
        }

        [Fact]
        public void SetDefaultApplicationEntity_EntityIsCorrectlySet()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetDefaultApplicationEntity<CustomApplication>();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

            Assert.Equal(typeof(CustomApplication), options.DefaultApplicationType);
        }

        [Fact]
        public void SetDefaultAuthorizationEntity_ThrowsAnExceptionForNullType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                return builder.SetDefaultAuthorizationEntity(type: null);
            });

            Assert.Equal("type", exception.ParamName);
        }

        [Fact]
        public void SetDefaultAuthorizationEntity_ThrowsAnExceptionForInvalidType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                return builder.SetDefaultAuthorizationEntity(typeof(long));
            });

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith(SR.GetResourceString(SR.ID1231), exception.Message);
        }

        [Fact]
        public void SetDefaultAuthorizationEntity_EntityIsCorrectlySet()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetDefaultAuthorizationEntity<CustomAuthorization>();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

            Assert.Equal(typeof(CustomAuthorization), options.DefaultAuthorizationType);
        }

        [Fact]
        public void SetDefaultScopeEntity_ThrowsAnExceptionForNullType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                return builder.SetDefaultScopeEntity(type: null);
            });

            Assert.Equal("type", exception.ParamName);
        }

        [Fact]
        public void SetDefaultScopeEntity_ThrowsAnExceptionForInvalidType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                return builder.SetDefaultScopeEntity(typeof(long));
            });

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith(SR.GetResourceString(SR.ID1231), exception.Message);
        }

        [Fact]
        public void SetDefaultScopeEntity_EntityIsCorrectlySet()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetDefaultScopeEntity<CustomScope>();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

            Assert.Equal(typeof(CustomScope), options.DefaultScopeType);
        }

        [Fact]
        public void SetDefaultTokenEntity_ThrowsAnExceptionForNullType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                return builder.SetDefaultTokenEntity(type: null);
            });

            Assert.Equal("type", exception.ParamName);
        }

        [Fact]
        public void SetDefaultTokenEntity_ThrowsAnExceptionForInvalidType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                return builder.SetDefaultTokenEntity(typeof(long));
            });

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith(SR.GetResourceString(SR.ID1231), exception.Message);
        }

        [Fact]
        public void SetDefaultTokenEntity_EntityIsCorrectlySet()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetDefaultTokenEntity<CustomToken>();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

            Assert.Equal(typeof(CustomToken), options.DefaultTokenType);
        }

        [Theory]
        [InlineData(-10)]
        [InlineData(0)]
        [InlineData(9)]
        public void SetEntityCacheLimit_ThrowsAnExceptionForInvalidLimit(int limit)
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => builder.SetEntityCacheLimit(limit));

            Assert.Equal("limit", exception.ParamName);
            Assert.StartsWith("The cache size cannot be less than 10.", exception.Message);
        }

        [Fact]
        public void SetEntityCacheLimit_LimitIsCorrectlyDisabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetEntityCacheLimit(42);

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

            Assert.Equal(42, options.EntityCacheLimit);
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
                IOpenIddictApplicationCache<CustomApplication> cache,
                IStringLocalizer<OpenIddictResources> localizer,
                ILogger<OpenIddictApplicationManager<CustomApplication>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options,
                IOpenIddictApplicationStoreResolver resolver)
                : base(cache, localizer, logger, options, resolver)
            {
            }
        }

        private class OpenGenericApplicationManager<TApplication> : OpenIddictApplicationManager<TApplication>
            where TApplication : class
        {
            public OpenGenericApplicationManager(
                IOpenIddictApplicationCache<TApplication> cache,
                IStringLocalizer<OpenIddictResources> localizer,
                ILogger<OpenIddictApplicationManager<TApplication>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options,
                IOpenIddictApplicationStoreResolver resolver)
                : base(cache, localizer, logger, options, resolver)
            {
            }
        }

        private class ClosedGenericAuthorizationManager : OpenIddictAuthorizationManager<CustomAuthorization>
        {
            public ClosedGenericAuthorizationManager(
                IOpenIddictAuthorizationCache<CustomAuthorization> cache,
                IStringLocalizer<OpenIddictResources> localizer,
                ILogger<OpenIddictAuthorizationManager<CustomAuthorization>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options,
                IOpenIddictAuthorizationStoreResolver resolver)
                : base(cache, localizer, logger, options, resolver)
            {
            }
        }

        private class OpenGenericAuthorizationManager<TAuthorization> : OpenIddictAuthorizationManager<TAuthorization>
            where TAuthorization : class
        {
            public OpenGenericAuthorizationManager(
                IOpenIddictAuthorizationCache<TAuthorization> cache,
                IStringLocalizer<OpenIddictResources> localizer,
                ILogger<OpenIddictAuthorizationManager<TAuthorization>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options,
                IOpenIddictAuthorizationStoreResolver resolver)
                : base(cache, localizer, logger, options, resolver)
            {
            }
        }

        private class ClosedGenericScopeManager : OpenIddictScopeManager<CustomScope>
        {
            public ClosedGenericScopeManager(
                IOpenIddictScopeCache<CustomScope> cache,
                IStringLocalizer<OpenIddictResources> localizer,
                ILogger<OpenIddictScopeManager<CustomScope>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options,
                IOpenIddictScopeStoreResolver resolver)
                : base(cache, localizer, logger, options, resolver)
            {
            }
        }

        private class OpenGenericScopeManager<TScope> : OpenIddictScopeManager<TScope>
            where TScope : class
        {
            public OpenGenericScopeManager(
                IOpenIddictScopeCache<TScope> cache,
                IStringLocalizer<OpenIddictResources> localizer,
                ILogger<OpenIddictScopeManager<TScope>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options,
                IOpenIddictScopeStoreResolver resolver)
                : base(cache, localizer, logger, options, resolver)
            {
            }
        }

        private class ClosedGenericTokenManager : OpenIddictTokenManager<CustomToken>
        {
            public ClosedGenericTokenManager(
                IOpenIddictTokenCache<CustomToken> cache,
                IStringLocalizer<OpenIddictResources> localizer,
                ILogger<OpenIddictTokenManager<CustomToken>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options,
                IOpenIddictTokenStoreResolver resolver)
                : base(cache, localizer, logger, options, resolver)
            {
            }
        }

        private class OpenGenericTokenManager<TToken> : OpenIddictTokenManager<TToken>
            where TToken : class
        {
            public OpenGenericTokenManager(
                IOpenIddictTokenCache<TToken> cache,
                IStringLocalizer<OpenIddictResources> localizer,
                ILogger<OpenIddictTokenManager<TToken>> logger,
                IOptionsMonitor<OpenIddictCoreOptions> options,
                IOpenIddictTokenStoreResolver resolver)
                : base(cache, localizer, logger, options, resolver)
            {
            }
        }
    }
}
