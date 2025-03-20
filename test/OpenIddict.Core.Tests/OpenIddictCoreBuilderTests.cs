/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Core.Tests;

public class OpenIddictCoreBuilderTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullServices()
    {
        // Arrange
        var services = (IServiceCollection) null!;

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
        Assert.StartsWith(SR.GetResourceString(SR.ID0232), exception.Message);
    }

    [Fact]
    public void ReplaceApplicationManager_ThrowsAnExceptionForClosedSourceManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceApplicationManager(typeof(ClosedGenericApplicationManager)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0232), exception.Message);
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
        var descriptor = Assert.Single(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(OpenIddictApplicationManager<>));
        Assert.Equal(typeof(OpenGenericApplicationManager<>), descriptor.ImplementationType);
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
        Assert.StartsWith(SR.GetResourceString(SR.ID0232), exception.Message);
    }

    [Fact]
    public void ReplaceAuthorizationManager_ThrowsAnExceptionForClosedSourceManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceAuthorizationManager(typeof(ClosedGenericAuthorizationManager)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0232), exception.Message);
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
        var descriptor = Assert.Single(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(OpenIddictAuthorizationManager<>));
        Assert.Equal(typeof(OpenGenericAuthorizationManager<>), descriptor.ImplementationType);
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
        Assert.StartsWith(SR.GetResourceString(SR.ID0232), exception.Message);
    }

    [Fact]
    public void ReplaceScopeManager_ThrowsAnExceptionForClosedSourceManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceScopeManager(typeof(ClosedGenericScopeManager)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0232), exception.Message);
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
        var descriptor = Assert.Single(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(OpenIddictScopeManager<>));
        Assert.Equal(typeof(OpenGenericScopeManager<>), descriptor.ImplementationType);
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
        Assert.StartsWith(SR.GetResourceString(SR.ID0232), exception.Message);
    }

    [Fact]
    public void ReplaceTokenManager_ThrowsAnExceptionForClosedSourceManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceTokenManager(typeof(ClosedGenericTokenManager)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0232), exception.Message);
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
        var descriptor = Assert.Single(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(OpenIddictTokenManager<>));
        Assert.Equal(typeof(OpenGenericTokenManager<>), descriptor.ImplementationType);
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
    public void SetDefaultApplicationEntity_ReplacesUntypedManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetDefaultApplicationEntity<CustomApplication>();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictApplicationManager) &&
            service.ImplementationFactory is not null);
    }

    [Fact]
    public void SetDefaultAuthorizationEntity_ReplacesUntypedManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetDefaultAuthorizationEntity<CustomAuthorization>();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictAuthorizationManager) &&
            service.ImplementationFactory is not null);
    }

    [Fact]
    public void SetDefaultScopeEntity_ReplacesUntypedManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetDefaultScopeEntity<CustomScope>();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictScopeManager) &&
            service.ImplementationFactory is not null);
    }

    [Fact]
    public void SetDefaultTokenEntity_ReplacesUntypedManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetDefaultTokenEntity<CustomToken>();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictTokenManager) &&
            service.ImplementationFactory is not null);
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

    private static ServiceCollection CreateServices()
    {
        var services = new ServiceCollection();
        services.AddOptions();

        return services;
    }

    private class CustomApplication { }
    private class CustomAuthorization { }
    private class CustomScope { }
    private class CustomToken { }

    private class ClosedGenericApplicationManager : OpenIddictApplicationManager<CustomApplication>
    {
        public ClosedGenericApplicationManager(
            IOpenIddictApplicationCache<CustomApplication> cache,
            ILogger<OpenIddictApplicationManager<CustomApplication>> logger,
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictApplicationStore<CustomApplication> store)
            : base(cache, logger, options, store)
        {
        }
    }

    private class OpenGenericApplicationManager<TApplication> : OpenIddictApplicationManager<TApplication>
        where TApplication : class
    {
        public OpenGenericApplicationManager(
            IOpenIddictApplicationCache<TApplication> cache,
            ILogger<OpenIddictApplicationManager<TApplication>> logger,
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictApplicationStore<TApplication> store)
            : base(cache, logger, options, store)
        {
        }
    }

    private class ClosedGenericAuthorizationManager : OpenIddictAuthorizationManager<CustomAuthorization>
    {
        public ClosedGenericAuthorizationManager(
            IOpenIddictAuthorizationCache<CustomAuthorization> cache,
            ILogger<OpenIddictAuthorizationManager<CustomAuthorization>> logger,
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictAuthorizationStore<CustomAuthorization> store)
            : base(cache, logger, options, store)
        {
        }
    }

    private class OpenGenericAuthorizationManager<TAuthorization> : OpenIddictAuthorizationManager<TAuthorization>
        where TAuthorization : class
    {
        public OpenGenericAuthorizationManager(
            IOpenIddictAuthorizationCache<TAuthorization> cache,
            ILogger<OpenIddictAuthorizationManager<TAuthorization>> logger,
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictAuthorizationStore<TAuthorization> store)
            : base(cache, logger, options, store)
        {
        }
    }

    private class ClosedGenericScopeManager : OpenIddictScopeManager<CustomScope>
    {
        public ClosedGenericScopeManager(
            IOpenIddictScopeCache<CustomScope> cache,
            ILogger<OpenIddictScopeManager<CustomScope>> logger,
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictScopeStore<CustomScope> store)
            : base(cache, logger, options, store)
        {
        }
    }

    private class OpenGenericScopeManager<TScope> : OpenIddictScopeManager<TScope>
        where TScope : class
    {
        public OpenGenericScopeManager(
            IOpenIddictScopeCache<TScope> cache,
            ILogger<OpenIddictScopeManager<TScope>> logger,
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictScopeStore<TScope> store)
            : base(cache, logger, options, store)
        {
        }
    }

    private class ClosedGenericTokenManager : OpenIddictTokenManager<CustomToken>
    {
        public ClosedGenericTokenManager(
            IOpenIddictTokenCache<CustomToken> cache,
            ILogger<OpenIddictTokenManager<CustomToken>> logger,
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictTokenStore<CustomToken> store)
            : base(cache, logger, options, store)
        {
        }
    }

    private class OpenGenericTokenManager<TToken> : OpenIddictTokenManager<TToken>
        where TToken : class
    {
        public OpenGenericTokenManager(
            IOpenIddictTokenCache<TToken> cache,
            ILogger<OpenIddictTokenManager<TToken>> logger,
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictTokenStore<TToken> store)
            : base(cache, logger, options, store)
        {
        }
    }
}
