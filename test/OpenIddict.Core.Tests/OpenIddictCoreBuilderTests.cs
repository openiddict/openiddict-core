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
    public void ReplaceResourceManager_ThrowsAnExceptionForClosedSourceManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceResourceManager(typeof(ClosedGenericResourceManager)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0232), exception.Message);
    }

    [Fact]
    public void ReplaceResourceManager_ThrowsAnExceptionForInvalidManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceResourceManager(typeof(object)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0232), exception.Message);
    }

    [Fact]
    public void ReplaceResourceManager_OverridesDefaultOpenGenericManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.ReplaceResourceManager(typeof(OpenGenericResourceManager<>));

        // Assert
        var descriptor = Assert.Single(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(OpenIddictResourceManager<>));
        Assert.Equal(typeof(OpenGenericResourceManager<>), descriptor.ImplementationType);
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
    public void ReplaceSessionManager_ThrowsAnExceptionForClosedSourceManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceSessionManager(typeof(ClosedGenericSessionManager)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0232), exception.Message);
    }

    [Fact]
    public void ReplaceSessionManager_ThrowsAnExceptionForInvalidManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.ReplaceSessionManager(typeof(object)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0232), exception.Message);
    }

    [Fact]
    public void ReplaceSessionManager_OverridesDefaultOpenGenericManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.ReplaceSessionManager(typeof(OpenGenericSessionManager<>));

        // Assert
        var descriptor = Assert.Single(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(OpenIddictSessionManager<>));
        Assert.Equal(typeof(OpenGenericSessionManager<>), descriptor.ImplementationType);
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
    public void DisableAutomaticClientSecretRehashing_RehashingIsCorrectlyDisabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.DisableAutomaticClientSecretRehashing();

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

        Assert.True(options.DisableAutomaticClientSecretRehashing);
    }

    [Theory]
    [InlineData("MD5")]
    [InlineData("SHA384")]
    [InlineData("Invalid")]
    public void SetClientSecretKeyDerivationHashAlgorithm_ThrowsAnExceptionForInvalidAlgorithm(string algorithmName)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var algorithm = new System.Security.Cryptography.HashAlgorithmName(algorithmName);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetClientSecretKeyDerivationHashAlgorithm(algorithm));

        Assert.Equal("algorithm", exception.ParamName);
    }

    [Theory]
    [InlineData("SHA1")]
    [InlineData("SHA256")]
    [InlineData("SHA512")]
    public void SetClientSecretKeyDerivationHashAlgorithm_AlgorithmIsCorrectlySet(string algorithmName)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var algorithm = new System.Security.Cryptography.HashAlgorithmName(algorithmName);

        // Act
        builder.SetClientSecretKeyDerivationHashAlgorithm(algorithm);

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

        Assert.Equal(algorithm, options.ClientSecretKeyDerivationHashAlgorithm);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(9_999)]
    [InlineData(10_000_001)]
    public void SetClientSecretKeyDerivationIterations_ThrowsAnExceptionForInvalidIterations(int iterations)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => builder.SetClientSecretKeyDerivationIterations(iterations));

        Assert.Equal("iterations", exception.ParamName);
    }

    [Theory]
    [InlineData(10_000)]
    [InlineData(50_000)]
    [InlineData(10_000_000)]
    public void SetClientSecretKeyDerivationIterations_IterationsAreCorrectlySet(int iterations)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetClientSecretKeyDerivationIterations(iterations);

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

        Assert.Equal(iterations, options.ClientSecretKeyDerivationIterations);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(255)]
    [InlineData(2049)]
    public void SetClientSecretKeyDerivationOutputLength_ThrowsAnExceptionForInvalidLength(int length)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => builder.SetClientSecretKeyDerivationOutputLength(length));

        Assert.Equal("length", exception.ParamName);
    }

    [Theory]
    [InlineData(256)]
    [InlineData(512)]
    [InlineData(2048)]
    public void SetClientSecretKeyDerivationOutputLength_LengthIsCorrectlySet(int length)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetClientSecretKeyDerivationOutputLength(length);

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

        Assert.Equal(length, options.ClientSecretKeyDerivationOutputLength);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(127)]
    [InlineData(1025)]
    public void SetClientSecretKeyDerivationSaltLength_ThrowsAnExceptionForInvalidLength(int length)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => builder.SetClientSecretKeyDerivationSaltLength(length));

        Assert.Equal("length", exception.ParamName);
    }

    [Theory]
    [InlineData(128)]
    [InlineData(256)]
    [InlineData(1024)]
    public void SetClientSecretKeyDerivationSaltLength_LengthIsCorrectlySet(int length)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetClientSecretKeyDerivationSaltLength(length);

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

        Assert.Equal(length, options.ClientSecretKeyDerivationSaltLength);
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
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => builder.SetEntityCacheLimit(limit));

        Assert.Equal("limit", exception.ParamName);
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
    public void SetDefaultResourceEntity_ReplacesUntypedManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetDefaultResourceEntity<CustomResource>();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictResourceManager) &&
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
    public void SetDefaultSessionEntity_ReplacesUntypedManager()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetDefaultSessionEntity<CustomSession>();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictSessionManager) &&
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
private static OpenIddictCoreBuilder CreateBuilder(IServiceCollection services)
        => services.AddOpenIddict().AddCore();

    private static ServiceCollection CreateServices()
    {
        var services = new ServiceCollection();
        services.AddOptions();

        return services;
    }

    private class CustomApplication;
    private class CustomAuthorization;
    private class CustomResource;
    private class CustomScope;
    private class CustomSession;
    private class CustomToken;

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

    private class ClosedGenericResourceManager : OpenIddictResourceManager<CustomResource>
    {
        public ClosedGenericResourceManager(
            IOpenIddictResourceCache<CustomResource> cache,
            ILogger<OpenIddictResourceManager<CustomResource>> logger,
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictResourceStore<CustomResource> store)
            : base(cache, logger, options, store)
        {
        }
    }

    private class OpenGenericResourceManager<TResource> : OpenIddictResourceManager<TResource>
        where TResource : class
    {
        public OpenGenericResourceManager(
            IOpenIddictResourceCache<TResource> cache,
            ILogger<OpenIddictResourceManager<TResource>> logger,
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictResourceStore<TResource> store)
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

    private class ClosedGenericSessionManager : OpenIddictSessionManager<CustomSession>
    {
        public ClosedGenericSessionManager(
            IOpenIddictSessionCache<CustomSession> cache,
            ILogger<OpenIddictSessionManager<CustomSession>> logger,
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictSessionStore<CustomSession> store)
            : base(cache, logger, options, store)
        {
        }
    }

    private class OpenGenericSessionManager<TSession> : OpenIddictSessionManager<TSession>
        where TSession : class
    {
        public OpenGenericSessionManager(
            IOpenIddictSessionCache<TSession> cache,
            ILogger<OpenIddictSessionManager<TSession>> logger,
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictSessionStore<TSession> store)
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
