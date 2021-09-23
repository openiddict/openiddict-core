/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace OpenIddict.Core.Tests;

public class OpenIddictCoreExtensionsTests
{
    [Fact]
    public void AddCore_ThrowsAnExceptionForNullBuilder()
    {
        // Arrange
        var builder = (OpenIddictBuilder) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddCore());

        Assert.Equal("builder", exception.ParamName);
    }

    [Fact]
    public void AddCore_ThrowsAnExceptionForNullConfiguration()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddCore(configuration: null!));

        Assert.Equal("configuration", exception.ParamName);
    }

    [Fact]
    public void AddCore_RegistersLoggingServices()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        Assert.Contains(services, service => service.ServiceType == typeof(ILogger<>));
    }

    [Fact]
    public void AddCore_RegistersOptionsServices()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        Assert.Contains(services, service => service.ServiceType == typeof(IOptions<>));
    }

    [Theory]
    [InlineData(typeof(OpenIddictApplicationManager<>))]
    [InlineData(typeof(OpenIddictAuthorizationManager<>))]
    [InlineData(typeof(OpenIddictScopeManager<>))]
    [InlineData(typeof(OpenIddictTokenManager<>))]
    public void AddCore_RegistersDefaultManagers(Type type)
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        Assert.Contains(services, service => service.ServiceType == type && service.ImplementationType == type);
    }

    [Theory]
    [InlineData(typeof(IOpenIddictApplicationStoreResolver), typeof(OpenIddictApplicationStoreResolver))]
    [InlineData(typeof(IOpenIddictAuthorizationStoreResolver), typeof(OpenIddictAuthorizationStoreResolver))]
    [InlineData(typeof(IOpenIddictScopeStoreResolver), typeof(OpenIddictScopeStoreResolver))]
    [InlineData(typeof(IOpenIddictTokenStoreResolver), typeof(OpenIddictTokenStoreResolver))]
    public void AddCore_RegistersDefaultResolvers(Type serviceType, Type implementationType)
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        Assert.Contains(services, service => service.ServiceType == serviceType &&
                                             service.ImplementationType == implementationType);
    }

    [Theory]
    [InlineData(typeof(IOpenIddictApplicationManager))]
    [InlineData(typeof(IOpenIddictAuthorizationManager))]
    [InlineData(typeof(IOpenIddictScopeManager))]
    [InlineData(typeof(IOpenIddictTokenManager))]
    public void AddCore_RegistersUntypedProxies(Type type)
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        Assert.Contains(services, service => service.ServiceType == type && service.ImplementationFactory is not null);
    }

    [Fact]
    public void AddCore_ResolvingUntypedApplicationManagerThrowsAnExceptionWhenDefaultEntityIsNotSet()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(delegate
        {
            return provider.GetRequiredService<IOpenIddictApplicationManager>();
        });

        Assert.Equal(SR.GetResourceString(SR.ID0273), exception.Message);
    }

    [Fact]
    public void AddCore_ResolvingUntypedAuthorizationManagerThrowsAnExceptionWhenDefaultEntityIsNotSet()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(delegate
        {
            return provider.GetRequiredService<IOpenIddictAuthorizationManager>();
        });

        Assert.Equal(SR.GetResourceString(SR.ID0274), exception.Message);
    }

    [Fact]
    public void AddCore_ResolvingUntypedScopeManagerThrowsAnExceptionWhenDefaultEntityIsNotSet()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(delegate
        {
            return provider.GetRequiredService<IOpenIddictScopeManager>();
        });

        Assert.Equal(SR.GetResourceString(SR.ID0275), exception.Message);
    }

    [Fact]
    public void AddCore_ResolvingUntypedTokenManagerThrowsAnExceptionWhenDefaultEntityIsNotSet()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(delegate
        {
            return provider.GetRequiredService<IOpenIddictTokenManager>();
        });

        Assert.Equal(SR.GetResourceString(SR.ID0276), exception.Message);
    }

    [Fact]
    public void AddCore_ResolvingUntypedApplicationManagerReturnsGenericManager()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore(options =>
        {
            options.SetDefaultApplicationEntity<OpenIddictApplication>();
            options.Services.AddSingleton(Mock.Of<IOpenIddictApplicationStore<OpenIddictApplication>>());
        });

        var provider = services.BuildServiceProvider();
        var manager = provider.GetRequiredService<IOpenIddictApplicationManager>();

        // Assert
        Assert.IsType<OpenIddictApplicationManager<OpenIddictApplication>>(manager);
    }

    [Fact]
    public void AddCore_ResolvingUntypedAuthorizationManagerReturnsGenericManager()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore(options =>
        {
            options.SetDefaultAuthorizationEntity<OpenIddictAuthorization>();
            options.Services.AddSingleton(Mock.Of<IOpenIddictAuthorizationStore<OpenIddictAuthorization>>());
        });

        var provider = services.BuildServiceProvider();
        var manager = provider.GetRequiredService<IOpenIddictAuthorizationManager>();

        // Assert
        Assert.IsType<OpenIddictAuthorizationManager<OpenIddictAuthorization>>(manager);
    }

    [Fact]
    public void AddCore_ResolvingUntypedScopeManagerReturnsGenericManager()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore(options =>
        {
            options.SetDefaultScopeEntity<OpenIddictScope>();
            options.Services.AddSingleton(Mock.Of<IOpenIddictScopeStore<OpenIddictScope>>());
        });

        var provider = services.BuildServiceProvider();
        var manager = provider.GetRequiredService<IOpenIddictScopeManager>();

        // Assert
        Assert.IsType<OpenIddictScopeManager<OpenIddictScope>>(manager);
    }

    [Fact]
    public void AddCore_ResolvingUntypedTokenManagerReturnsGenericManager()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore(options =>
        {
            options.SetDefaultTokenEntity<OpenIddictToken>();
            options.Services.AddSingleton(Mock.Of<IOpenIddictTokenStore<OpenIddictToken>>());
        });

        var provider = services.BuildServiceProvider();
        var manager = provider.GetRequiredService<IOpenIddictTokenManager>();

        // Assert
        Assert.IsType<OpenIddictTokenManager<OpenIddictToken>>(manager);
    }

    public class OpenIddictApplication { }
    public class OpenIddictAuthorization { }
    public class OpenIddictScope { }
    public class OpenIddictToken { }
}
