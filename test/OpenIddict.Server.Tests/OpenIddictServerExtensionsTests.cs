/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Server.Tests;

public class OpenIddictServerExtensionsTests
{
    [Fact]
    public void AddServer_ThrowsAnExceptionForNullBuilder()
    {
        // Arrange
        var builder = (OpenIddictBuilder) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddServer());

        Assert.Equal("builder", exception.ParamName);
    }

    [Fact]
    public void AddServer_ThrowsAnExceptionForNullConfiguration()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddServer(configuration: null!));

        Assert.Equal("configuration", exception.ParamName);
    }

    [Fact]
    public void AddServer_RegistersLoggingServices()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddServer();

        // Assert
        Assert.Contains(services, service => service.ServiceType == typeof(ILogger<>));
    }

    [Fact]
    public void AddServer_RegistersOptionsServices()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddServer();

        // Assert
        Assert.Contains(services, service => service.ServiceType == typeof(IOptions<>));
    }
    
    [Fact]
    public void AddServer_RegistersServerDispatcher()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddServer();

        // Assert
        Assert.Contains(services, service => service.ServiceType == typeof(IOpenIddictServerDispatcher) &&
                                             service.ImplementationType == typeof(OpenIddictServerDispatcher) &&
                                             service.Lifetime == ServiceLifetime.Scoped);
    }
    
    [Fact]
    public void AddServer_RegistersServerFactory()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddServer();

        // Assert
        Assert.Contains(services, service => service.ServiceType == typeof(IOpenIddictServerFactory) &&
                                             service.ImplementationType == typeof(OpenIddictServerFactory) &&
                                             service.Lifetime == ServiceLifetime.Scoped);
    }

    public static IEnumerable<object[]> DefaultHandlers
        => OpenIddictServerHandlers.DefaultHandlers.Select(descriptor => new object[] { descriptor });
    
    [Theory]
    [MemberData(nameof(DefaultHandlers))]
    public void AddServer_RegistersDefaultHandler(OpenIddictServerHandlerDescriptor descriptor)
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddServer();

        // Assert
        Assert.Contains(services, service => service.Lifetime == descriptor.ServiceDescriptor.Lifetime &&
                                             service.ServiceType == descriptor.ServiceDescriptor.ServiceType &&
                                             service.ImplementationType == descriptor.ServiceDescriptor.ImplementationType);
    }

    [Theory]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireAuthorizationStorageEnabled))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireAuthorizationRequest))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireClientIdParameter))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireConfigurationRequest))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireCryptographyRequest))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireDegradedModeDisabled))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireDeviceRequest))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireEndpointPermissionsEnabled))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireGrantTypePermissionsEnabled))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireIntrospectionRequest))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireLogoutRequest))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequirePostLogoutRedirectUriParameter))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireReferenceAccessTokensEnabled))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireReferenceRefreshTokensEnabled))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireRevocationRequest))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireSlidingRefreshTokenExpirationEnabled))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireScopePermissionsEnabled))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireScopeValidationEnabled))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireTokenStorageEnabled))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireTokenRequest))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireUserinfoRequest))]
    [InlineData(typeof(OpenIddictServerHandlerFilters.RequireVerificationRequest))]
    public void AddServer_RegistersRequiredSingletons(Type type)
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddServer();

        // Assert
        Assert.Contains(services, service => service.ServiceType == type &&
                                             service.ImplementationType == type &&
                                             service.Lifetime == ServiceLifetime.Singleton);
    }

    [Fact]
    public void AddServer_ResolvingProviderThrowsAnExceptionWhenCoreServicesAreNotRegistered()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddServer();

        // Assert
        var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<OpenIddictServerConfiguration>());

        Assert.NotNull(exception);
    }

    [Theory]
    [InlineData(typeof(IPostConfigureOptions<OpenIddictServerOptions>), typeof(OpenIddictServerConfiguration))]
    public void AddServer_RegistersConfiguration(Type serviceType, Type implementationType)
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddServer();

        // Assert
        Assert.Contains(services, service => service.ServiceType == serviceType &&
                                             service.ImplementationType == implementationType);
    }
    
    [Fact]
    public void AddServer_CanBeSafelyInvokedMultipleTimes()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act and assert
        builder.AddServer();
        builder.AddServer();
        builder.AddServer();
    }
}
