/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore.Models;
using Xunit;

namespace OpenIddict.EntityFrameworkCore.Tests;

public class OpenIddictEntityFrameworkCoreExtensionsTests
{
    [Fact]
    public void UseEntityFrameworkCore_ThrowsAnExceptionForNullBuilder()
    {
        // Arrange
        var builder = (OpenIddictCoreBuilder) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.UseEntityFrameworkCore());

        Assert.Equal("builder", exception.ParamName);
    }

    [Fact]
    public void UseEntityFrameworkCore_ThrowsAnExceptionForNullConfiguration()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictCoreBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.UseEntityFrameworkCore(configuration: null!));

        Assert.Equal("configuration", exception.ParamName);
    }

    [Fact]
    public void UseEntityFrameworkCore_RegistersDefaultEntities()
    {
        // Arrange
        var services = new ServiceCollection().AddOptions();
        var builder = new OpenIddictCoreBuilder(services);

        // Act
        builder.UseEntityFrameworkCore();

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

        Assert.Equal(typeof(OpenIddictEntityFrameworkCoreApplication), options.DefaultApplicationType);
        Assert.Equal(typeof(OpenIddictEntityFrameworkCoreAuthorization), options.DefaultAuthorizationType);
        Assert.Equal(typeof(OpenIddictEntityFrameworkCoreScope), options.DefaultScopeType);
        Assert.Equal(typeof(OpenIddictEntityFrameworkCoreToken), options.DefaultTokenType);
    }

    [Theory]
    [InlineData(typeof(IOpenIddictApplicationStoreResolver), typeof(OpenIddictEntityFrameworkCoreApplicationStoreResolver))]
    [InlineData(typeof(IOpenIddictAuthorizationStoreResolver), typeof(OpenIddictEntityFrameworkCoreAuthorizationStoreResolver))]
    [InlineData(typeof(IOpenIddictScopeStoreResolver), typeof(OpenIddictEntityFrameworkCoreScopeStoreResolver))]
    [InlineData(typeof(IOpenIddictTokenStoreResolver), typeof(OpenIddictEntityFrameworkCoreTokenStoreResolver))]
    public void UseEntityFrameworkCore_RegistersEntityFrameworkCoreStoreResolvers(Type serviceType, Type implementationType)
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictCoreBuilder(services);

        // Act
        builder.UseEntityFrameworkCore();

        // Assert
        Assert.Contains(services, service => service.ServiceType == serviceType &&
                                             service.ImplementationType == implementationType);
    }

    [Theory]
    [InlineData(typeof(OpenIddictEntityFrameworkCoreApplicationStoreResolver.TypeResolutionCache))]
    [InlineData(typeof(OpenIddictEntityFrameworkCoreAuthorizationStoreResolver.TypeResolutionCache))]
    [InlineData(typeof(OpenIddictEntityFrameworkCoreScopeStoreResolver.TypeResolutionCache))]
    [InlineData(typeof(OpenIddictEntityFrameworkCoreTokenStoreResolver.TypeResolutionCache))]
    public void UseEntityFrameworkCore_RegistersEntityFrameworkCoreStoreResolverCaches(Type type)
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictCoreBuilder(services);

        // Act
        builder.UseEntityFrameworkCore();

        // Assert
        Assert.Contains(services, service => service.ServiceType == type &&
                                             service.ImplementationType == type);
    }

    [Theory]
    [InlineData(typeof(OpenIddictEntityFrameworkCoreApplicationStore<,,,,>))]
    [InlineData(typeof(OpenIddictEntityFrameworkCoreAuthorizationStore<,,,,>))]
    [InlineData(typeof(OpenIddictEntityFrameworkCoreScopeStore<,,>))]
    [InlineData(typeof(OpenIddictEntityFrameworkCoreTokenStore<,,,,>))]
    public void UseEntityFrameworkCore_RegistersEntityFrameworkCoreStore(Type type)
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictCoreBuilder(services);

        // Act
        builder.UseEntityFrameworkCore();

        // Assert
        Assert.Contains(services, service => service.ServiceType == type && service.ImplementationType == type);
    }
}
