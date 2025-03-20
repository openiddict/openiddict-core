/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
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
        var exception = Assert.Throws<ArgumentNullException>(builder.UseEntityFrameworkCore);

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
    public void UseEntityFrameworkCore_RegistersUntypedManagers()
    {
        // Arrange
        var services = new ServiceCollection().AddOptions();
        var builder = new OpenIddictCoreBuilder(services);

        // Act
        builder.UseEntityFrameworkCore();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictApplicationManager) &&
            service.ImplementationFactory is not null);
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictAuthorizationManager) &&
            service.ImplementationFactory is not null);
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictScopeManager) &&
            service.ImplementationFactory is not null);
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictTokenManager) &&
            service.ImplementationFactory is not null);
    }

    [Fact]
    public void UseEntityFrameworkCore_RegistersEntityFrameworkCoreStores()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictCoreBuilder(services);

        // Act
        builder.UseEntityFrameworkCore();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictApplicationStore<OpenIddictEntityFrameworkCoreApplication>) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkCoreApplicationStore));
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictAuthorizationStore<OpenIddictEntityFrameworkCoreAuthorization>) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkCoreAuthorizationStore));
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictScopeStore<OpenIddictEntityFrameworkCoreScope>) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkCoreScopeStore));
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictTokenStore<OpenIddictEntityFrameworkCoreToken>) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkCoreTokenStore));
    }
}
