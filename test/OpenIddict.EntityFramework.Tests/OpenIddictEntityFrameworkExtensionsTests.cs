/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using OpenIddict.EntityFramework.Models;
using Xunit;

namespace OpenIddict.EntityFramework.Tests;

public class OpenIddictEntityFrameworkExtensionsTests
{
    [Fact]
    public void UseEntityFramework_ThrowsAnExceptionForNullBuilder()
    {
        // Arrange
        var builder = (OpenIddictCoreBuilder) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(builder.UseEntityFramework);

        Assert.Equal("builder", exception.ParamName);
    }

    [Fact]
    public void UseEntityFramework_ThrowsAnExceptionForNullConfiguration()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictCoreBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.UseEntityFramework(configuration: null!));

        Assert.Equal("configuration", exception.ParamName);
    }

    [Fact]
    public void UseEntityFramework_RegistersUntypedManagers()
    {
        // Arrange
        var services = new ServiceCollection().AddOptions();
        var builder = new OpenIddictCoreBuilder(services);

        // Act
        builder.UseEntityFramework();

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
    public void UseEntityFramework_RegistersEntityFrameworkStores()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictCoreBuilder(services);

        // Act
        builder.UseEntityFramework();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictApplicationStore<OpenIddictEntityFrameworkApplication>) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkApplicationStore));
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictAuthorizationStore<OpenIddictEntityFrameworkAuthorization>) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkAuthorizationStore));
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictScopeStore<OpenIddictEntityFrameworkScope>) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkScopeStore));
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictTokenStore<OpenIddictEntityFrameworkToken>) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkTokenStore));
    }
}
