/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.EntityFrameworkCore.Models;
using Xunit;

namespace OpenIddict.EntityFrameworkCore.Tests;

public class OpenIddictEntityFrameworkCoreBuilderTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullServices()
    {
        // Arrange
        var services = (IServiceCollection) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictEntityFrameworkCoreBuilder(services));

        Assert.Equal("services", exception.ParamName);
    }

    [Fact]
    public void ReplaceDefaultEntities_StoresAreCorrectlyReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.ReplaceDefaultEntities<CustomApplication, CustomAuthorization, CustomScope, CustomToken, long>();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictApplicationStore<CustomApplication>) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkCoreApplicationStore<CustomApplication, CustomAuthorization, CustomToken, long>));
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictAuthorizationStore<CustomAuthorization>) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkCoreAuthorizationStore<CustomAuthorization, CustomApplication, CustomToken, long>));
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictScopeStore<CustomScope>) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkCoreScopeStore<CustomScope, long>));
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictTokenStore<CustomToken>) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkCoreTokenStore<CustomToken, CustomApplication, CustomAuthorization, long>));
    }

    [Fact]
    public void UseDbContext_OverridesContextType()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.UseDbContext<CustomDbContext>();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictEntityFrameworkCoreContext) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkCoreContext<CustomDbContext>));
    }

    private static OpenIddictEntityFrameworkCoreBuilder CreateBuilder(IServiceCollection services)
        => services.AddOpenIddict().AddCore().UseEntityFrameworkCore();

    private static IServiceCollection CreateServices()
    {
        var services = new ServiceCollection();
        services.AddOptions();

        return services;
    }

    public class CustomApplication : OpenIddictEntityFrameworkCoreApplication<long, CustomAuthorization, CustomToken> { }
    public class CustomAuthorization : OpenIddictEntityFrameworkCoreAuthorization<long, CustomApplication, CustomToken> { }
    public class CustomScope : OpenIddictEntityFrameworkCoreScope<long> { }
    public class CustomToken : OpenIddictEntityFrameworkCoreToken<long, CustomApplication, CustomAuthorization> { }

    public class CustomDbContext : DbContext
    {
    }
}
