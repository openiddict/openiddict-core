/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Data.Entity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.EntityFramework.Models;
using Xunit;

namespace OpenIddict.EntityFramework.Tests;

public class OpenIddictEntityFrameworkBuilderTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullServices()
    {
        // Arrange
        var services = (IServiceCollection) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictEntityFrameworkBuilder(services));

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
            service.ImplementationType == typeof(OpenIddictEntityFrameworkApplicationStore<CustomApplication, CustomAuthorization, CustomToken, long>));
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictAuthorizationStore<CustomAuthorization>) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkAuthorizationStore<CustomAuthorization, CustomApplication, CustomToken, long>));
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictScopeStore<CustomScope>) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkScopeStore<CustomScope, long>));
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictTokenStore<CustomToken>) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkTokenStore<CustomToken, CustomApplication, CustomAuthorization, long>));
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
            service.ServiceType == typeof(IOpenIddictEntityFrameworkContext) &&
            service.ImplementationType == typeof(OpenIddictEntityFrameworkContext<CustomDbContext>));
    }

    private static OpenIddictEntityFrameworkBuilder CreateBuilder(IServiceCollection services)
        => services.AddOpenIddict().AddCore().UseEntityFramework();

    private static IServiceCollection CreateServices()
    {
        var services = new ServiceCollection();
        services.AddOptions();

        return services;
    }

    public class CustomApplication : OpenIddictEntityFrameworkApplication<long, CustomAuthorization, CustomToken> { }
    public class CustomAuthorization : OpenIddictEntityFrameworkAuthorization<long, CustomApplication, CustomToken> { }
    public class CustomScope : OpenIddictEntityFrameworkScope<long> { }
    public class CustomToken : OpenIddictEntityFrameworkToken<long, CustomApplication, CustomAuthorization> { }

    public class CustomDbContext : DbContext
    {
        public CustomDbContext(string nameOrConnectionString)
            : base(nameOrConnectionString)
        {
        }
    }
}
