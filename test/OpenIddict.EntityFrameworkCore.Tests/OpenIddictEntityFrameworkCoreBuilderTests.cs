/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore.Models;
using Xunit;
using SR = OpenIddict.Abstractions.OpenIddictResources;

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
    public void ReplaceDefaultEntities_EntitiesAreCorrectlyReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.ReplaceDefaultEntities<CustomApplication, CustomAuthorization, CustomScope, CustomToken, long>();

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

        Assert.Equal(typeof(CustomApplication), options.DefaultApplicationType);
        Assert.Equal(typeof(CustomAuthorization), options.DefaultAuthorizationType);
        Assert.Equal(typeof(CustomScope), options.DefaultScopeType);
        Assert.Equal(typeof(CustomToken), options.DefaultTokenType);
    }

    [Fact]
    public void ReplaceDefaultEntities_AllowsSpecifyingCustomKeyType()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.ReplaceDefaultEntities<long>();

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

        Assert.Equal(typeof(OpenIddictEntityFrameworkCoreApplication<long>), options.DefaultApplicationType);
        Assert.Equal(typeof(OpenIddictEntityFrameworkCoreAuthorization<long>), options.DefaultAuthorizationType);
        Assert.Equal(typeof(OpenIddictEntityFrameworkCoreScope<long>), options.DefaultScopeType);
        Assert.Equal(typeof(OpenIddictEntityFrameworkCoreToken<long>), options.DefaultTokenType);
    }

    [Fact]
    public void UseDbContext_ThrowsAnExceptionForNullType()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(delegate
        {
            return builder.UseDbContext(type: null!);
        });

        Assert.Equal("type", exception.ParamName);
    }

    [Fact]
    public void UseDbContext_ThrowsAnExceptionForInvalidType()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(delegate
        {
            return builder.UseDbContext(typeof(object));
        });

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0232), exception.Message);
    }

    [Fact]
    public void UseDbContext_SetsDbContextTypeInOptions()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.UseDbContext<CustomDbContext>();

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions>>().CurrentValue;

        Assert.Equal(typeof(CustomDbContext), options.DbContextType);
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
        public CustomDbContext(DbContextOptions options)
            : base(options)
        {
        }
    }
}
