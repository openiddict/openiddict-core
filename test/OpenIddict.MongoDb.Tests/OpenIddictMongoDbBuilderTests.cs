/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using Moq;
using OpenIddict.Core;
using OpenIddict.MongoDb.Models;
using Xunit;

namespace OpenIddict.MongoDb.Tests;

public class OpenIddictMongoDbBuilderTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullServices()
    {
        // Arrange
        var services = (IServiceCollection) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictMongoDbBuilder(services));

        Assert.Equal("services", exception.ParamName);
    }

    [Fact]
    public void ReplaceDefaultApplicationEntity_StoreIsCorrectlyReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.ReplaceDefaultApplicationEntity<CustomApplication>();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictApplicationStore<CustomApplication>) &&
            service.ImplementationType == typeof(OpenIddictMongoDbApplicationStore<CustomApplication>));
    }

    [Fact]
    public void ReplaceDefaultAuthorizationEntity_StoreIsCorrectlyReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.ReplaceDefaultAuthorizationEntity<CustomAuthorization>();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictAuthorizationStore<CustomAuthorization>) &&
            service.ImplementationType == typeof(OpenIddictMongoDbAuthorizationStore<CustomAuthorization>));
    }

    [Fact]
    public void ReplaceDefaultScopeEntity_StoreIsCorrectlyReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.ReplaceDefaultScopeEntity<CustomScope>();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictScopeStore<CustomScope>) &&
            service.ImplementationType == typeof(OpenIddictMongoDbScopeStore<CustomScope>));
    }

    [Fact]
    public void ReplaceDefaultTokenEntity_StoreIsCorrectlyReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.ReplaceDefaultTokenEntity<CustomToken>();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Scoped &&
            service.ServiceType == typeof(IOpenIddictTokenStore<CustomToken>) &&
            service.ImplementationType == typeof(OpenIddictMongoDbTokenStore<CustomToken>));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void SetApplicationsCollectionName_ThrowsAnExceptionForNullOrEmptyCollectionName(string? name)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetApplicationsCollectionName(name!));

        Assert.Equal("name", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0261), exception.Message);
    }

    [Fact]
    public void SetApplicationsCollectionName_CollectionNameIsCorrectlySet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetApplicationsCollectionName("custom_collection");

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictMongoDbOptions>>().CurrentValue;

        Assert.Equal("custom_collection", options.ApplicationsCollectionName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void SetAuthorizationsCollectionName_ThrowsAnExceptionForNullOrEmptyCollectionName(string? name)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetAuthorizationsCollectionName(name!));

        Assert.Equal("name", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0261), exception.Message);
    }

    [Fact]
    public void SetAuthorizationsCollectionName_CollectionNameIsCorrectlySet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetAuthorizationsCollectionName("custom_collection");

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictMongoDbOptions>>().CurrentValue;

        Assert.Equal("custom_collection", options.AuthorizationsCollectionName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void SetScopesCollectionName_ThrowsAnExceptionForNullOrEmptyCollectionName(string? name)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetScopesCollectionName(name!));

        Assert.Equal("name", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0261), exception.Message);
    }

    [Fact]
    public void SetScopesCollectionName_CollectionNameIsCorrectlySet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetScopesCollectionName("custom_collection");

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictMongoDbOptions>>().CurrentValue;

        Assert.Equal("custom_collection", options.ScopesCollectionName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void SetTokensCollectionName_ThrowsAnExceptionForNullOrEmptyCollectionName(string? name)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetTokensCollectionName(name!));

        Assert.Equal("name", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0261), exception.Message);
    }

    [Fact]
    public void SetTokensCollectionName_CollectionNameIsCorrectlySet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetTokensCollectionName("custom_collection");

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictMongoDbOptions>>().CurrentValue;

        Assert.Equal("custom_collection", options.TokensCollectionName);
    }

    [Fact]
    public void UseDatabase_ThrowsAnExceptionForNullDatabase()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(delegate
        {
            return builder.UseDatabase(database: null!);
        });

        Assert.Equal("database", exception.ParamName);
    }

    [Fact]
    public void UseDatabase_SetsDatabaseInOptions()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var database = Mock.Of<IMongoDatabase>();

        // Act
        builder.UseDatabase(database);

        // Assert
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictMongoDbOptions>>().CurrentValue;

        Assert.Equal(database, options.Database);
    }

    private static OpenIddictMongoDbBuilder CreateBuilder(IServiceCollection services)
        => services.AddOpenIddict().AddCore().UseMongoDb();

    private static IServiceCollection CreateServices()
    {
        var services = new ServiceCollection();
        services.AddOptions();

        return services;
    }

    public class CustomApplication : OpenIddictMongoDbApplication { }
    public class CustomAuthorization : OpenIddictMongoDbAuthorization { }
    public class CustomScope : OpenIddictMongoDbScope { }
    public class CustomToken : OpenIddictMongoDbToken { }
}
