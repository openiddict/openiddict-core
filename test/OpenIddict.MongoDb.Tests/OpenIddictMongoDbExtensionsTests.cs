/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using OpenIddict.MongoDb.Models;
using Xunit;

namespace OpenIddict.MongoDb.Tests;

public class OpenIddictMongoDbExtensionsTests
{
    [Fact]
    public void UseMongoDb_ThrowsAnExceptionForNullBuilder()
    {
        // Arrange
        var builder = (OpenIddictCoreBuilder) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(builder.UseMongoDb);

        Assert.Equal("builder", exception.ParamName);
    }

    [Fact]
    public void UseMongoDb_ThrowsAnExceptionForNullConfiguration()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictCoreBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.UseMongoDb(configuration: null!));

        Assert.Equal("configuration", exception.ParamName);
    }

    [Fact]
    public void UseMongoDb_RegistersUntypedManagers()
    {
        // Arrange
        var services = new ServiceCollection().AddOptions();
        var builder = new OpenIddictCoreBuilder(services);

        // Act
        builder.UseMongoDb();

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
    public void UseMongoDb_RegistersMongoDbStores()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictCoreBuilder(services);

        // Act
        builder.UseMongoDb();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Singleton &&
            service.ServiceType == typeof(IOpenIddictApplicationStore<OpenIddictMongoDbApplication>) &&
            service.ImplementationType == typeof(OpenIddictMongoDbApplicationStore));
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Singleton &&
            service.ServiceType == typeof(IOpenIddictAuthorizationStore<OpenIddictMongoDbAuthorization>) &&
            service.ImplementationType == typeof(OpenIddictMongoDbAuthorizationStore));
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Singleton &&
            service.ServiceType == typeof(IOpenIddictScopeStore<OpenIddictMongoDbScope>) &&
            service.ImplementationType == typeof(OpenIddictMongoDbScopeStore));
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Singleton &&
            service.ServiceType == typeof(IOpenIddictTokenStore<OpenIddictMongoDbToken>) &&
            service.ImplementationType == typeof(OpenIddictMongoDbTokenStore));
    }

    [Fact]
    public void UseMongoDb_RegistersMongoDbContext()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictCoreBuilder(services);

        // Act
        builder.UseMongoDb();

        // Assert
        Assert.Contains(services, service =>
            service.Lifetime == ServiceLifetime.Singleton &&
            service.ServiceType == typeof(IOpenIddictMongoDbContext) &&
            service.ImplementationType == typeof(OpenIddictMongoDbContext));
    }
}
