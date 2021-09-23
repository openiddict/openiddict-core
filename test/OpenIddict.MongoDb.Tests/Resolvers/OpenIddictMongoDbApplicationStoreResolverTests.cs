/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.MongoDb.Models;
using Xunit;

namespace OpenIddict.MongoDb.Tests;

public class OpenIddictMongoDbApplicationStoreResolverTests
{
    [Fact]
    public void Get_ReturnsCustomStoreCorrespondingToTheSpecifiedTypeWhenAvailable()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IOpenIddictApplicationStore<CustomApplication>>());

        var provider = services.BuildServiceProvider();
        var resolver = new OpenIddictMongoDbApplicationStoreResolver(provider);

        // Act and assert
        Assert.NotNull(resolver.Get<CustomApplication>());
    }

    [Fact]
    public void Get_ThrowsAnExceptionForInvalidEntityType()
    {
        // Arrange
        var services = new ServiceCollection();

        var provider = services.BuildServiceProvider();
        var resolver = new OpenIddictMongoDbApplicationStoreResolver(provider);

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => resolver.Get<CustomApplication>());

        Assert.Equal(SR.GetResourceString(SR.ID0257), exception.Message);
    }

    [Fact]
    public void Get_ReturnsDefaultStoreCorrespondingToTheSpecifiedTypeWhenAvailable()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IOpenIddictApplicationStore<CustomApplication>>());
        services.AddSingleton(CreateStore());

        var provider = services.BuildServiceProvider();
        var resolver = new OpenIddictMongoDbApplicationStoreResolver(provider);

        // Act and assert
        Assert.NotNull(resolver.Get<MyApplication>());
    }

    private static OpenIddictMongoDbApplicationStore<MyApplication> CreateStore()
        => new Mock<OpenIddictMongoDbApplicationStore<MyApplication>>(
            Mock.Of<IOpenIddictMongoDbContext>(),
            Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>()).Object;

    public class CustomApplication { }

    public class MyApplication : OpenIddictMongoDbApplication { }
}
