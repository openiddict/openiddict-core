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

public class OpenIddictMongoDbAuthorizationStoreResolverTests
{
    [Fact]
    public void Get_ReturnsCustomStoreCorrespondingToTheSpecifiedTypeWhenAvailable()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>());

        var provider = services.BuildServiceProvider();
        var resolver = new OpenIddictMongoDbAuthorizationStoreResolver(provider);

        // Act and assert
        Assert.NotNull(resolver.Get<CustomAuthorization>());
    }

    [Fact]
    public void Get_ThrowsAnExceptionForInvalidEntityType()
    {
        // Arrange
        var services = new ServiceCollection();

        var provider = services.BuildServiceProvider();
        var resolver = new OpenIddictMongoDbAuthorizationStoreResolver(provider);

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => resolver.Get<CustomAuthorization>());

        Assert.Equal(SR.GetResourceString(SR.ID0258), exception.Message);
    }

    [Fact]
    public void Get_ReturnsDefaultStoreCorrespondingToTheSpecifiedTypeWhenAvailable()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>());
        services.AddSingleton(CreateStore());

        var provider = services.BuildServiceProvider();
        var resolver = new OpenIddictMongoDbAuthorizationStoreResolver(provider);

        // Act and assert
        Assert.NotNull(resolver.Get<MyAuthorization>());
    }

    private static OpenIddictMongoDbAuthorizationStore<MyAuthorization> CreateStore()
        => new Mock<OpenIddictMongoDbAuthorizationStore<MyAuthorization>>(
            Mock.Of<IOpenIddictMongoDbContext>(),
            Mock.Of<IOptionsMonitor<OpenIddictMongoDbOptions>>()).Object;

    public class CustomAuthorization { }

    public class MyAuthorization : OpenIddictMongoDbAuthorization { }
}
