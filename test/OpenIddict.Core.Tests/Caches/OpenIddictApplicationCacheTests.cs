/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace OpenIddict.Core.Tests;

public class OpenIddictApplicationCacheTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var options = (IOptionsMonitor<OpenIddictCoreOptions>) null!;
        var store = Mock.Of<IOpenIddictApplicationStore<object>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictApplicationCache<object>(options, store));

        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullStore()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = (IOpenIddictApplicationStore<object>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictApplicationCache<object>(options, store));

        Assert.Equal("store", exception.ParamName);
    }

    [Fact]
    public async Task AddAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<OpenIddictApplication>>();
        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.AddAsync(application: null!, CancellationToken.None).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<OpenIddictApplication>>();
        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store);

        // Act and assert
        cache.Dispose();
        cache.Dispose();
    }

    [Fact]
    public async Task FindByClientIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<OpenIddictApplication>>();
        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.FindByClientIdAsync(identifier: null!, CancellationToken.None).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByClientIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<OpenIddictApplication>>();
        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => cache.FindByClientIdAsync(identifier: string.Empty, CancellationToken.None).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByClientIdAsync_ReturnsCachedApplicationOnCacheHit()
    {
        // Arrange
        var application = new OpenIddictApplication();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<OpenIddictApplication>>();

        store.Setup(store => store.GetIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");
        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");
        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);
        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store.Object);

        await cache.AddAsync(application, CancellationToken.None);

        // Act
        var result = await cache.FindByClientIdAsync("client-id", CancellationToken.None);

        // Assert
        Assert.Same(application, result);
        store.Verify(store => store.FindByClientIdAsync("client-id", It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByClientIdAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var application = new OpenIddictApplication();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<OpenIddictApplication>>();

        store.Setup(store => store.FindByClientIdAsync("client-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(application);
        store.Setup(store => store.GetIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");
        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");
        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);
        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store.Object);

        // Act
        var result = await cache.FindByClientIdAsync("client-id", CancellationToken.None);

        // Assert
        Assert.Same(application, result);
        store.Verify(store => store.FindByClientIdAsync("client-id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<OpenIddictApplication>>();
        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.FindByIdAsync(identifier: null!, CancellationToken.None).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<OpenIddictApplication>>();
        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => cache.FindByIdAsync(identifier: string.Empty, CancellationToken.None).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsCachedApplicationOnCacheHit()
    {
        // Arrange
        var application = new OpenIddictApplication();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<OpenIddictApplication>>();

        store.Setup(store => store.GetIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");
        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");
        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);
        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store.Object);

        await cache.AddAsync(application, CancellationToken.None);

        // Act
        var result = await cache.FindByIdAsync("application-id", CancellationToken.None);

        // Assert
        Assert.Same(application, result);
        store.Verify(store => store.FindByIdAsync("application-id", It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByIdAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var application = new OpenIddictApplication();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<OpenIddictApplication>>();

        store.Setup(store => store.FindByIdAsync("application-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(application);
        store.Setup(store => store.GetIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");
        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");
        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);
        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store.Object);

        // Act
        var result = await cache.FindByIdAsync("application-id", CancellationToken.None);

        // Assert
        Assert.Same(application, result);
        store.Verify(store => store.FindByIdAsync("application-id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsNullWhenApplicationNotFound()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<OpenIddictApplication>>();

        store.Setup(store => store.FindByIdAsync("application-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync((OpenIddictApplication?) null);

        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store.Object);

        // Act
        var result = await cache.FindByIdAsync("application-id", CancellationToken.None);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task FindByPostLogoutRedirectUriAsync_ReturnsCachedApplicationsOnCacheHit()
    {
        // Arrange
        var applications = new[]
        {
            new OpenIddictApplication(),
            new OpenIddictApplication()
        };
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<OpenIddictApplication>>();

        store.Setup(store => store.GetIdAsync(applications[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id-1");
        store.Setup(store => store.GetClientIdAsync(applications[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id-1");
        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(applications[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);
        store.Setup(store => store.GetRedirectUrisAsync(applications[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetIdAsync(applications[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id-2");
        store.Setup(store => store.GetClientIdAsync(applications[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id-2");
        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(applications[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);
        store.Setup(store => store.GetRedirectUrisAsync(applications[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.FindByPostLogoutRedirectUriAsync("https://localhost/signout-callback", It.IsAny<CancellationToken>()))
             .Returns(applications.ToAsyncEnumerable());

        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store.Object);

        await cache.FindByPostLogoutRedirectUriAsync("https://localhost/signout-callback", CancellationToken.None).ToListAsync();

        // Act
        var results = await cache.FindByPostLogoutRedirectUriAsync("https://localhost/signout-callback", CancellationToken.None).ToListAsync();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(applications[0], results);
        Assert.Contains(applications[1], results);
        store.Verify(store => store.FindByPostLogoutRedirectUriAsync("https://localhost/signout-callback", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByRedirectUriAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var applications = new[]
        {
            new OpenIddictApplication(),
            new OpenIddictApplication()
        };
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<OpenIddictApplication>>();

        store.Setup(store => store.GetIdAsync(applications[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id-1");
        store.Setup(store => store.GetClientIdAsync(applications[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id-1");
        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(applications[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);
        store.Setup(store => store.GetRedirectUrisAsync(applications[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetIdAsync(applications[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id-2");
        store.Setup(store => store.GetClientIdAsync(applications[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id-2");
        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(applications[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);
        store.Setup(store => store.GetRedirectUrisAsync(applications[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.FindByRedirectUriAsync("https://localhost/callback", It.IsAny<CancellationToken>()))
             .Returns(applications.ToAsyncEnumerable());

        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store.Object);

        // Act
        var results = await cache.FindByRedirectUriAsync("https://localhost/callback", CancellationToken.None).ToListAsync();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(applications[0], results);
        Assert.Contains(applications[1], results);
        store.Verify(store => store.FindByRedirectUriAsync("https://localhost/callback", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task RemoveAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<OpenIddictApplication>>();
        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.RemoveAsync(application: null!, CancellationToken.None).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task RemoveAsync_InvalidatesCachedEntries()
    {
        // Arrange
        var application = new OpenIddictApplication();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<OpenIddictApplication>>();

        store.Setup(store => store.GetIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");
        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");
        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);
        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store.Object);

        await cache.AddAsync(application, CancellationToken.None);

        // Act
        await cache.RemoveAsync(application, CancellationToken.None);

        var result = await cache.FindByIdAsync("application-id", CancellationToken.None);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task RemoveAsync_ThrowsForApplicationWithoutId()
    {
        // Arrange
        var application = new OpenIddictApplication();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<OpenIddictApplication>>();

        store.Setup(store => store.GetIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        var cache = new OpenIddictApplicationCache<OpenIddictApplication>(options, store.Object);

        // Act and assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => cache.RemoveAsync(application, CancellationToken.None).AsTask());
    }

    public sealed class OpenIddictApplication { }
}
