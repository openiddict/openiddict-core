/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace OpenIddict.Core.Tests;

public class OpenIddictResourceCacheTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var options = (IOptionsMonitor<OpenIddictCoreOptions>) null!;
        var store = Mock.Of<IOpenIddictResourceStore<object>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictResourceCache<object>(options, store));

        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullStore()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = (IOpenIddictResourceStore<object>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictResourceCache<object>(options, store));

        Assert.Equal("store", exception.ParamName);
    }

    [Fact]
    public async Task AddAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictResourceStore<OpenIddictResource>>();
        var cache = new OpenIddictResourceCache<OpenIddictResource>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.AddAsync(resource: null!, CancellationToken.None).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictResourceStore<OpenIddictResource>>();
        var cache = new OpenIddictResourceCache<OpenIddictResource>(options, store);

        // Act and assert
        cache.Dispose();
        cache.Dispose();
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictResourceStore<OpenIddictResource>>();
        var cache = new OpenIddictResourceCache<OpenIddictResource>(options, store);

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
        var store = Mock.Of<IOpenIddictResourceStore<OpenIddictResource>>();
        var cache = new OpenIddictResourceCache<OpenIddictResource>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => cache.FindByIdAsync(identifier: string.Empty, CancellationToken.None).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsCachedResourceOnCacheHit()
    {
        // Arrange
        var resource = new OpenIddictResource();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictResourceStore<OpenIddictResource>>();

        store.Setup(store => store.GetIdAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("resource-id");
        store.Setup(store => store.GetNameAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("resource-name");

        var cache = new OpenIddictResourceCache<OpenIddictResource>(options, store.Object);

        await cache.AddAsync(resource, CancellationToken.None);

        // Act
        var result = await cache.FindByIdAsync("resource-id", CancellationToken.None);

        // Assert
        Assert.Same(resource, result);
        store.Verify(store => store.FindByIdAsync("resource-id", It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByIdAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var resource = new OpenIddictResource();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictResourceStore<OpenIddictResource>>();

        store.Setup(store => store.FindByIdAsync("resource-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(resource);
        store.Setup(store => store.GetIdAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("resource-id");
        store.Setup(store => store.GetNameAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("resource-name");

        var cache = new OpenIddictResourceCache<OpenIddictResource>(options, store.Object);

        // Act
        var result = await cache.FindByIdAsync("resource-id", CancellationToken.None);

        // Assert
        Assert.Same(resource, result);
        store.Verify(store => store.FindByIdAsync("resource-id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsNullWhenResourceNotFound()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictResourceStore<OpenIddictResource>>();

        store.Setup(store => store.FindByIdAsync("resource-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync((OpenIddictResource?) null);

        var cache = new OpenIddictResourceCache<OpenIddictResource>(options, store.Object);

        // Act
        var result = await cache.FindByIdAsync("resource-id", CancellationToken.None);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task FindByNameAsync_ThrowsAnExceptionForNullName()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictResourceStore<OpenIddictResource>>();
        var cache = new OpenIddictResourceCache<OpenIddictResource>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.FindByNameAsync(name: null!, CancellationToken.None).AsTask());

        Assert.Equal("name", exception.ParamName);
    }

    [Fact]
    public async Task FindByNameAsync_ThrowsAnExceptionForEmptyName()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictResourceStore<OpenIddictResource>>();
        var cache = new OpenIddictResourceCache<OpenIddictResource>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => cache.FindByNameAsync(name: string.Empty, CancellationToken.None).AsTask());

        Assert.Equal("name", exception.ParamName);
    }

    [Fact]
    public async Task FindByNameAsync_ReturnsCachedResourceOnCacheHit()
    {
        // Arrange
        var resource = new OpenIddictResource();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictResourceStore<OpenIddictResource>>();

        store.Setup(store => store.GetIdAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("resource-id");
        store.Setup(store => store.GetNameAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("resource-name");

        var cache = new OpenIddictResourceCache<OpenIddictResource>(options, store.Object);

        await cache.AddAsync(resource, CancellationToken.None);

        // Act
        var result = await cache.FindByNameAsync("resource-name", CancellationToken.None);

        // Assert
        Assert.Same(resource, result);
        store.Verify(store => store.FindByNameAsync("resource-name", It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByNameAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var resource = new OpenIddictResource();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictResourceStore<OpenIddictResource>>();

        store.Setup(store => store.FindByNameAsync("resource-name", It.IsAny<CancellationToken>()))
             .ReturnsAsync(resource);
        store.Setup(store => store.GetIdAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("resource-id");
        store.Setup(store => store.GetNameAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("resource-name");

        var cache = new OpenIddictResourceCache<OpenIddictResource>(options, store.Object);

        // Act
        var result = await cache.FindByNameAsync("resource-name", CancellationToken.None);

        // Assert
        Assert.Same(resource, result);
        store.Verify(store => store.FindByNameAsync("resource-name", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByNamesAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var resources = new[]
        {
            new OpenIddictResource(),
            new OpenIddictResource()
        };
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictResourceStore<OpenIddictResource>>();

        store.Setup(store => store.GetIdAsync(resources[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("resource-id-1");
        store.Setup(store => store.GetNameAsync(resources[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("resource-name-1");

        store.Setup(store => store.GetIdAsync(resources[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("resource-id-2");
        store.Setup(store => store.GetNameAsync(resources[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("resource-name-2");

        store.Setup(store => store.FindByNamesAsync(It.IsAny<ImmutableArray<string>>(), It.IsAny<CancellationToken>()))
             .Returns(resources.ToAsyncEnumerable());

        var cache = new OpenIddictResourceCache<OpenIddictResource>(options, store.Object);

        // Act
        var results = await cache.FindByNamesAsync(["resource-name-1", "resource-name-2"], CancellationToken.None).ToListAsync();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(resources[0], results);
        Assert.Contains(resources[1], results);
    }

    [Fact]
    public async Task RemoveAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictResourceStore<OpenIddictResource>>();
        var cache = new OpenIddictResourceCache<OpenIddictResource>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.RemoveAsync(resource: null!, CancellationToken.None).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task RemoveAsync_InvalidatesCachedEntries()
    {
        // Arrange
        var resource = new OpenIddictResource();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictResourceStore<OpenIddictResource>>();

        store.Setup(store => store.GetIdAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("resource-id");
        store.Setup(store => store.GetNameAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("resource-name");

        var cache = new OpenIddictResourceCache<OpenIddictResource>(options, store.Object);

        await cache.AddAsync(resource, CancellationToken.None);

        // Act
        await cache.RemoveAsync(resource, CancellationToken.None);

        var result = await cache.FindByIdAsync("resource-id", CancellationToken.None);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task RemoveAsync_ThrowsForResourceWithoutId()
    {
        // Arrange
        var resource = new OpenIddictResource();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictResourceStore<OpenIddictResource>>();

        store.Setup(store => store.GetIdAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        var cache = new OpenIddictResourceCache<OpenIddictResource>(options, store.Object);

        // Act and assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => cache.RemoveAsync(resource, CancellationToken.None).AsTask());
    }

    public sealed class OpenIddictResource;
}
