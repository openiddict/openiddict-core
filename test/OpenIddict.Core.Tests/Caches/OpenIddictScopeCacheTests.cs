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

public class OpenIddictScopeCacheTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var options = (IOptionsMonitor<OpenIddictCoreOptions>) null!;
        var store = Mock.Of<IOpenIddictScopeStore<object>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictScopeCache<object>(options, store));

        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullStore()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = (IOpenIddictScopeStore<object>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictScopeCache<object>(options, store));

        Assert.Equal("store", exception.ParamName);
    }

    [Fact]
    public async Task AddAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictScopeStore<OpenIddictScope>>();
        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.AddAsync(scope: null!, CancellationToken.None).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictScopeStore<OpenIddictScope>>();
        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store);

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
        var store = Mock.Of<IOpenIddictScopeStore<OpenIddictScope>>();
        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store);

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
        var store = Mock.Of<IOpenIddictScopeStore<OpenIddictScope>>();
        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => cache.FindByIdAsync(identifier: string.Empty, CancellationToken.None).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsCachedScopeOnCacheHit()
    {
        // Arrange
        var scope = new OpenIddictScope();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictScopeStore<OpenIddictScope>>();

        store.Setup(store => store.GetIdAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-id");
        store.Setup(store => store.GetNameAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-name");
        store.Setup(store => store.GetResourcesAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store.Object);

        await cache.AddAsync(scope, CancellationToken.None);

        // Act
        var result = await cache.FindByIdAsync("scope-id", CancellationToken.None);

        // Assert
        Assert.Same(scope, result);
        store.Verify(store => store.FindByIdAsync("scope-id", It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByIdAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var scope = new OpenIddictScope();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictScopeStore<OpenIddictScope>>();

        store.Setup(store => store.FindByIdAsync("scope-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(scope);
        store.Setup(store => store.GetIdAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-id");
        store.Setup(store => store.GetNameAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-name");
        store.Setup(store => store.GetResourcesAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store.Object);

        // Act
        var result = await cache.FindByIdAsync("scope-id", CancellationToken.None);

        // Assert
        Assert.Same(scope, result);
        store.Verify(store => store.FindByIdAsync("scope-id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsNullWhenScopeNotFound()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictScopeStore<OpenIddictScope>>();

        store.Setup(store => store.FindByIdAsync("scope-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync((OpenIddictScope?) null);

        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store.Object);

        // Act
        var result = await cache.FindByIdAsync("scope-id", CancellationToken.None);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task FindByNameAsync_ThrowsAnExceptionForNullName()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictScopeStore<OpenIddictScope>>();
        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store);

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
        var store = Mock.Of<IOpenIddictScopeStore<OpenIddictScope>>();
        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => cache.FindByNameAsync(name: string.Empty, CancellationToken.None).AsTask());

        Assert.Equal("name", exception.ParamName);
    }

    [Fact]
    public async Task FindByNameAsync_ReturnsCachedScopeOnCacheHit()
    {
        // Arrange
        var scope = new OpenIddictScope();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictScopeStore<OpenIddictScope>>();

        store.Setup(store => store.GetIdAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-id");
        store.Setup(store => store.GetNameAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-name");
        store.Setup(store => store.GetResourcesAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store.Object);

        await cache.AddAsync(scope, CancellationToken.None);

        // Act
        var result = await cache.FindByNameAsync("scope-name", CancellationToken.None);

        // Assert
        Assert.Same(scope, result);
        store.Verify(store => store.FindByNameAsync("scope-name", It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByNameAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var scope = new OpenIddictScope();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictScopeStore<OpenIddictScope>>();

        store.Setup(store => store.FindByNameAsync("scope-name", It.IsAny<CancellationToken>()))
             .ReturnsAsync(scope);
        store.Setup(store => store.GetIdAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-id");
        store.Setup(store => store.GetNameAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-name");
        store.Setup(store => store.GetResourcesAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store.Object);

        // Act
        var result = await cache.FindByNameAsync("scope-name", CancellationToken.None);

        // Assert
        Assert.Same(scope, result);
        store.Verify(store => store.FindByNameAsync("scope-name", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByNamesAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var scopes = new[]
        {
            new OpenIddictScope(),
            new OpenIddictScope()
        };
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictScopeStore<OpenIddictScope>>();

        store.Setup(store => store.GetIdAsync(scopes[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-id-1");
        store.Setup(store => store.GetNameAsync(scopes[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-name-1");
        store.Setup(store => store.GetResourcesAsync(scopes[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetIdAsync(scopes[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-id-2");
        store.Setup(store => store.GetNameAsync(scopes[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-name-2");
        store.Setup(store => store.GetResourcesAsync(scopes[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.FindByNamesAsync(It.IsAny<ImmutableArray<string>>(), It.IsAny<CancellationToken>()))
             .Returns(scopes.ToAsyncEnumerable());

        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store.Object);

        // Act
        var results = await cache.FindByNamesAsync(["scope-name-1", "scope-name-2"], CancellationToken.None).ToListAsync();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(scopes[0], results);
        Assert.Contains(scopes[1], results);
    }

    [Fact]
    public async Task FindByResourceAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var scopes = new[]
        {
            new OpenIddictScope(),
            new OpenIddictScope()
        };
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictScopeStore<OpenIddictScope>>();

        store.Setup(store => store.GetIdAsync(scopes[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-id-1");
        store.Setup(store => store.GetNameAsync(scopes[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-name-1");
        store.Setup(store => store.GetResourcesAsync(scopes[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetIdAsync(scopes[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-id-2");
        store.Setup(store => store.GetNameAsync(scopes[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-name-2");
        store.Setup(store => store.GetResourcesAsync(scopes[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.FindByResourceAsync("resource", It.IsAny<CancellationToken>()))
             .Returns(scopes.ToAsyncEnumerable());

        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store.Object);

        // Act
        var results = await cache.FindByResourceAsync("resource", CancellationToken.None).ToListAsync();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(scopes[0], results);
        Assert.Contains(scopes[1], results);
        store.Verify(store => store.FindByResourceAsync("resource", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task RemoveAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictScopeStore<OpenIddictScope>>();
        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.RemoveAsync(scope: null!, CancellationToken.None).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task RemoveAsync_InvalidatesCachedEntries()
    {
        // Arrange
        var scope = new OpenIddictScope();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictScopeStore<OpenIddictScope>>();

        store.Setup(store => store.GetIdAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-id");
        store.Setup(store => store.GetNameAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-name");
        store.Setup(store => store.GetResourcesAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store.Object);

        await cache.AddAsync(scope, CancellationToken.None);

        // Act
        await cache.RemoveAsync(scope, CancellationToken.None);

        var result = await cache.FindByIdAsync("scope-id", CancellationToken.None);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task RemoveAsync_ThrowsForScopeWithoutId()
    {
        // Arrange
        var scope = new OpenIddictScope();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictScopeStore<OpenIddictScope>>();

        store.Setup(store => store.GetIdAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        var cache = new OpenIddictScopeCache<OpenIddictScope>(options, store.Object);

        // Act and assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => cache.RemoveAsync(scope, CancellationToken.None).AsTask());
    }

    public sealed class OpenIddictScope;
}
