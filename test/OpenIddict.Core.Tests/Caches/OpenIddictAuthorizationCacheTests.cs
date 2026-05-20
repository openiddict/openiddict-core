/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace OpenIddict.Core.Tests;

public class OpenIddictAuthorizationCacheTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var options = (IOptionsMonitor<OpenIddictCoreOptions>) null!;
        var store = Mock.Of<IOpenIddictAuthorizationStore<object>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictAuthorizationCache<object>(options, store));

        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullStore()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = (IOpenIddictAuthorizationStore<object>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictAuthorizationCache<object>(options, store));

        Assert.Equal("store", exception.ParamName);
    }

    [Fact]
    public async Task AddAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictAuthorizationStore<OpenIddictAuthorization>>();
        var cache = new OpenIddictAuthorizationCache<OpenIddictAuthorization>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.AddAsync(authorization: null!, CancellationToken.None).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictAuthorizationStore<OpenIddictAuthorization>>();
        var cache = new OpenIddictAuthorizationCache<OpenIddictAuthorization>(options, store);

        // Act and assert
        cache.Dispose();
        cache.Dispose();
    }

    [Fact]
    public async Task FindByApplicationIdAsync_ReturnsCachedAuthorizationsOnCacheHit()
    {
        // Arrange
        var authorizations = new[]
        {
            new OpenIddictAuthorization(),
            new OpenIddictAuthorization()
        };
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<OpenIddictAuthorization>>();

        store.Setup(store => store.GetIdAsync(authorizations[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("authorization-id-1");
        store.Setup(store => store.GetApplicationIdAsync(authorizations[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");
        store.Setup(store => store.GetSubjectAsync(authorizations[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("subject-1");

        store.Setup(store => store.GetIdAsync(authorizations[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("authorization-id-2");
        store.Setup(store => store.GetApplicationIdAsync(authorizations[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");
        store.Setup(store => store.GetSubjectAsync(authorizations[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("subject-2");

        store.Setup(store => store.FindByApplicationIdAsync("application-id", It.IsAny<CancellationToken>()))
             .Returns(authorizations.ToAsyncEnumerable());

        var cache = new OpenIddictAuthorizationCache<OpenIddictAuthorization>(options, store.Object);
        await cache.FindByApplicationIdAsync("application-id", CancellationToken.None).ToListAsync();

        // Act
        var results = await cache.FindByApplicationIdAsync("application-id", CancellationToken.None).ToListAsync();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(authorizations[0], results);
        Assert.Contains(authorizations[1], results);
        store.Verify(store => store.FindByApplicationIdAsync("application-id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictAuthorizationStore<OpenIddictAuthorization>>();
        var cache = new OpenIddictAuthorizationCache<OpenIddictAuthorization>(options, store);

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
        var store = Mock.Of<IOpenIddictAuthorizationStore<OpenIddictAuthorization>>();
        var cache = new OpenIddictAuthorizationCache<OpenIddictAuthorization>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => cache.FindByIdAsync(identifier: string.Empty, CancellationToken.None).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsCachedAuthorizationOnCacheHit()
    {
        // Arrange
        var authorization = new OpenIddictAuthorization();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<OpenIddictAuthorization>>();

        store.Setup(store => store.GetIdAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync("authorization-id");
        store.Setup(store => store.GetApplicationIdAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");
        store.Setup(store => store.GetSubjectAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync("subject");

        var cache = new OpenIddictAuthorizationCache<OpenIddictAuthorization>(options, store.Object);

        await cache.AddAsync(authorization, CancellationToken.None);

        // Act
        var result = await cache.FindByIdAsync("authorization-id", CancellationToken.None);

        // Assert
        Assert.Same(authorization, result);
        store.Verify(store => store.FindByIdAsync("authorization-id", It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByIdAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var authorization = new OpenIddictAuthorization();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<OpenIddictAuthorization>>();

        store.Setup(store => store.FindByIdAsync("authorization-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(authorization);
        store.Setup(store => store.GetIdAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync("authorization-id");
        store.Setup(store => store.GetApplicationIdAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");
        store.Setup(store => store.GetSubjectAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync("subject");

        var cache = new OpenIddictAuthorizationCache<OpenIddictAuthorization>(options, store.Object);

        // Act
        var result = await cache.FindByIdAsync("authorization-id", CancellationToken.None);

        // Assert
        Assert.Same(authorization, result);
        store.Verify(store => store.FindByIdAsync("authorization-id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsNullWhenAuthorizationNotFound()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<OpenIddictAuthorization>>();

        store.Setup(store => store.FindByIdAsync("authorization-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync((OpenIddictAuthorization?) null);

        var cache = new OpenIddictAuthorizationCache<OpenIddictAuthorization>(options, store.Object);

        // Act
        var result = await cache.FindByIdAsync("authorization-id", CancellationToken.None);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task FindBySubjectAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var authorizations = new[]
        {
            new OpenIddictAuthorization(),
            new OpenIddictAuthorization()
        };
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<OpenIddictAuthorization>>();

        store.Setup(store => store.GetIdAsync(authorizations[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("authorization-id-1");
        store.Setup(store => store.GetApplicationIdAsync(authorizations[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id-1");
        store.Setup(store => store.GetSubjectAsync(authorizations[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("subject");

        store.Setup(store => store.GetIdAsync(authorizations[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("authorization-id-2");
        store.Setup(store => store.GetApplicationIdAsync(authorizations[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id-2");
        store.Setup(store => store.GetSubjectAsync(authorizations[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("subject");

        store.Setup(store => store.FindBySubjectAsync("subject", It.IsAny<CancellationToken>()))
             .Returns(authorizations.ToAsyncEnumerable());

        var cache = new OpenIddictAuthorizationCache<OpenIddictAuthorization>(options, store.Object);

        // Act
        var results = await cache.FindBySubjectAsync("subject", CancellationToken.None).ToListAsync();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(authorizations[0], results);
        Assert.Contains(authorizations[1], results);
        store.Verify(store => store.FindBySubjectAsync("subject", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task RemoveAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictAuthorizationStore<OpenIddictAuthorization>>();
        var cache = new OpenIddictAuthorizationCache<OpenIddictAuthorization>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.RemoveAsync(authorization: null!, CancellationToken.None).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task RemoveAsync_InvalidatesCachedEntries()
    {
        // Arrange
        var authorization = new OpenIddictAuthorization();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<OpenIddictAuthorization>>();

        store.Setup(store => store.GetIdAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync("authorization-id");
        store.Setup(store => store.GetApplicationIdAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");
        store.Setup(store => store.GetSubjectAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync("subject");

        var cache = new OpenIddictAuthorizationCache<OpenIddictAuthorization>(options, store.Object);

        await cache.AddAsync(authorization, CancellationToken.None);

        // Act
        await cache.RemoveAsync(authorization, CancellationToken.None);

        var result = await cache.FindByIdAsync("authorization-id", CancellationToken.None);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task RemoveAsync_ThrowsForAuthorizationWithoutId()
    {
        // Arrange
        var authorization = new OpenIddictAuthorization();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<OpenIddictAuthorization>>();

        store.Setup(store => store.GetIdAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        var cache = new OpenIddictAuthorizationCache<OpenIddictAuthorization>(options, store.Object);

        // Act and assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => cache.RemoveAsync(authorization, CancellationToken.None).AsTask());
    }

    public sealed class OpenIddictAuthorization { }
}
