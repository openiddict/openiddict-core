/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace OpenIddict.Core.Tests;

public class OpenIddictTokenCacheTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var options = (IOptionsMonitor<OpenIddictCoreOptions>) null!;
        var store = Mock.Of<IOpenIddictTokenStore<object>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictTokenCache<object>(options, store));

        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullStore()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = (IOpenIddictTokenStore<object>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictTokenCache<object>(options, store));

        Assert.Equal("store", exception.ParamName);
    }

    [Fact]
    public async Task AddAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictTokenStore<OpenIddictToken>>();
        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.AddAsync(token: null!, CancellationToken.None).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictTokenStore<OpenIddictToken>>();
        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store);

        // Act and assert
        cache.Dispose();
        cache.Dispose();
    }

    [Fact]
    public async Task FindByApplicationIdAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var tokens = new[]
        {
            new OpenIddictToken(),
            new OpenIddictToken()
        };
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<OpenIddictToken>>();

        store.Setup(store => store.GetIdAsync(tokens[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("token-id-1");
        store.Setup(store => store.GetReferenceIdAsync(tokens[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetApplicationIdAsync(tokens[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");
        store.Setup(store => store.GetAuthorizationIdAsync(tokens[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetSubjectAsync(tokens[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        store.Setup(store => store.GetIdAsync(tokens[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("token-id-2");
        store.Setup(store => store.GetReferenceIdAsync(tokens[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetApplicationIdAsync(tokens[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");
        store.Setup(store => store.GetAuthorizationIdAsync(tokens[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetSubjectAsync(tokens[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        store.Setup(store => store.FindByApplicationIdAsync("application-id", It.IsAny<CancellationToken>()))
             .Returns(tokens.ToAsyncEnumerable());

        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store.Object);

        // Act
        var results = await cache.FindByApplicationIdAsync("application-id", CancellationToken.None).ToListAsync();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(tokens[0], results);
        Assert.Contains(tokens[1], results);
        store.Verify(store => store.FindByApplicationIdAsync("application-id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByAuthorizationIdAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var tokens = new[]
        {
            new OpenIddictToken(),
            new OpenIddictToken()
        };
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<OpenIddictToken>>();

        store.Setup(store => store.GetIdAsync(tokens[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("token-id-1");
        store.Setup(store => store.GetReferenceIdAsync(tokens[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetApplicationIdAsync(tokens[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetAuthorizationIdAsync(tokens[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("authorization-id");
        store.Setup(store => store.GetSubjectAsync(tokens[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        store.Setup(store => store.GetIdAsync(tokens[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("token-id-2");
        store.Setup(store => store.GetReferenceIdAsync(tokens[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetApplicationIdAsync(tokens[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetAuthorizationIdAsync(tokens[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("authorization-id");
        store.Setup(store => store.GetSubjectAsync(tokens[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        store.Setup(store => store.FindByAuthorizationIdAsync("authorization-id", It.IsAny<CancellationToken>()))
             .Returns(tokens.ToAsyncEnumerable());

        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store.Object);

        // Act
        var results = await cache.FindByAuthorizationIdAsync("authorization-id", CancellationToken.None).ToListAsync();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(tokens[0], results);
        Assert.Contains(tokens[1], results);
        store.Verify(store => store.FindByAuthorizationIdAsync("authorization-id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictTokenStore<OpenIddictToken>>();
        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store);

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
        var store = Mock.Of<IOpenIddictTokenStore<OpenIddictToken>>();
        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => cache.FindByIdAsync(identifier: string.Empty, CancellationToken.None).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsCachedTokenOnCacheHit()
    {
        // Arrange
        var token = new OpenIddictToken();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<OpenIddictToken>>();

        store.Setup(store => store.GetIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync("token-id");
        store.Setup(store => store.GetReferenceIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetApplicationIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetSubjectAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store.Object);

        await cache.AddAsync(token, CancellationToken.None);

        // Act
        var result = await cache.FindByIdAsync("token-id", CancellationToken.None);

        // Assert
        Assert.Same(token, result);
        store.Verify(store => store.FindByIdAsync("token-id", It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByIdAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var token = new OpenIddictToken();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<OpenIddictToken>>();

        store.Setup(store => store.FindByIdAsync("token-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(token);
        store.Setup(store => store.GetIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync("token-id");
        store.Setup(store => store.GetReferenceIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetApplicationIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetSubjectAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store.Object);

        // Act
        var result = await cache.FindByIdAsync("token-id", CancellationToken.None);

        // Assert
        Assert.Same(token, result);
        store.Verify(store => store.FindByIdAsync("token-id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsNullWhenTokenNotFound()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<OpenIddictToken>>();

        store.Setup(store => store.FindByIdAsync("token-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync((OpenIddictToken?) null);

        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store.Object);

        // Act
        var result = await cache.FindByIdAsync("token-id", CancellationToken.None);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task FindByReferenceIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictTokenStore<OpenIddictToken>>();
        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.FindByReferenceIdAsync(identifier: null!, CancellationToken.None).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByReferenceIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictTokenStore<OpenIddictToken>>();
        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => cache.FindByReferenceIdAsync(identifier: string.Empty, CancellationToken.None).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByReferenceIdAsync_ReturnsCachedTokenOnCacheHit()
    {
        // Arrange
        var token = new OpenIddictToken();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<OpenIddictToken>>();

        store.Setup(store => store.GetIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync("token-id");
        store.Setup(store => store.GetReferenceIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync("reference-id");
        store.Setup(store => store.GetApplicationIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetSubjectAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store.Object);

        await cache.AddAsync(token, CancellationToken.None);

        // Act
        var result = await cache.FindByReferenceIdAsync("reference-id", CancellationToken.None);

        // Assert
        Assert.Same(token, result);
        store.Verify(store => store.FindByReferenceIdAsync("reference-id", It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByReferenceIdAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var token = new OpenIddictToken();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<OpenIddictToken>>();

        store.Setup(store => store.FindByReferenceIdAsync("reference-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(token);
        store.Setup(store => store.GetIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync("token-id");
        store.Setup(store => store.GetReferenceIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync("reference-id");
        store.Setup(store => store.GetApplicationIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetSubjectAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store.Object);

        // Act
        var result = await cache.FindByReferenceIdAsync("reference-id", CancellationToken.None);

        // Assert
        Assert.Same(token, result);
        store.Verify(store => store.FindByReferenceIdAsync("reference-id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindBySubjectAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var tokens = new[]
        {
            new OpenIddictToken(),
            new OpenIddictToken()
        };
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<OpenIddictToken>>();

        store.Setup(store => store.GetIdAsync(tokens[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("token-id-1");
        store.Setup(store => store.GetReferenceIdAsync(tokens[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetApplicationIdAsync(tokens[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetAuthorizationIdAsync(tokens[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetSubjectAsync(tokens[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("subject");

        store.Setup(store => store.GetIdAsync(tokens[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("token-id-2");
        store.Setup(store => store.GetReferenceIdAsync(tokens[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetApplicationIdAsync(tokens[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetAuthorizationIdAsync(tokens[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetSubjectAsync(tokens[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("subject");

        store.Setup(store => store.FindBySubjectAsync("subject", It.IsAny<CancellationToken>()))
             .Returns(tokens.ToAsyncEnumerable());

        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store.Object);

        // Act
        var results = await cache.FindBySubjectAsync("subject", CancellationToken.None).ToListAsync();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(tokens[0], results);
        Assert.Contains(tokens[1], results);
        store.Verify(store => store.FindBySubjectAsync("subject", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task RemoveAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictTokenStore<OpenIddictToken>>();
        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.RemoveAsync(token: null!, CancellationToken.None).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task RemoveAsync_InvalidatesCachedEntries()
    {
        // Arrange
        var token = new OpenIddictToken();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<OpenIddictToken>>();

        store.Setup(store => store.GetIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync("token-id");
        store.Setup(store => store.GetReferenceIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetApplicationIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetSubjectAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store.Object);

        await cache.AddAsync(token, CancellationToken.None);

        // Act
        await cache.RemoveAsync(token, CancellationToken.None);

        var result = await cache.FindByIdAsync("token-id", CancellationToken.None);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task RemoveAsync_ThrowsForTokenWithoutId()
    {
        // Arrange
        var token = new OpenIddictToken();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<OpenIddictToken>>();

        store.Setup(store => store.GetIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        var cache = new OpenIddictTokenCache<OpenIddictToken>(options, store.Object);

        // Act and assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => cache.RemoveAsync(token, CancellationToken.None).AsTask());
    }

    public sealed class OpenIddictToken;
}
