/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace OpenIddict.Core.Tests;

public class OpenIddictTokenManagerTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullCache()
    {
        // Arrange
        var cache = (IOpenIddictTokenCache<CustomToken>) null!;
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictTokenManager<CustomToken>(cache, logger, options, store));

        Assert.Equal("cache", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullLogger()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = (ILogger<OpenIddictTokenManager<CustomToken>>) null!;
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictTokenManager<CustomToken>(cache, logger, options, store));

        Assert.Equal("logger", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = (IOptionsMonitor<OpenIddictCoreOptions>) null!;
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictTokenManager<CustomToken>(cache, logger, options, store));

        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullStore()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = (IOpenIddictTokenStore<CustomToken>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictTokenManager<CustomToken>(cache, logger, options, store));

        Assert.Equal("store", exception.ParamName);
    }

    [Fact]
    public async Task CountAsync_CallsStoreMethod()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();

        store.Setup(store => store.CountAsync(It.IsAny<CancellationToken>()))
             .ReturnsAsync(42);

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store.Object);

        // Act
        var count = await manager.CountAsync();

        // Assert
        Assert.Equal(42, count);
        store.Verify(store => store.CountAsync(It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task CountAsync_WithQuery_ThrowsAnExceptionForNullQuery()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.CountAsync<CustomToken>(query: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task CreateAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.CreateAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task DeleteAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.DeleteAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task DeleteAsync_RemovesTokenFromCache_WhenCachingIsEnabled()
    {
        // Arrange
        var cache = new Mock<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = false });
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();
        var token = new CustomToken();

        var manager = new OpenIddictTokenManager<CustomToken>(cache.Object, logger, options, store.Object);

        // Act
        await manager.DeleteAsync(token);

        // Assert
        cache.Verify(cache => cache.RemoveAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        store.Verify(store => store.DeleteAsync(token, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task DeleteAsync_DoesNotRemoveFromCache_WhenCachingIsDisabled()
    {
        // Arrange
        var cache = new Mock<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();
        var token = new CustomToken();

        var manager = new OpenIddictTokenManager<CustomToken>(cache.Object, logger, options, store.Object);

        // Act
        await manager.DeleteAsync(token);

        // Assert
        cache.Verify(cache => cache.RemoveAsync(It.IsAny<CustomToken>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(store => store.DeleteAsync(token, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public void FindByApplicationIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => manager.FindByApplicationIdAsync(identifier: null!));

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public void FindByApplicationIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(
            () => manager.FindByApplicationIdAsync(identifier: string.Empty));

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public void FindByAuthorizationIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => manager.FindByAuthorizationIdAsync(identifier: null!));

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public void FindByAuthorizationIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(
            () => manager.FindByAuthorizationIdAsync(identifier: string.Empty));

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.FindByIdAsync(identifier: null!).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.FindByIdAsync(identifier: string.Empty).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_UsesCache_WhenCachingIsEnabled()
    {
        // Arrange
        var token = new CustomToken();
        var cache = new Mock<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = false });
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();

        cache.Setup(cache => cache.FindByIdAsync("id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(token);

        store.Setup(store => store.GetIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync("id");

        var manager = new OpenIddictTokenManager<CustomToken>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByIdAsync("id");

        // Assert
        Assert.Same(token, result);
        cache.Verify(cache => cache.FindByIdAsync("id", It.IsAny<CancellationToken>()), Times.Once());
        store.Verify(store => store.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByIdAsync_UsesStore_WhenCachingIsDisabled()
    {
        // Arrange
        var token = new CustomToken();
        var cache = new Mock<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();

        store.Setup(store => store.FindByIdAsync("id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(token);

        store.Setup(store => store.GetIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync("id");

        var manager = new OpenIddictTokenManager<CustomToken>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByIdAsync("id");

        // Assert
        Assert.Same(token, result);
        cache.Verify(cache => cache.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(store => store.FindByIdAsync("id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByReferenceIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.FindByReferenceIdAsync(identifier: null!).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByReferenceIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.FindByReferenceIdAsync(identifier: string.Empty).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public void FindBySubjectAsync_ThrowsAnExceptionForNullSubject()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => manager.FindBySubjectAsync(subject: null!));

        Assert.Equal("subject", exception.ParamName);
    }

    [Fact]
    public void FindBySubjectAsync_ThrowsAnExceptionForEmptySubject()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(
            () => manager.FindBySubjectAsync(subject: string.Empty));

        Assert.Equal("subject", exception.ParamName);
    }

    [Fact]
    public async Task GetApplicationIdAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetApplicationIdAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task GetAsync_WithQuery_ThrowsAnExceptionForNullQuery()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetAsync<CustomToken>(query: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task GetAsync_WithQueryAndState_ThrowsAnExceptionForNullQuery()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetAsync<object, CustomToken>(query: null!, state: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task GetAuthorizationIdAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetAuthorizationIdAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task GetCreationDateAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetCreationDateAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task GetExpirationDateAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetExpirationDateAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task GetIdAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetIdAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task GetIdAsync_ReturnsIdentifierFromStore()
    {
        // Arrange
        var token = new CustomToken();
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();

        store.Setup(store => store.GetIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync("unique-token-id");

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store.Object);

        // Act
        var id = await manager.GetIdAsync(token);

        // Assert
        Assert.Equal("unique-token-id", id);
        store.Verify(store => store.GetIdAsync(token, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetPayloadAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetPayloadAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task GetPropertiesAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetPropertiesAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task GetRedemptionDateAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetRedemptionDateAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task GetReferenceIdAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetReferenceIdAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task GetStatusAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetStatusAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task GetSubjectAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetSubjectAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task GetTypeAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetTypeAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task HasStatusAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasStatusAsync(token: null!, "valid").AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task HasStatusAsync_ThrowsAnExceptionForNullStatus()
    {
        // Arrange
        var token = new CustomToken();
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasStatusAsync(token, status: null!).AsTask());

        Assert.Equal("status", exception.ParamName);
    }

    [Theory]
    [InlineData(Statuses.Valid,   Statuses.Valid,   true )]
    [InlineData(Statuses.Valid,   Statuses.Revoked, false)]
    [InlineData(Statuses.Revoked, "REVOKED",        false)]
    public async Task HasStatusAsync_ReturnsExpectedResult(string storedStatus, string testedStatus, bool expected)
    {
        // Arrange
        var token = new CustomToken();
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();

        store.Setup(store => store.GetStatusAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync(storedStatus);

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store.Object);

        // Act
        var result = await manager.HasStatusAsync(token, testedStatus);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public async Task HasTypeAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasTypeAsync(token: null!, "type").AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task HasTypeAsync_ThrowsAnExceptionForEmptyType()
    {
        // Arrange
        var token = new CustomToken();
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.HasTypeAsync(token, type: string.Empty).AsTask());

        Assert.Equal("type", exception.ParamName);
    }

    [Theory]
    [InlineData(TokenTypeHints.AccessToken,  TokenTypeIdentifiers.AccessToken,  true )]
    [InlineData(TokenTypeHints.AccessToken,  TokenTypeIdentifiers.RefreshToken, false)]
    [InlineData(TokenTypeHints.AccessToken,  "urn:ietf:params:oauth:token-type:ACCESS_TOKEN", false)]
    public async Task HasTypeAsync_ReturnsExpectedResult(string storedType, string testedType, bool expected)
    {
        // Arrange
        var token = new CustomToken();
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();

        store.Setup(store => store.GetTypeAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync(storedType);

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store.Object);

        // Act
        var result = await manager.HasTypeAsync(token, testedType);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public async Task HasTypeAsync_WithArray_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasTypeAsync(token: null!, ImmutableArray.Create(TokenTypeHints.AccessToken)).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Theory]
    [InlineData(null, new[] { TokenTypeHints.AccessToken }, false)]
    [InlineData(TokenTypeHints.RefreshToken, new[] { TokenTypeIdentifiers.AccessToken, TokenTypeIdentifiers.RefreshToken }, true )]
    [InlineData("authorization_code", new[] { TokenTypeIdentifiers.AccessToken, TokenTypeIdentifiers.RefreshToken }, false)]
    [InlineData(TokenTypeHints.AccessToken, new[] { "ACCESS_TOKEN" }, false)]
    public async Task HasTypeAsync_WithArray_ReturnsExpectedResult(string? type, string[] types, bool expected)
    {
        // Arrange
        var token = new CustomToken();
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();

        store.Setup(store => store.GetTypeAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync(type);

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store.Object);

        // Act
        var result = await manager.HasTypeAsync(token, [.. types]);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public async Task ListAsync_ReturnsAllTokens()
    {
        // Arrange
        var tokens = new[] { new CustomToken(), new CustomToken() };
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();

        store.Setup(store => store.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()))
             .Returns(tokens.ToAsyncEnumerable());

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store.Object);

        // Act
        var results = new List<CustomToken>();
        await foreach (var tkn in manager.ListAsync())
        {
            results.Add(tkn);
        }

        // Assert
        Assert.Equal(2, results.Count);
        store.Verify(store => store.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task PopulateAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);
        var descriptor = new OpenIddictTokenDescriptor();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.PopulateAsync(token: null!, descriptor).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task PopulateAsync_ThrowsAnExceptionForNullDescriptor()
    {
        // Arrange
        var token = new CustomToken();
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.PopulateAsync(token, descriptor: null!).AsTask());

        Assert.Equal("descriptor", exception.ParamName);
    }

    [Fact]
    public async Task PruneAsync_CallsStoreMethod()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();

        store.Setup(store => store.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
             .ReturnsAsync(42);

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store.Object);

        // Act
        var count = await manager.PruneAsync(DateTimeOffset.UtcNow);

        // Assert
        Assert.Equal(42, count);
        store.Verify(store => store.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task RevokeAsync_CallsStoreMethod()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();

        store.Setup(store => store.RevokeAsync("alice", "client-id", Statuses.Valid, TokenTypeHints.AccessToken, It.IsAny<CancellationToken>()))
             .ReturnsAsync(5);

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store.Object);

        // Act
        var count = await manager.RevokeAsync("alice", "client-id", Statuses.Valid, TokenTypeHints.AccessToken);

        // Assert
        Assert.Equal(5, count);
        store.Verify(store => store.RevokeAsync("alice", "client-id", Statuses.Valid, TokenTypeHints.AccessToken, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task RevokeByApplicationIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.RevokeByApplicationIdAsync(identifier: null!).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task RevokeByApplicationIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.RevokeByApplicationIdAsync(identifier: string.Empty).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task RevokeByAuthorizationIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.RevokeByAuthorizationIdAsync(identifier: null!).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task RevokeByAuthorizationIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.RevokeByAuthorizationIdAsync(identifier: string.Empty).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task RevokeBySubjectAsync_ThrowsAnExceptionForNullSubject()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.RevokeBySubjectAsync(subject: null!).AsTask());

        Assert.Equal("subject", exception.ParamName);
    }

    [Fact]
    public async Task RevokeBySubjectAsync_ThrowsAnExceptionForEmptySubject()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.RevokeBySubjectAsync(subject: string.Empty).AsTask());

        Assert.Equal("subject", exception.ParamName);
    }

    [Fact]
    public async Task TryRedeemAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.TryRedeemAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task TryRejectAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.TryRejectAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task TryRevokeAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.TryRevokeAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task UpdateAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.UpdateAsync(token: null!).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task UpdateAsync_WithDescriptor_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);
        var descriptor = new OpenIddictTokenDescriptor();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.UpdateAsync(token: null!, descriptor).AsTask());

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public void ValidateAsync_ThrowsAnExceptionForNullToken()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictTokenStore<CustomToken>>();

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => manager.ValidateAsync(token: null!));

        Assert.Equal("token", exception.ParamName);
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenReferenceIdIsAlreadyUsed()
    {
        // Arrange
        var token = new CustomToken();
        var other = new CustomToken();
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();

        store.Setup(store => store.GetReferenceIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync("reference-id");

        store.Setup(store => store.FindByReferenceIdAsync("reference-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(other);

        store.Setup(store => store.GetIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync("token-id");

        store.Setup(store => store.GetIdAsync(other, It.IsAny<CancellationToken>()))
             .ReturnsAsync("other-token-id");

        store.Setup(store => store.GetTypeAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync(TokenTypeHints.AccessToken);

        store.Setup(store => store.GetStatusAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync(Statuses.Valid);

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(token).ToListAsync();

        // Assert
        Assert.Contains(results, result => string.Equals(result.ErrorMessage, SR.GetResourceString(SR.ID2085), StringComparison.Ordinal));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenTypeIsEmpty()
    {
        // Arrange
        var token = new CustomToken();
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();

        store.Setup(store => store.GetReferenceIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        store.Setup(store => store.GetTypeAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        store.Setup(store => store.GetStatusAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync(Statuses.Valid);

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(token).ToListAsync();

        // Assert
        Assert.Contains(results, result => string.Equals(result.ErrorMessage, SR.GetResourceString(SR.ID2086), StringComparison.Ordinal));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenStatusIsEmpty()
    {
        // Arrange
        var token = new CustomToken();
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();

        store.Setup(store => store.GetReferenceIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        store.Setup(store => store.GetTypeAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync(TokenTypeHints.AccessToken);

        store.Setup(store => store.GetStatusAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(token).ToListAsync();

        // Assert
        Assert.Contains(results, result => string.Equals(result.ErrorMessage, SR.GetResourceString(SR.ID2038), StringComparison.Ordinal));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsNoErrorsForValidToken()
    {
        // Arrange
        var token = new CustomToken();
        var cache = Mock.Of<IOpenIddictTokenCache<CustomToken>>();
        var logger = Mock.Of<ILogger<OpenIddictTokenManager<CustomToken>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictTokenStore<CustomToken>>();

        store.Setup(store => store.GetReferenceIdAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        store.Setup(store => store.GetTypeAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync(TokenTypeHints.AccessToken);

        store.Setup(store => store.GetStatusAsync(token, It.IsAny<CancellationToken>()))
             .ReturnsAsync(Statuses.Valid);

        var manager = new OpenIddictTokenManager<CustomToken>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(token).ToListAsync();

        // Assert
        Assert.DoesNotContain(results, static result => result != ValidationResult.Success);
    }

    public class CustomToken;
}
