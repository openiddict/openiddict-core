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

public class OpenIddictAuthorizationManagerTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullCache()
    {
        // Arrange
        var cache = (IOpenIddictAuthorizationCache<CustomAuthorization>) null!;
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store));

        Assert.Equal("cache", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullLogger()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = (ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>) null!;
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store));

        Assert.Equal("logger", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = (IOptionsMonitor<OpenIddictCoreOptions>) null!;
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store));

        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullStore()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = (IOpenIddictAuthorizationStore<CustomAuthorization>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store));

        Assert.Equal("store", exception.ParamName);
    }

    [Fact]
    public async Task CountAsync_CallsStoreMethod()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.CountAsync(It.IsAny<CancellationToken>()))
             .ReturnsAsync(42);

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

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
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.CountAsync<CustomAuthorization>(query: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task CreateAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.CreateAsync(authorization: null!).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task DeleteAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.DeleteAsync(authorization: null!).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task DeleteAsync_RemovesAuthorizationFromCache_WhenCachingIsEnabled()
    {
        // Arrange
        var cache = new Mock<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = false });
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();
        var authorization = new CustomAuthorization();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache.Object, logger, options, store.Object);

        // Act
        await manager.DeleteAsync(authorization);

        // Assert
        cache.Verify(cache => cache.RemoveAsync(authorization, It.IsAny<CancellationToken>()), Times.Once());
        store.Verify(store => store.DeleteAsync(authorization, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task DeleteAsync_DoesNotRemoveFromCache_WhenCachingIsDisabled()
    {
        // Arrange
        var cache = new Mock<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();
        var authorization = new CustomAuthorization();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache.Object, logger, options, store.Object);

        // Act
        await manager.DeleteAsync(authorization);

        // Assert
        cache.Verify(cache => cache.RemoveAsync(It.IsAny<CustomAuthorization>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(store => store.DeleteAsync(authorization, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindAsync_FiltersOutAuthorizationsWithNonMatchingSubject()
    {
        // Arrange
        var authorizations = new[] { new CustomAuthorization(), new CustomAuthorization() };
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.FindAsync("alice", null, null, null, null, It.IsAny<CancellationToken>()))
             .Returns(authorizations.ToAsyncEnumerable());

        store.Setup(store => store.GetSubjectAsync(authorizations[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("alice");

        store.Setup(store => store.GetSubjectAsync(authorizations[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("bob");

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var results = await manager.FindAsync("alice", null, null, null, null).ToListAsync();

        // Assert
        Assert.Single(results);
        Assert.Same(authorizations[0], results[0]);
    }

    [Fact]
    public async Task FindAsync_FiltersOutAuthorizationsWithNonMatchingScopes()
    {
        // Arrange
        var authorizations = new[] { new CustomAuthorization(), new CustomAuthorization() };
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.FindAsync(null, null, null, null, ImmutableArray.Create("openid"), It.IsAny<CancellationToken>()))
             .Returns(authorizations.ToAsyncEnumerable());

        store.Setup(store => store.GetSubjectAsync(It.IsAny<CustomAuthorization>(), It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        store.Setup(store => store.GetScopesAsync(authorizations[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync(["openid", "profile"]);

        store.Setup(store => store.GetScopesAsync(authorizations[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync(["profile"]);

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var results = await manager.FindAsync(null, null, null, null, ImmutableArray.Create("openid")).ToListAsync();

        // Assert
        Assert.Single(results);
        Assert.Same(authorizations[0], results[0]);
    }

    [Fact]
    public void FindByApplicationIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => manager.FindByApplicationIdAsync(identifier: null!));

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public void FindByApplicationIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(
            () => manager.FindByApplicationIdAsync(identifier: string.Empty));

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.FindByIdAsync(identifier: null!).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.FindByIdAsync(identifier: string.Empty).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_UsesCache_WhenCachingIsEnabled()
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = new Mock<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = false });
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        cache.Setup(cache => cache.FindByIdAsync("id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(authorization);

        store.Setup(store => store.GetIdAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync("id");

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByIdAsync("id");

        // Assert
        Assert.Same(authorization, result);
        cache.Verify(cache => cache.FindByIdAsync("id", It.IsAny<CancellationToken>()), Times.Once());
        store.Verify(store => store.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByIdAsync_UsesStore_WhenCachingIsDisabled()
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = new Mock<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.FindByIdAsync("id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(authorization);

        store.Setup(store => store.GetIdAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync("id");

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByIdAsync("id");

        // Assert
        Assert.Same(authorization, result);
        cache.Verify(cache => cache.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(store => store.FindByIdAsync("id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public void FindBySubjectAsync_ThrowsAnExceptionForNullSubject()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => manager.FindBySubjectAsync(subject: null!));

        Assert.Equal("subject", exception.ParamName);
    }

    [Fact]
    public void FindBySubjectAsync_ThrowsAnExceptionForEmptySubject()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(
            () => manager.FindBySubjectAsync(subject: string.Empty));

        Assert.Equal("subject", exception.ParamName);
    }

    [Fact]
    public async Task GetApplicationIdAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetApplicationIdAsync(authorization: null!).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task GetAsync_WithQuery_ThrowsAnExceptionForNullQuery()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetAsync<CustomAuthorization>(query: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task GetAsync_WithQueryAndState_ThrowsAnExceptionForNullQuery()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetAsync<object, CustomAuthorization>(query: null!, state: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task GetCreationDateAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetCreationDateAsync(authorization: null!).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task GetIdAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetIdAsync(authorization: null!).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task GetIdAsync_ReturnsIdentifierFromStore()
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.GetIdAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync("unique-auth-id");

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var id = await manager.GetIdAsync(authorization);

        // Assert
        Assert.Equal("unique-auth-id", id);
        store.Verify(store => store.GetIdAsync(authorization, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetPropertiesAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetPropertiesAsync(authorization: null!).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task GetScopesAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetScopesAsync(authorization: null!).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task GetStatusAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetStatusAsync(authorization: null!).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task GetSubjectAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetSubjectAsync(authorization: null!).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task GetTypeAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetTypeAsync(authorization: null!).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task HasScopesAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasScopesAsync(authorization: null!, ["scope"]).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Theory]
    [InlineData(new[] { "scope1", "scope2", "scope3" }, new[] { "scope1", "scope2" }, true)]
    [InlineData(new[] { "scope1" }, new[] { "scope1", "scope2" }, false)]
    public async Task HasScopesAsync_ReturnsExpectedResult(string[] storedScopes, string[] testedScopes, bool expected)
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.GetScopesAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync([.. storedScopes]);

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var result = await manager.HasScopesAsync(authorization, [.. testedScopes]);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public async Task HasStatusAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasStatusAsync(authorization: null!, "valid").AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task HasStatusAsync_ThrowsAnExceptionForNullStatus()
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasStatusAsync(authorization, status: null!).AsTask());

        Assert.Equal("status", exception.ParamName);
    }

    [Theory]
    [InlineData(Statuses.Valid,   Statuses.Valid,   true )]
    [InlineData(Statuses.Valid,   Statuses.Revoked, false)]
    [InlineData(Statuses.Revoked, "REVOKED",        false)]
    public async Task HasStatusAsync_ReturnsExpectedResult(string storedStatus, string testedStatus, bool expected)
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.GetStatusAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(storedStatus);

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var result = await manager.HasStatusAsync(authorization, testedStatus);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public async Task HasTypeAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasTypeAsync(authorization: null!, "permanent").AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task HasTypeAsync_ThrowsAnExceptionForNullType()
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasTypeAsync(authorization, type: null!).AsTask());

        Assert.Equal("type", exception.ParamName);
    }

    [Theory]
    [InlineData(AuthorizationTypes.Permanent, AuthorizationTypes.Permanent, true )]
    [InlineData(AuthorizationTypes.Permanent, AuthorizationTypes.AdHoc,     false)]
    [InlineData(AuthorizationTypes.Permanent, "PERMANENT",                  false)]
    public async Task HasTypeAsync_ReturnsExpectedResult(string storedType, string testedType, bool expected)
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.GetTypeAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(storedType);

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var result = await manager.HasTypeAsync(authorization, testedType);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public async Task ListAsync_ReturnsAllAuthorizations()
    {
        // Arrange
        var authorizations = new[] { new CustomAuthorization(), new CustomAuthorization() };
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()))
             .Returns(authorizations.ToAsyncEnumerable());

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var results = new List<CustomAuthorization>();
        await foreach (var auth in manager.ListAsync())
        {
            results.Add(auth);
        }

        // Assert
        Assert.Equal(2, results.Count);
        store.Verify(store => store.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task PopulateAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);
        var descriptor = new OpenIddictAuthorizationDescriptor();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.PopulateAsync(authorization: null!, descriptor).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task PopulateAsync_ThrowsAnExceptionForNullDescriptor()
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.PopulateAsync(authorization, descriptor: null!).AsTask());

        Assert.Equal("descriptor", exception.ParamName);
    }

    [Fact]
    public async Task PruneAsync_CallsStoreMethod()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
             .ReturnsAsync(42);

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var count = await manager.PruneAsync(DateTimeOffset.UtcNow);

        // Assert
        Assert.Equal(42, count);
        store.Verify(store => store.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task RevokeAsync_ReturnsZeroWhenNoAuthorizationsFound()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.FindAsync(
            It.IsAny<string?>(),
            It.IsAny<string?>(),
            It.IsAny<string?>(),
            It.IsAny<string?>(),
            It.IsAny<ImmutableArray<string>?>(),
            It.IsAny<CancellationToken>()))
             .Returns((string? subject, string? client, string? status, string? type, ImmutableArray<string>? scopes, CancellationToken cancellationToken) =>
             {
                 return Enumerable.Empty<CustomAuthorization>().ToAsyncEnumerable();
             });

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var count = await manager.RevokeAsync("subject", "client", "status", "type");

        // Assert
        Assert.Equal(0, count);
    }

    [Fact]
    public async Task RevokeByApplicationIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.RevokeByApplicationIdAsync(identifier: null!).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task RevokeByApplicationIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.RevokeByApplicationIdAsync(identifier: string.Empty).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task RevokeBySubjectAsync_ThrowsAnExceptionForNullSubject()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.RevokeBySubjectAsync(subject: null!).AsTask());

        Assert.Equal("subject", exception.ParamName);
    }

    [Fact]
    public async Task RevokeBySubjectAsync_ThrowsAnExceptionForEmptySubject()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.RevokeBySubjectAsync(subject: string.Empty).AsTask());

        Assert.Equal("subject", exception.ParamName);
    }

    [Fact]
    public async Task TryRevokeAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.TryRevokeAsync(authorization: null!).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task TryRevokeAsync_ReturnsTrueImmediatelyWhenAlreadyRevoked()
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.GetStatusAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(Statuses.Revoked);

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var result = await manager.TryRevokeAsync(authorization);

        // Assert
        Assert.True(result);
        store.Verify(store => store.SetStatusAsync(It.IsAny<CustomAuthorization>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task TryRevokeAsync_ReturnsFalseWhenStatusIsNotRevoked_CaseSensitive()
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.GetStatusAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync("REVOKED");

        store.Setup(store => store.GetIdAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync("id");

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        await manager.TryRevokeAsync(authorization);

        store.Verify(store => store.SetStatusAsync(authorization, Statuses.Revoked, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task UpdateAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.UpdateAsync(authorization: null!).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task UpdateAsync_WithDescriptor_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);
        var descriptor = new OpenIddictAuthorizationDescriptor();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.UpdateAsync(authorization: null!, descriptor).AsTask());

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public void ValidateAsync_ThrowsAnExceptionForNullAuthorization()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => manager.ValidateAsync(authorization: null!));

        Assert.Equal("authorization", exception.ParamName);
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenTypeIsEmpty()
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.GetTypeAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        store.Setup(store => store.GetStatusAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(Statuses.Valid);

        store.Setup(store => store.GetScopesAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(authorization).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2116));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenTypeIsNotSupported()
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.GetTypeAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync("unsupported-type");

        store.Setup(store => store.GetStatusAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(Statuses.Valid);

        store.Setup(store => store.GetScopesAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(authorization).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2117));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenStatusIsEmpty()
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.GetTypeAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(AuthorizationTypes.Permanent);

        store.Setup(store => store.GetStatusAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        store.Setup(store => store.GetScopesAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(authorization).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2038));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenScopeIsEmpty()
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.GetTypeAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(AuthorizationTypes.Permanent);

        store.Setup(store => store.GetStatusAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(Statuses.Valid);

        store.Setup(store => store.GetScopesAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync([string.Empty]);

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(authorization).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2039));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenScopeContainsSpace()
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.GetTypeAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(AuthorizationTypes.Permanent);

        store.Setup(store => store.GetStatusAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(Statuses.Valid);

        store.Setup(store => store.GetScopesAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["scope with space"]);

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(authorization).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2042));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsNoErrorsForValidAuthorization()
    {
        // Arrange
        var authorization = new CustomAuthorization();
        var cache = Mock.Of<IOpenIddictAuthorizationCache<CustomAuthorization>>();
        var logger = Mock.Of<ILogger<OpenIddictAuthorizationManager<CustomAuthorization>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictAuthorizationStore<CustomAuthorization>>();

        store.Setup(store => store.GetTypeAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(AuthorizationTypes.Permanent);

        store.Setup(store => store.GetStatusAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(Statuses.Valid);

        store.Setup(store => store.GetScopesAsync(authorization, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["openid", "profile"]);

        var manager = new OpenIddictAuthorizationManager<CustomAuthorization>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(authorization).ToListAsync();

        // Assert
        Assert.DoesNotContain(results, static result => result != ValidationResult.Success);
    }

    public class CustomAuthorization { }
}
