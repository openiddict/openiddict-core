/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Binary;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;

namespace OpenIddict.Core.Tests;

public class OpenIddictApplicationManagerTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullCache()
    {
        // Arrange
        var cache = (IOpenIddictApplicationCache<CustomApplication>) null!;
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store));

        Assert.Equal("cache", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullLogger()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = (ILogger<OpenIddictApplicationManager<CustomApplication>>) null!;
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store));

        Assert.Equal("logger", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = (IOptionsMonitor<OpenIddictCoreOptions>) null!;
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store));

        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullStore()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = (IOpenIddictApplicationStore<CustomApplication>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store));

        Assert.Equal("store", exception.ParamName);
    }

    [Fact]
    public async Task CountAsync_CallsStoreMethod()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.CountAsync(It.IsAny<CancellationToken>()))
             .ReturnsAsync(42);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

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
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.CountAsync<CustomApplication>(query: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task CreateAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.CreateAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task CreateAsync_WithSecret_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.CreateAsync(application: null!, secret: "secret").AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task CreateAsync_WithDescriptor_ThrowsAnExceptionForNullDescriptor()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.CreateAsync(descriptor: null!).AsTask());

        Assert.Equal("descriptor", exception.ParamName);
    }

    [Fact]
    public async Task DeleteAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.DeleteAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task DeleteAsync_RemovesApplicationFromCache_WhenCachingIsEnabled()
    {
        // Arrange
        var cache = new Mock<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = false });
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();
        var application = new CustomApplication();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache.Object, logger, options, store.Object);

        // Act
        await manager.DeleteAsync(application);

        // Assert
        cache.Verify(cache => cache.RemoveAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        store.Verify(store => store.DeleteAsync(application, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task DeleteAsync_DoesNotRemoveFromCache_WhenCachingIsDisabled()
    {
        // Arrange
        var cache = new Mock<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();
        var application = new CustomApplication();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache.Object, logger, options, store.Object);

        // Act
        await manager.DeleteAsync(application);

        // Assert
        cache.Verify(cache => cache.RemoveAsync(It.IsAny<CustomApplication>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(store => store.DeleteAsync(application, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByClientIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.FindByClientIdAsync(identifier: null!).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByClientIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.FindByClientIdAsync(identifier: string.Empty).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByClientIdAsync_UsesCache_WhenCachingIsEnabled()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = new Mock<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = false });
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        cache.Setup(cache => cache.FindByClientIdAsync("client_id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(application);

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client_id");

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByClientIdAsync("client_id");

        // Assert
        Assert.Same(application, result);
        cache.Verify(cache => cache.FindByClientIdAsync("client_id", It.IsAny<CancellationToken>()), Times.Once());
        store.Verify(store => store.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByClientIdAsync_UsesStore_WhenCachingIsDisabled()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = new Mock<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.FindByClientIdAsync("client_id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(application);

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client_id");

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByClientIdAsync("client_id");

        // Assert
        Assert.Same(application, result);
        cache.Verify(cache => cache.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(store => store.FindByClientIdAsync("client_id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.FindByIdAsync(identifier: null!).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.FindByIdAsync(identifier: string.Empty).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_UsesCache_WhenCachingIsEnabled()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = new Mock<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = false });
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        cache.Setup(cache => cache.FindByIdAsync("id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(application);

        store.Setup(store => store.GetIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("id");

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByIdAsync("id");

        // Assert
        Assert.Same(application, result);
        cache.Verify(cache => cache.FindByIdAsync("id", It.IsAny<CancellationToken>()), Times.Once());
        store.Verify(store => store.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByIdAsync_UsesStore_WhenCachingIsDisabled()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = new Mock<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.FindByIdAsync("id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(application);

        store.Setup(store => store.GetIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("id");

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByIdAsync("id");

        // Assert
        Assert.Same(application, result);
        cache.Verify(cache => cache.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(store => store.FindByIdAsync("id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public void FindByPostLogoutRedirectUriAsync_ThrowsAnExceptionForNullUri()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            manager.FindByPostLogoutRedirectUriAsync(uri: null!));

        Assert.Equal("uri", exception.ParamName);
    }

    [Fact]
    public void FindByPostLogoutRedirectUriAsync_ThrowsAnExceptionForEmptyUri()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() =>
            manager.FindByPostLogoutRedirectUriAsync(uri: string.Empty));

        Assert.Equal("uri", exception.ParamName);
    }

    [Fact]
    public async Task FindByPostLogoutRedirectUriAsync_UsesCache_WhenCachingIsEnabled()
    {
        // Arrange
        var applications = new[] { new CustomApplication() };
        var cache = new Mock<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = false });
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        cache.Setup(cache => cache.FindByPostLogoutRedirectUriAsync("https://www.fabrikam.com/callback/logout", It.IsAny<CancellationToken>()))
             .Returns(applications.ToAsyncEnumerable());

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(applications[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://www.fabrikam.com/callback/logout"]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByPostLogoutRedirectUriAsync("https://www.fabrikam.com/callback/logout").ToListAsync();

        // Assert
        Assert.Same(applications[0], result[0]);
        cache.Verify(cache => cache.FindByPostLogoutRedirectUriAsync("https://www.fabrikam.com/callback/logout", It.IsAny<CancellationToken>()), Times.Once());
        store.Verify(store => store.FindByPostLogoutRedirectUriAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByPostLogoutRedirectUriAsync_UsesStore_WhenCachingIsDisabled()
    {
        // Arrange
        var applications = new[] { new CustomApplication() };
        var cache = new Mock<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.FindByPostLogoutRedirectUriAsync("https://www.fabrikam.com/callback/logout", It.IsAny<CancellationToken>()))
             .Returns(applications.ToAsyncEnumerable());

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(applications[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://www.fabrikam.com/callback/logout"]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByPostLogoutRedirectUriAsync("https://www.fabrikam.com/callback/logout").ToListAsync();

        // Assert
        Assert.Same(applications[0], result[0]);
        cache.Verify(cache => cache.FindByPostLogoutRedirectUriAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(store => store.FindByPostLogoutRedirectUriAsync("https://www.fabrikam.com/callback/logout", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public void FindByRedirectUriAsync_ThrowsAnExceptionForNullUri()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            manager.FindByRedirectUriAsync(uri: null!));

        Assert.Equal("uri", exception.ParamName);
    }

    [Fact]
    public void FindByRedirectUriAsync_ThrowsAnExceptionForEmptyUri()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() =>
            manager.FindByRedirectUriAsync(uri: string.Empty));

        Assert.Equal("uri", exception.ParamName);
    }

    [Fact]
    public async Task FindByRedirectUriAsync_UsesCache_WhenCachingIsEnabled()
    {
        // Arrange
        var applications = new[] { new CustomApplication() };
        var cache = new Mock<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = false });
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        cache.Setup(cache => cache.FindByRedirectUriAsync("https://www.fabrikam.com/callback", It.IsAny<CancellationToken>()))
             .Returns(applications.ToAsyncEnumerable());

        store.Setup(store => store.GetRedirectUrisAsync(applications[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://www.fabrikam.com/callback"]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByRedirectUriAsync("https://www.fabrikam.com/callback").ToListAsync();

        // Assert
        Assert.Same(applications[0], result[0]);
        cache.Verify(cache => cache.FindByRedirectUriAsync("https://www.fabrikam.com/callback", It.IsAny<CancellationToken>()), Times.Once());
        store.Verify(store => store.FindByRedirectUriAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByRedirectUriAsync_UsesStore_WhenCachingIsDisabled()
    {
        // Arrange
        var applications = new[] { new CustomApplication() };
        var cache = new Mock<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.FindByRedirectUriAsync("https://www.fabrikam.com/callback", It.IsAny<CancellationToken>()))
             .Returns(applications.ToAsyncEnumerable());

        store.Setup(store => store.GetRedirectUrisAsync(applications[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://www.fabrikam.com/callback"]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByRedirectUriAsync("https://www.fabrikam.com/callback").ToListAsync();

        // Assert
        Assert.Same(applications[0], result[0]);
        cache.Verify(cache => cache.FindByRedirectUriAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(store => store.FindByRedirectUriAsync("https://www.fabrikam.com/callback", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetApplicationTypeAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetApplicationTypeAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetAsync_WithQuery_ThrowsAnExceptionForNullQuery()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetAsync<CustomApplication>(query: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task GetAsync_WithQueryAndState_ThrowsAnExceptionForNullQuery()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetAsync<object, CustomApplication>(query: null!, state: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task GetClientIdAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetClientIdAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetClientIdAsync_ReturnsClientIdFromStore()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("my-client-id");

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var clientId = await manager.GetClientIdAsync(application);

        // Assert
        Assert.Equal("my-client-id", clientId);
        store.Verify(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetClientTypeAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetClientTypeAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetClientTypeAsync_ReturnsClientTypeFromStore()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("public");

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var clientType = await manager.GetClientTypeAsync(application);

        // Assert
        Assert.Equal("public", clientType);
        store.Verify(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetConsentTypeAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetConsentTypeAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetDisplayNameAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetDisplayNameAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetDisplayNameAsync_ReturnsDisplayNameFromStore()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetDisplayNameAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("My Application");

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var displayName = await manager.GetDisplayNameAsync(application);

        // Assert
        Assert.Equal("My Application", displayName);
        store.Verify(store => store.GetDisplayNameAsync(application, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetDisplayNamesAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetDisplayNamesAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetIdAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetIdAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetIdAsync_ReturnsIdentifierFromStore()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("unique-id");

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var id = await manager.GetIdAsync(application);

        // Assert
        Assert.Equal("unique-id", id);
        store.Verify(store => store.GetIdAsync(application, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetJsonWebKeySetAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetJsonWebKeySetAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetLocalizedDisplayNameAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetLocalizedDisplayNameAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetLocalizedDisplayNameAsync_WithCulture_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetLocalizedDisplayNameAsync(application: null!, CultureInfo.CurrentCulture).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetPermissionsAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetPermissionsAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetPostLogoutRedirectUrisAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetPostLogoutRedirectUrisAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetPropertiesAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetPropertiesAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetPublicKeyInfrastructureTlsClientAuthenticationPolicyAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);
        var policy = new X509ChainPolicy();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetPublicKeyInfrastructureTlsClientAuthenticationPolicyAsync(application: null!, policy).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetRedirectUrisAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetRedirectUrisAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetRequirementsAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetRequirementsAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetSelfSignedTlsClientAuthenticationPolicyAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);
        var policy = new X509ChainPolicy();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetSelfSignedTlsClientAuthenticationPolicyAsync(application: null!, policy).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task GetSettingsAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetSettingsAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task HasApplicationTypeAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasApplicationTypeAsync(application: null!, "web").AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task HasApplicationTypeAsync_ThrowsAnExceptionForNullType()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasApplicationTypeAsync(application, type: null!).AsTask());

        Assert.Equal("type", exception.ParamName);
    }

    [Fact]
    public async Task HasApplicationTypeAsync_ReturnsTrueWhenTypeMatches()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetApplicationTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("web");

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.HasApplicationTypeAsync(application, "web");

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task HasClientTypeAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasClientTypeAsync(application: null!, "public").AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task HasClientTypeAsync_ThrowsAnExceptionForNullType()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasClientTypeAsync(application, type: null!).AsTask());

        Assert.Equal("type", exception.ParamName);
    }

    [Theory]
    [InlineData("public", "public", true)]
    [InlineData("confidential", "public", false)]
    public async Task HasClientTypeAsync_ReturnsExpectedResult(string storedType, string testedType, bool expected)
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(storedType);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.HasClientTypeAsync(application, testedType);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public async Task HasConsentTypeAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasConsentTypeAsync(application: null!, "explicit").AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task HasConsentTypeAsync_ThrowsAnExceptionForNullType()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasConsentTypeAsync(application, type: null!).AsTask());

        Assert.Equal("type", exception.ParamName);
    }

    [Fact]
    public async Task HasConsentTypeAsync_ReturnsTrueWhenTypeMatches()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetConsentTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("explicit");

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.HasConsentTypeAsync(application, "explicit");

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task HasPermissionAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasPermissionAsync(application: null!, "ept:token").AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task HasPermissionAsync_ThrowsAnExceptionForNullPermission()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasPermissionAsync(application, permission: null!).AsTask());

        Assert.Equal("permission", exception.ParamName);
    }

    [Fact]
    public async Task HasRequirementAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasRequirementAsync(application: null!, "requirement").AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task HasRequirementAsync_ThrowsAnExceptionForNullRequirement()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.HasRequirementAsync(application, requirement: null!).AsTask());

        Assert.Equal("requirement", exception.ParamName);
    }

    [Fact]
    public async Task HasRequirementAsync_ReturnsTrueWhenRequirementExists()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetRequirementsAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["requirement1", "requirement2"]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.HasRequirementAsync(application, "requirement1");

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task ListAsync_ReturnsAllApplications()
    {
        // Arrange
        var applications = new[] { new CustomApplication(), new CustomApplication() };
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()))
             .Returns(applications.ToAsyncEnumerable());

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = new List<CustomApplication>();
        await foreach (var app in manager.ListAsync())
        {
            results.Add(app);
        }

        // Assert
        Assert.Equal(2, results.Count);
        store.Verify(store => store.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ObfuscateClientSecretAsync_ThrowsAnExceptionForNullSecret()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.ObfuscateClientSecretAsync(secret: null!).AsTask());

        Assert.Equal("secret", exception.ParamName);
    }

    [Fact]
    public async Task ObfuscateClientSecretAsync_ThrowsAnExceptionForEmptySecret()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.ObfuscateClientSecretAsync(secret: string.Empty).AsTask());

        Assert.Equal("secret", exception.ParamName);
    }

    [Fact]
    public async Task ObfuscateClientSecretAsync_ReturnsBase64EncodedHash()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act
        var hash = await manager.ObfuscateClientSecretAsync("my-secret");

        var payload = Convert.FromBase64String(hash);
        Assert.NotEmpty(payload);
    }

    [Fact]
    public async Task ObfuscateClientSecretAsync_WritesFormatMarker()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act
        var hash = await manager.ObfuscateClientSecretAsync("my-secret");

        var payload = Convert.FromBase64String(hash);
        Assert.Equal(0x01, payload[0]);
    }

    [Fact]
    public async Task ObfuscateClientSecretAsync_UsesSha512ByDefault()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act
        var hash = await manager.ObfuscateClientSecretAsync("my-secret");

        var payload = Convert.FromBase64String(hash);
        Assert.Equal(2u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(1, 4)));
    }

    [Fact]
    public async Task ObfuscateClientSecretAsync_UsesSha256WhenConfigured()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions
            {
                ClientSecretKeyDerivationHashAlgorithm = HashAlgorithmName.SHA256
            });
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act
        var hash = await manager.ObfuscateClientSecretAsync("my-secret");

        var payload = Convert.FromBase64String(hash);
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(1, 4)));
    }

    [Fact]
    public async Task ObfuscateClientSecretAsync_UsesSha1WhenConfigured()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions
            {
                ClientSecretKeyDerivationHashAlgorithm = HashAlgorithmName.SHA1
            });
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act
        var hash = await manager.ObfuscateClientSecretAsync("my-secret");

        var payload = Convert.FromBase64String(hash);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(1, 4)));
    }

    [Fact]
    public async Task ObfuscateClientSecretAsync_ThrowsForUnsupportedAlgorithm()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions
            {
                ClientSecretKeyDerivationHashAlgorithm = HashAlgorithmName.SHA384
            });
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act and assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => manager.ObfuscateClientSecretAsync("my-secret").AsTask());
    }

    [Fact]
    public async Task ObfuscateClientSecretAsync_WritesConfiguredIterationCount()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions
            {
                ClientSecretKeyDerivationIterations = 50_000
            });
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act
        var hash = await manager.ObfuscateClientSecretAsync("my-secret");

        // Assert
        var payload = Convert.FromBase64String(hash);
        Assert.Equal(50_000u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(5, 4)));
    }

    [Fact]
    public async Task ObfuscateClientSecretAsync_WritesSaltOfConfiguredLength()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions
            {
                ClientSecretKeyDerivationSaltLength = 128 // bits → 16 bytes
            });
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act
        var hash = await manager.ObfuscateClientSecretAsync("my-secret");

        var payload = Convert.FromBase64String(hash);
        Assert.Equal(16u, BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(9, 4)));
    }

    [Fact]
    public async Task ObfuscateClientSecretAsync_ProducesDifferentHashesForSameSecret()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        var hash1 = await manager.ObfuscateClientSecretAsync("my-secret");
        var hash2 = await manager.ObfuscateClientSecretAsync("my-secret");

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public async Task ObfuscateClientSecretAsync_ProducesHashValidatableByValidateClientSecretAsync()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act
        var hash = await manager.ObfuscateClientSecretAsync("my-secret");
        var (isValid, isRehashRequired) = await manager.ValidateClientSecretAsync("my-secret", hash);

        // Assert
        Assert.True(isValid);
        Assert.False(isRehashRequired);
    }

    [Fact]
    public async Task PopulateAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);
        var descriptor = new OpenIddictApplicationDescriptor();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.PopulateAsync(application: null!, descriptor).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task PopulateAsync_ThrowsAnExceptionForNullDescriptor()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.PopulateAsync(application, descriptor: null!).AsTask());

        Assert.Equal("descriptor", exception.ParamName);
    }

    [Fact]
    public async Task UpdateAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.UpdateAsync(application: null!).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task UpdateAsync_WithDescriptor_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);
        var descriptor = new OpenIddictApplicationDescriptor();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.UpdateAsync(application: null!, descriptor).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task UpdateAsync_WithSecret_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.UpdateAsync(application: null!, secret: "secret").AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public void ValidateAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => manager.ValidateAsync(application: null!));

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenClientIdIsEmpty()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Public);

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(application).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2036));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenClientIdIsAlreadyUsed()
    {
        // Arrange
        var application = new CustomApplication();
        var other = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.FindByClientIdAsync("client-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(other);

        store.Setup(store => store.GetIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");

        store.Setup(store => store.GetIdAsync(other, It.IsAny<CancellationToken>()))
             .ReturnsAsync("other-application-id");

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Public);

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(application).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2111));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenClientTypeIsEmpty()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(application).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2050));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenClientTypeIsNotSupported()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("unsupported-type");

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(application).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2112));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenPublicApplicationHasClientSecret()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Public);

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("some-secret");

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(application).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2114));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenConfidentialApplicationHasNoSecretAndNoSigningKey()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Confidential);

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        store.Setup(store => store.GetJsonWebKeySetAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync((JsonWebKeySet?) null);

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(application).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2113));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenConfidentialApplicationHasJwksWithoutSigningKey()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Confidential);

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        var jwks = new JsonWebKeySet();
        jwks.Keys.Add(new JsonWebKey { Kty = JsonWebAlgorithmsKeyTypes.Octet, Use = JsonWebKeyUseNames.Sig });

        store.Setup(store => store.GetJsonWebKeySetAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(jwks);

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(application).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2113));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenRedirectUriIsEmpty()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Confidential);

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("hashed-secret");

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([string.Empty]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(application).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2061));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenRedirectUriIsNotAbsolute()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Confidential);

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("hashed-secret");

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["not-an-absolute-uri"]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(application).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2062));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenRedirectUriContainsFragment()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Confidential);

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("hashed-secret");

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://client.contoso.com/callback#fragment"]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(application).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2115));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenRedirectUriContainsIssParameter()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Confidential);

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("hashed-secret");

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://client.contoso.com/callback?iss=https%3A%2F%2Fissuer.contoso.com"]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(application).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.FormatID2134(Parameters.Iss));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenPostLogoutRedirectUriContainsFragment()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Confidential);

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("hashed-secret");

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://client.contoso.com/logout#fragment"]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(application).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2115));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsNoErrorsForValidConfidentialApplicationWithSecret()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Confidential);

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("hashed-secret");

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://client.contoso.com/callback"]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(application).ToListAsync();

        // Assert
        Assert.DoesNotContain(results, static result => result != ValidationResult.Success);
    }

    [Fact]
    public async Task ValidateAsync_ReturnsNoErrorsForValidConfidentialApplicationWithRsaSigningKey()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Confidential);

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        var jwks = new JsonWebKeySet();
        jwks.Keys.Add(new JsonWebKey { Kty = JsonWebAlgorithmsKeyTypes.RSA, Use = JsonWebKeyUseNames.Sig });

        store.Setup(store => store.GetJsonWebKeySetAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(jwks);

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(application).ToListAsync();

        // Assert
        Assert.DoesNotContain(results, static result => result != ValidationResult.Success);
    }

    [Fact]
    public async Task ValidateAsync_ReturnsNoErrorsForValidPublicApplication()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Public);

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://client.contoso.com/callback"]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(application).ToListAsync();

        // Assert
        Assert.DoesNotContain(results, static result => result != ValidationResult.Success);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.ValidateClientSecretAsync(application: null!, "secret").AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ThrowsAnExceptionForNullSecret()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.ValidateClientSecretAsync(application, secret: null!).AsTask());

        Assert.Equal("secret", exception.ParamName);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ThrowsAnExceptionForEmptySecret()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.ValidateClientSecretAsync(application, secret: string.Empty).AsTask());

        Assert.Equal("secret", exception.ParamName);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ReturnsFalseForPublicClients()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Public);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.ValidateClientSecretAsync(application, "any-secret");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ReturnsFalseWhenStoredSecretIsNull()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Confidential);

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.ValidateClientSecretAsync(application, "any-secret");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ReturnsFalseWhenStoredSecretIsEmpty()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Confidential);

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.ValidateClientSecretAsync(application, "any-secret");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ReturnsFalseWhenSecretDoesNotMatch()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Confidential);

        var hashedSecret = "AQAAAAIAAYagAAAAEOlzsJpxnNJRh9HnCQNEzZMPLqTYYqH5WJ5+DJMwL+BhiLUGjL2SQnfRU8bQv2K2Sg==";
        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(hashedSecret);

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.ValidateClientSecretAsync(application, "wrong-secret");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_PerformsRehashWhenRequired()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        var storedHash = "AQAAAAEAACcQAAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fMMgkjB4tHCgxxjPemQnSkFqO0dtrtE3xiqISZNQJfWNqm+Flbr/sNlQCAWRy0XrIxw6HU3B+YB5aHDlJhCTw2w==";

        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions
            {
                DisableAutomaticClientSecretRehashing = false
            });

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Confidential);

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(storedHash);

        store.Setup(store => store.FindByClientIdAsync("client-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync((CustomApplication?) null);

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.UpdateAsync(application, It.IsAny<CancellationToken>()))
             .Returns(ValueTask.CompletedTask);

        store.Setup(store => store.SetClientSecretAsync(application, It.IsAny<string?>(), It.IsAny<CancellationToken>()))
             .Returns(ValueTask.CompletedTask);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        await manager.ValidateClientSecretAsync(application, "test-secret");

        // Assert
        store.Verify(store => store.UpdateAsync(application, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateClientSecretAsync_SkipsRehashWhenDisabled()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions
            {
                DisableAutomaticClientSecretRehashing = true
            });
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Confidential);

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        var oldHash = "AQAAAAEACicQAAAAEJPkfY9tVqKqHQlLPqNT0ksqN8C3LqY4RqBYQaJHhWPQXuYhWFpN9pLkR8vZxQ==";
        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(oldHash);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.ValidateClientSecretAsync(application, "test-secret");

        // Assert
        store.Verify(store => store.UpdateAsync(application, It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ContinuesOnRehashFailure()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions
            {
                DisableAutomaticClientSecretRehashing = false
            });

        store.Setup(store => store.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ClientTypes.Confidential);

        store.Setup(store => store.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("client-id");

        store.Setup(store => store.GetClientSecretAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync("AQAAAAEAACcQAAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fMMgkjB4tHCgxxjPemQnSkFqO0dtrtE3xiqISZNQJfWNqm+Flbr/sNlQCAWRy0XrIxw6HU3B+YB5aHDlJhCTw2w==");

        store.Setup(store => store.FindByClientIdAsync("client-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync((CustomApplication?) null);

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync([]);

        store.Setup(store => store.UpdateAsync(application, It.IsAny<CancellationToken>()))
             .Returns(new ValueTask(Task.FromException(new InvalidOperationException("Concurrency conflict"))));

        store.Setup(store => store.SetClientSecretAsync(application, It.IsAny<string?>(), It.IsAny<CancellationToken>()))
             .Returns(ValueTask.CompletedTask);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.ValidateClientSecretAsync(application, "test-secret");

        // Assert
        Assert.True(result);
        store.Verify(store => store.UpdateAsync(application, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ThrowsAnExceptionForNullSecret()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.ValidateClientSecretAsync(secret: null!, "comparand").AsTask());

        Assert.Equal("secret", exception.ParamName);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ThrowsAnExceptionForEmptySecret()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.ValidateClientSecretAsync(secret: string.Empty, "comparand").AsTask());

        Assert.Equal("secret", exception.ParamName);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ThrowsAnExceptionForNullComparand()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.ValidateClientSecretAsync("secret", comparand: null!).AsTask());

        Assert.Equal("comparand", exception.ParamName);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ThrowsAnExceptionForEmptyComparand()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.ValidateClientSecretAsync("secret", comparand: string.Empty).AsTask());

        Assert.Equal("comparand", exception.ParamName);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ReturnsFalseForInvalidBase64Comparand()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act
        var (isValid, isRehashRequired) = await manager.ValidateClientSecretAsync("secret", "not-valid-base64!!!");

        // Assert
        Assert.False(isValid);
        Assert.False(isRehashRequired);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ReturnsFalseForEmptyPayload()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        var (isValid, isRehashRequired) = await manager.ValidateClientSecretAsync("secret", Convert.ToBase64String([0x01]));

        // Assert
        Assert.False(isValid);
        Assert.False(isRehashRequired);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ReturnsFalseForInvalidFormatMarker()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        var payload = new byte[20];
        payload[0] = 0x02;
        var (isValid, isRehashRequired) = await manager.ValidateClientSecretAsync("secret", Convert.ToBase64String(payload));

        // Assert
        Assert.False(isValid);
        Assert.False(isRehashRequired);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ReturnsFalseForUnknownAlgorithmVersion()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        var payload = new byte[50];
        payload[0] = 0x01;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), 99);
        var (isValid, isRehashRequired) = await manager.ValidateClientSecretAsync("secret", Convert.ToBase64String(payload));

        // Assert
        Assert.False(isValid);
        Assert.False(isRehashRequired);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ReturnsFalseForTooFewIterations()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        var payload = new byte[50];
        payload[0] = 0x01;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), 1); // SHA256
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), 9_999);
        var (isValid, isRehashRequired) = await manager.ValidateClientSecretAsync("secret", Convert.ToBase64String(payload));

        // Assert
        Assert.False(isValid);
        Assert.False(isRehashRequired);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ReturnsFalseForTooManyIterations()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        var payload = new byte[50];
        payload[0] = 0x01;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), 1); // SHA256
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), 10_000_001);
        var (isValid, isRehashRequired) = await manager.ValidateClientSecretAsync("secret", Convert.ToBase64String(payload));

        // Assert
        Assert.False(isValid);
        Assert.False(isRehashRequired);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ReturnsFalseForTooShortSalt()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        var payload = new byte[50];
        payload[0] = 0x01;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), 1); // SHA256
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), 100_000);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(9, 4), 15);
        var (isValid, isRehashRequired) = await manager.ValidateClientSecretAsync("secret", Convert.ToBase64String(payload));

        // Assert
        Assert.False(isValid);
        Assert.False(isRehashRequired);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ReturnsFalseWhenSecretDoesNotMatch()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act
        var (isValid, isRehashRequired) = await manager.ValidateClientSecretAsync("wrong-secret",
            "AQAAAAIAAYagAAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fa7sVq4Aib4PoDsWFuIX7V4NFLHw5zf2TM+3M6JSc3S2ae5j2Njof7cWUUqaG4esxvbG6aKTTQMogVSejRPMbhQ==");

        // Assert
        Assert.False(isValid);
        Assert.False(isRehashRequired);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ReturnsTrueWithoutRehashWhenOptionsMatch()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act
        var (isValid, isRehashRequired) = await manager.ValidateClientSecretAsync("my-secret",
            "AQAAAAIAAYagAAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fhmvJW1GK8OLHa33ut1TfRoG5BojsxFN8Oq8lnF9CTGu/Ti7ItixBhZaDxxb5lejILz/Ob+33P0h2Zax9+FTeWg==");

        // Assert
        Assert.True(isValid);
        Assert.False(isRehashRequired);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ReturnsTrueWithRehashWhenAlgorithmChanged()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act
        var (isValid, isRehashRequired) = await manager.ValidateClientSecretAsync("my-secret",
            "AQAAAAEAAYagAAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fcc2TaLOEfZnHMySJlkQmmM1nnq4c6jFhE65SjmqPATGuvpSybeRzlk8584bUg3qjJbxxJ1oALKzppT0V6sPYQQ==");

        // Assert
        Assert.True(isValid);
        Assert.True(isRehashRequired);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ReturnsTrueWithRehashWhenIterationsChanged()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act
        var (isValid, isRehashRequired) = await manager.ValidateClientSecretAsync("my-secret",
            "AQAAAAIAAMNQAAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fhUaA0RyMXFhPzsknq1++eBXKuNGp6nPquCMb4NVu9st1Qj6cDZXnnHmS2FXgc/2AUe8+QJ35JGY3SW3gJjzQUA==");

        // Assert
        Assert.True(isValid);
        Assert.True(isRehashRequired);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ReturnsTrueWithRehashWhenSaltLengthChanged()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act
        var (isValid, isRehashRequired) = await manager.ValidateClientSecretAsync("my-secret",
            "AQAAAAIAAYagAAAAEAABAgMEBQYHCAkKCwwNDg9/NCTaaTU2IRS086JD6lOexCek5paQ+YtfkDinqaRBpu6sdgeztT00H36B5hWW787rjVDMg9IpYdZ7iPiQZZZu");

        // Assert
        Assert.True(isValid);
        Assert.True(isRehashRequired);
    }

    [Fact]
    public async Task ValidateClientSecretAsync_ProtectedMethod_ReturnsTrueWithRehashWhenOutputLengthChanged()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var manager = new CustomApplicationManagerWithProtectedAccess(cache, logger, options, store);

        // Act
        var (isValid, isRehashRequired) = await manager.ValidateClientSecretAsync("my-secret",
            "AQAAAAIAAYagAAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fhmvJW1GK8OLHa33ut1TfRg==");

        // Assert
        Assert.True(isValid);
        Assert.True(isRehashRequired);
    }

    [Fact]
    public async Task ValidatePostLogoutRedirectUriAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.ValidatePostLogoutRedirectUriAsync(application: null!, "https://localhost").AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task ValidatePostLogoutRedirectUriAsync_ThrowsAnExceptionForNullUri()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.ValidatePostLogoutRedirectUriAsync(application, uri: null!).AsTask());

        Assert.Equal("uri", exception.ParamName);
    }

    [Fact]
    public async Task ValidatePostLogoutRedirectUriAsync_ThrowsAnExceptionForEmptyUri()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.ValidatePostLogoutRedirectUriAsync(application, uri: string.Empty).AsTask());

        Assert.Equal("uri", exception.ParamName);
    }

    [Fact]
    public async Task ValidatePostLogoutRedirectUriAsync_ReturnsFalseWhenUriNotRegistered()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://contoso.com/logout"]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.ValidatePostLogoutRedirectUriAsync(application, "https://other.com/logout");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidatePostLogoutRedirectUriAsync_ReturnsTrueWhenUriMatchesExactly()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://contoso.com/logout"]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.ValidatePostLogoutRedirectUriAsync(application, "https://contoso.com/logout");

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task ValidatePostLogoutRedirectUriAsync_ReturnsFalseWhenUriDiffersInCase()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://contoso.com/Logout"]);

        store.Setup(store => store.GetApplicationTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ApplicationTypes.Web);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.ValidatePostLogoutRedirectUriAsync(application, "https://contoso.com/logout");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidatePostLogoutRedirectUriAsync_ReturnsTrueForNativeApplicationWhenLoopbackUriMatchesWithDifferentPort()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["http://127.0.0.1/logout"]);

        store.Setup(store => store.GetApplicationTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ApplicationTypes.Native);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        var result = await manager.ValidatePostLogoutRedirectUriAsync(application, "http://127.0.0.1:7890/logout");

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task ValidatePostLogoutRedirectUriAsync_ReturnsFalseForNativeApplicationWhenClientUriUsesDefaultPort()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["http://127.0.0.1/logout"]);

        store.Setup(store => store.GetApplicationTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ApplicationTypes.Native);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        var result = await manager.ValidatePostLogoutRedirectUriAsync(application, "http://127.0.0.1:80/logout");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidatePostLogoutRedirectUriAsync_ReturnsFalseForNativeApplicationWhenUriIsNotLoopback()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://contoso.com/logout"]);

        store.Setup(store => store.GetApplicationTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ApplicationTypes.Native);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        var result = await manager.ValidatePostLogoutRedirectUriAsync(application, "https://contoso.com:7890/logout");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidatePostLogoutRedirectUriAsync_ReturnsFalseForNativeApplicationWhenSchemesDiffer()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["http://127.0.0.1/logout"]);

        store.Setup(store => store.GetApplicationTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ApplicationTypes.Native);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        var result = await manager.ValidatePostLogoutRedirectUriAsync(application, "https://127.0.0.1:7890/logout");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidatePostLogoutRedirectUriAsync_ReturnsFalseForNativeApplicationWhenPathsDiffer()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["http://127.0.0.1/logout"]);

        store.Setup(store => store.GetApplicationTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ApplicationTypes.Native);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        var result = await manager.ValidatePostLogoutRedirectUriAsync(application, "http://127.0.0.1:7890/other");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidatePostLogoutRedirectUriAsync_ReturnsFalseForNonNativeApplicationWhenPortDiffers()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetPostLogoutRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["http://127.0.0.1/logout"]);

        store.Setup(store => store.GetApplicationTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ApplicationTypes.Web);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.ValidatePostLogoutRedirectUriAsync(application, "http://127.0.0.1:7890/logout");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidatePublicKeyInfrastructureTlsClientCertificateAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);
        var certificate = (X509Certificate2)null!;
        var policy = new X509ChainPolicy();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.ValidatePublicKeyInfrastructureTlsClientCertificateAsync(application: null!, certificate, policy).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task ValidatePublicKeyInfrastructureTlsClientCertificateAsync_ThrowsAnExceptionForNullCertificate()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);
        var policy = new X509ChainPolicy();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.ValidatePublicKeyInfrastructureTlsClientCertificateAsync(application, certificate: null!, policy).AsTask());

        Assert.Equal("certificate", exception.ParamName);
    }

    [Fact]
    public async Task ValidateRedirectUriAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.ValidateRedirectUriAsync(application: null!, "https://localhost").AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task ValidateRedirectUriAsync_ThrowsAnExceptionForNullUri()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.ValidateRedirectUriAsync(application, uri: null!).AsTask());

        Assert.Equal("uri", exception.ParamName);
    }

    [Fact]
    public async Task ValidateRedirectUriAsync_ThrowsAnExceptionForEmptyUri()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.ValidateRedirectUriAsync(application, uri: string.Empty).AsTask());

        Assert.Equal("uri", exception.ParamName);
    }

    [Fact]
    public async Task ValidateRedirectUriAsync_ReturnsFalseWhenUriNotRegistered()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://contoso.com/callback"]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.ValidateRedirectUriAsync(application, "https://other.com/callback");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateRedirectUriAsync_ReturnsTrueWhenUriMatchesExactly()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://contoso.com/callback"]);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.ValidateRedirectUriAsync(application, "https://contoso.com/callback");

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task ValidateRedirectUriAsync_ReturnsFalseWhenUriDiffersInCase()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://contoso.com/Callback"]);

        store.Setup(store => store.GetApplicationTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ApplicationTypes.Web);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.ValidateRedirectUriAsync(application, "https://contoso.com/callback");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateRedirectUriAsync_ReturnsTrueForNativeApplicationWhenLoopbackUriMatchesWithDifferentPort()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["http://127.0.0.1/callback"]);

        store.Setup(store => store.GetApplicationTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ApplicationTypes.Native);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        var result = await manager.ValidateRedirectUriAsync(application, "http://127.0.0.1:7890/callback");

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task ValidateRedirectUriAsync_ReturnsFalseForNativeApplicationWhenClientUriUsesDefaultPort()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["http://127.0.0.1/callback"]);

        store.Setup(store => store.GetApplicationTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ApplicationTypes.Native);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        var result = await manager.ValidateRedirectUriAsync(application, "http://127.0.0.1:80/callback");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateRedirectUriAsync_ReturnsFalseForNativeApplicationWhenUriIsNotLoopback()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["https://contoso.com/callback"]);

        store.Setup(store => store.GetApplicationTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ApplicationTypes.Native);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        var result = await manager.ValidateRedirectUriAsync(application, "https://contoso.com:7890/callback");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateRedirectUriAsync_ReturnsFalseForNativeApplicationWhenSchemesDiffer()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["http://127.0.0.1/callback"]);

        store.Setup(store => store.GetApplicationTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ApplicationTypes.Native);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        var result = await manager.ValidateRedirectUriAsync(application, "https://127.0.0.1:7890/callback");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateRedirectUriAsync_ReturnsFalseForNativeApplicationWhenPathsDiffer()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["http://127.0.0.1/callback"]);

        store.Setup(store => store.GetApplicationTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ApplicationTypes.Native);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        var result = await manager.ValidateRedirectUriAsync(application, "http://127.0.0.1:7890/other");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateRedirectUriAsync_ReturnsFalseForNonNativeApplicationWhenPortDiffers()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictApplicationStore<CustomApplication>>();

        store.Setup(store => store.GetRedirectUrisAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(["http://127.0.0.1/callback"]);

        store.Setup(store => store.GetApplicationTypeAsync(application, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ApplicationTypes.Web);

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store.Object);

        // Act
        var result = await manager.ValidateRedirectUriAsync(application, "http://127.0.0.1:7890/callback");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateSelfSignedTlsClientCertificateAsync_ThrowsAnExceptionForNullApplication()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);
        var certificate = (X509Certificate2)null!;
        var policy = new X509ChainPolicy();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.ValidateSelfSignedTlsClientCertificateAsync(application: null!, certificate, policy).AsTask());

        Assert.Equal("application", exception.ParamName);
    }

    [Fact]
    public async Task ValidateSelfSignedTlsClientCertificateAsync_ThrowsAnExceptionForNullCertificate()
    {
        // Arrange
        var application = new CustomApplication();
        var cache = Mock.Of<IOpenIddictApplicationCache<CustomApplication>>();
        var logger = Mock.Of<ILogger<OpenIddictApplicationManager<CustomApplication>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictApplicationStore<CustomApplication>>();

        var manager = new OpenIddictApplicationManager<CustomApplication>(cache, logger, options, store);
        var policy = new X509ChainPolicy();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.ValidateSelfSignedTlsClientCertificateAsync(application, certificate: null!, policy).AsTask());

        Assert.Equal("certificate", exception.ParamName);
    }

    public class CustomApplication { }

    private class CustomApplicationManagerWithProtectedAccess : OpenIddictApplicationManager<CustomApplication>
    {
        public CustomApplicationManagerWithProtectedAccess(
            IOpenIddictApplicationCache<CustomApplication> cache,
            ILogger<OpenIddictApplicationManager<CustomApplication>> logger,
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictApplicationStore<CustomApplication> store)
            : base(cache, logger, options, store)
        {
        }

        public new ValueTask<string> ObfuscateClientSecretAsync(string secret, CancellationToken cancellationToken = default)
            => base.ObfuscateClientSecretAsync(secret, cancellationToken);

        public new ValueTask<(bool IsValid, bool IsRehashRequired)> ValidateClientSecretAsync(
            string secret, string comparand, CancellationToken cancellationToken = default)
            => base.ValidateClientSecretAsync(secret, comparand, cancellationToken);
    }
}
