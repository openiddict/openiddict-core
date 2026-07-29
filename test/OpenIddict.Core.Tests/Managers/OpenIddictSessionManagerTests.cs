/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace OpenIddict.Core.Tests;

public class OpenIddictSessionManagerTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullCache()
    {
        // Arrange
        var cache = (IOpenIddictSessionCache<CustomSession>) null!;
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictSessionManager<CustomSession>(cache, logger, options, store));

        Assert.Equal("cache", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullLogger()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = (ILogger<OpenIddictSessionManager<CustomSession>>) null!;
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictSessionManager<CustomSession>(cache, logger, options, store));

        Assert.Equal("logger", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = (IOptionsMonitor<OpenIddictCoreOptions>) null!;
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictSessionManager<CustomSession>(cache, logger, options, store));

        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullStore()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = (IOpenIddictSessionStore<CustomSession>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictSessionManager<CustomSession>(cache, logger, options, store));

        Assert.Equal("store", exception.ParamName);
    }

    [Fact]
    public async Task CountAsync_CallsStoreMethod()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();

        store.Setup(store => store.CountAsync(It.IsAny<CancellationToken>()))
             .ReturnsAsync(42);

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store.Object);

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
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.CountAsync<CustomSession>(query: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task CreateAsync_ThrowsAnExceptionForNullSession()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.CreateAsync(session: null!).AsTask());

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public async Task DeleteAsync_ThrowsAnExceptionForNullSession()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.DeleteAsync(session: null!).AsTask());

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public async Task DeleteAsync_RemovessessionFromCache_WhenCachingIsEnabled()
    {
        // Arrange
        var cache = new Mock<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = false });
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();
        var session = new CustomSession();

        var manager = new OpenIddictSessionManager<CustomSession>(cache.Object, logger, options, store.Object);

        // Act
        await manager.DeleteAsync(session);

        // Assert
        cache.Verify(cache => cache.RemoveAsync(session, It.IsAny<CancellationToken>()), Times.Once());
        store.Verify(store => store.DeleteAsync(session, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task DeleteAsync_DoesNotRemoveFromCache_WhenCachingIsDisabled()
    {
        // Arrange
        var cache = new Mock<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();
        var session = new CustomSession();

        var manager = new OpenIddictSessionManager<CustomSession>(cache.Object, logger, options, store.Object);

        // Act
        await manager.DeleteAsync(session);

        // Assert
        cache.Verify(cache => cache.RemoveAsync(It.IsAny<CustomSession>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(store => store.DeleteAsync(session, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.FindByIdAsync(identifier: null!).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.FindByIdAsync(identifier: string.Empty).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_UsesCache_WhenCachingIsEnabled()
    {
        // Arrange
        var session = new CustomSession();
        var cache = new Mock<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = false });
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();

        cache.Setup(cache => cache.FindByIdAsync("id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(session);

        store.Setup(store => store.GetIdAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync("id");

        var manager = new OpenIddictSessionManager<CustomSession>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByIdAsync("id");

        // Assert
        Assert.Same(session, result);
        cache.Verify(cache => cache.FindByIdAsync("id", It.IsAny<CancellationToken>()), Times.Once());
        store.Verify(store => store.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByIdAsync_UsesStore_WhenCachingIsDisabled()
    {
        // Arrange
        var session = new CustomSession();
        var cache = new Mock<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();

        store.Setup(store => store.FindByIdAsync("id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(session);

        store.Setup(store => store.GetIdAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync("id");

        var manager = new OpenIddictSessionManager<CustomSession>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByIdAsync("id");

        // Assert
        Assert.Same(session, result);
        cache.Verify(cache => cache.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(store => store.FindByIdAsync("id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetAsync_WithQuery_ThrowsAnExceptionForNullQuery()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetAsync<CustomSession>(query: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task GetAsync_WithQueryAndState_ThrowsAnExceptionForNullQuery()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetAsync<object, CustomSession>(query: null!, state: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task GetIdAsync_ThrowsAnExceptionForNullSession()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetIdAsync(session: null!).AsTask());

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public async Task GetIdAsync_ReturnsIdentifierFromStore()
    {
        // Arrange
        var session = new CustomSession();
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();

        store.Setup(store => store.GetIdAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync("unique-session-id");

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store.Object);

        // Act
        var id = await manager.GetIdAsync(session);

        // Assert
        Assert.Equal("unique-session-id", id);
        store.Verify(store => store.GetIdAsync(session, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetApplicationIdAsync_ThrowsAnExceptionForNullSession()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetApplicationIdAsync(session: null!).AsTask());

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public async Task GetApplicationIdAsync_ReturnsIdentifierFromStore()
    {
        // Arrange
        var session = new CustomSession();
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();

        store.Setup(store => store.GetApplicationIdAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store.Object);

        // Act
        var applicationId = await manager.GetApplicationIdAsync(session);

        // Assert
        Assert.Equal("application-id", applicationId);
        store.Verify(store => store.GetApplicationIdAsync(session, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetAuthorizationIdAsync_ThrowsAnExceptionForNullSession()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetAuthorizationIdAsync(session: null!).AsTask());

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public async Task GetAuthorizationIdAsync_ReturnsIdentifierFromStore()
    {
        // Arrange
        var session = new CustomSession();
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();

        store.Setup(store => store.GetAuthorizationIdAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync("authorization-id");

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store.Object);

        // Act
        var authorizationId = await manager.GetAuthorizationIdAsync(session);

        // Assert
        Assert.Equal("authorization-id", authorizationId);
        store.Verify(store => store.GetAuthorizationIdAsync(session, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetCreationDateAsync_ThrowsAnExceptionForNullSession()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetCreationDateAsync(session: null!).AsTask());

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public async Task GetCreationDateAsync_ReturnsCreationDateFromStore()
    {
        // Arrange
        var session = new CustomSession();
        var creationDate = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();

        store.Setup(store => store.GetCreationDateAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync(creationDate);

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store.Object);

        // Act
        var result = await manager.GetCreationDateAsync(session);

        // Assert
        Assert.Equal(creationDate, result);
        store.Verify(store => store.GetCreationDateAsync(session, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetLoginIdAsync_ThrowsAnExceptionForNullSession()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetLoginIdAsync(session: null!).AsTask());

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public async Task GetLoginIdAsync_ReturnsIdentifierFromStore()
    {
        // Arrange
        var session = new CustomSession();
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();

        store.Setup(store => store.GetLoginIdAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync("login-id");

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store.Object);

        // Act
        var loginId = await manager.GetLoginIdAsync(session);

        // Assert
        Assert.Equal("login-id", loginId);
        store.Verify(store => store.GetLoginIdAsync(session, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetPropertiesAsync_ThrowsAnExceptionForNullSession()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetPropertiesAsync(session: null!).AsTask());

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public async Task GetPropertiesAsync_ReturnsPropertiesFromStore()
    {
        // Arrange
        var session = new CustomSession();
        var properties = ImmutableDictionary<string, JsonElement>.Empty;
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();

        store.Setup(store => store.GetPropertiesAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync(properties);

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store.Object);

        // Act
        var result = await manager.GetPropertiesAsync(session);

        // Assert
        Assert.Same(properties, result);
        store.Verify(store => store.GetPropertiesAsync(session, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetStatusAsync_ThrowsAnExceptionForNullSession()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetStatusAsync(session: null!).AsTask());

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public async Task GetStatusAsync_ReturnsStatusFromStore()
    {
        // Arrange
        var session = new CustomSession();
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();

        store.Setup(store => store.GetStatusAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync(Statuses.Valid);

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store.Object);

        // Act
        var status = await manager.GetStatusAsync(session);

        // Assert
        Assert.Equal(Statuses.Valid, status);
        store.Verify(store => store.GetStatusAsync(session, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetSubjectAsync_ThrowsAnExceptionForNullSession()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetSubjectAsync(session: null!).AsTask());

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public async Task GetSubjectAsync_ReturnsSubjectFromStore()
    {
        // Arrange
        var session = new CustomSession();
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();

        store.Setup(store => store.GetSubjectAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync("subject");

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store.Object);

        // Act
        var subject = await manager.GetSubjectAsync(session);

        // Assert
        Assert.Equal("subject", subject);
        store.Verify(store => store.GetSubjectAsync(session, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ListAsync_ReturnsAllSessions()
    {
        // Arrange
        var sessions = new[] { new CustomSession(), new CustomSession() };
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();

        store.Setup(store => store.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()))
             .Returns(sessions.ToAsyncEnumerable());

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store.Object);

        // Act
        var results = new List<CustomSession>();
        await foreach (var scp in manager.ListAsync())
        {
            results.Add(scp);
        }

        // Assert
        Assert.Equal(2, results.Count);
        store.Verify(store => store.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task PopulateAsync_ThrowsAnExceptionForNullSession()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);
        var descriptor = new OpenIddictSessionDescriptor();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.PopulateAsync(session: null!, descriptor).AsTask());

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public async Task PopulateAsync_ThrowsAnExceptionForNullDescriptor()
    {
        // Arrange
        var session = new CustomSession();
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.PopulateAsync(session, descriptor: null!).AsTask());

        Assert.Equal("descriptor", exception.ParamName);
    }

    [Fact]
    public async Task UpdateAsync_ThrowsAnExceptionForNullSession()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.UpdateAsync(session: null!).AsTask());

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public async Task UpdateAsync_WithDescriptor_ThrowsAnExceptionForNullSession()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);
        var descriptor = new OpenIddictSessionDescriptor();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.UpdateAsync(session: null!, descriptor).AsTask());

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public void ValidateAsync_ThrowsAnExceptionForNullSession()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictSessionStore<CustomSession>>();

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => manager.ValidateAsync(session: null!));

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenStatusIsEmpty()
    {
        // Arrange
        var session = new CustomSession();
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();

        store.Setup(store => store.GetStatusAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(session).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2038));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenLoginIdIsEmpty()
    {
        // Arrange
        var session = new CustomSession();
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();

        store.Setup(store => store.GetStatusAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync(Statuses.Valid);

        store.Setup(store => store.GetLoginIdAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(session).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2209));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsNoErrorsForValidSession()
    {
        // Arrange
        var session = new CustomSession();
        var cache = Mock.Of<IOpenIddictSessionCache<CustomSession>>();
        var logger = Mock.Of<ILogger<OpenIddictSessionManager<CustomSession>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictSessionStore<CustomSession>>();

        store.Setup(store => store.GetStatusAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync(Statuses.Valid);

        store.Setup(store => store.GetLoginIdAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync("login-id");

        var manager = new OpenIddictSessionManager<CustomSession>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(session).ToListAsync();

        // Assert
        Assert.DoesNotContain(results, static result => result != ValidationResult.Success);
    }

    public class CustomSession;
}
