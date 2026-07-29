/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace OpenIddict.Core.Tests;

public class OpenIddictSessionCacheTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var options = (IOptionsMonitor<OpenIddictCoreOptions>) null!;
        var store = Mock.Of<IOpenIddictSessionStore<object>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictSessionCache<object>(options, store));

        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullStore()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = (IOpenIddictSessionStore<object>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictSessionCache<object>(options, store));

        Assert.Equal("store", exception.ParamName);
    }

    [Fact]
    public async Task AddAsync_ThrowsAnExceptionForNullsession()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<OpenIddictSession>>();
        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.AddAsync(session: null!, CancellationToken.None).AsTask());

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<OpenIddictSession>>();
        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store);

        // Act and assert
        cache.Dispose();
        cache.Dispose();
    }

    [Fact]
    public async Task FindByApplicationIdAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var sessions = new[]
        {
            new OpenIddictSession(),
            new OpenIddictSession()
        };
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictSessionStore<OpenIddictSession>>();

        store.Setup(store => store.GetIdAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("session-id-1");
        store.Setup(store => store.GetApplicationIdAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");
        store.Setup(store => store.GetAuthorizationIdAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetSubjectAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        store.Setup(store => store.GetIdAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("session-id-2");
        store.Setup(store => store.GetApplicationIdAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("application-id");
        store.Setup(store => store.GetAuthorizationIdAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetSubjectAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        store.Setup(store => store.FindByApplicationIdAsync("application-id", It.IsAny<CancellationToken>()))
             .Returns(sessions.ToAsyncEnumerable());

        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store.Object);

        // Act
        var results = await cache.FindByApplicationIdAsync("application-id", CancellationToken.None).ToListAsync();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(sessions[0], results);
        Assert.Contains(sessions[1], results);
        store.Verify(store => store.FindByApplicationIdAsync("application-id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByApplicationIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<OpenIddictSession>>();
        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => cache.FindByApplicationIdAsync(identifier: null!, CancellationToken.None));

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByApplicationIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<OpenIddictSession>>();
        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(
            () => cache.FindByApplicationIdAsync(identifier: string.Empty, CancellationToken.None));

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByAuthorizationIdAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var sessions = new[]
        {
            new OpenIddictSession(),
            new OpenIddictSession()
        };
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictSessionStore<OpenIddictSession>>();

        store.Setup(store => store.GetIdAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("session-id-1");
        store.Setup(store => store.GetApplicationIdAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetAuthorizationIdAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("authorization-id");
        store.Setup(store => store.GetSubjectAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        store.Setup(store => store.GetIdAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("session-id-2");
        store.Setup(store => store.GetApplicationIdAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetAuthorizationIdAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("authorization-id");
        store.Setup(store => store.GetSubjectAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        store.Setup(store => store.FindByAuthorizationIdAsync("authorization-id", It.IsAny<CancellationToken>()))
             .Returns(sessions.ToAsyncEnumerable());

        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store.Object);

        // Act
        var results = await cache.FindByAuthorizationIdAsync("authorization-id", CancellationToken.None).ToListAsync();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(sessions[0], results);
        Assert.Contains(sessions[1], results);
        store.Verify(store => store.FindByAuthorizationIdAsync("authorization-id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByAuthorizationIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<OpenIddictSession>>();
        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => cache.FindByAuthorizationIdAsync(identifier: null!, CancellationToken.None));

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByAuthorizationIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<OpenIddictSession>>();
        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(
            () => cache.FindByAuthorizationIdAsync(identifier: string.Empty, CancellationToken.None));

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<OpenIddictSession>>();
        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store);

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
        var store = Mock.Of<IOpenIddictSessionStore<OpenIddictSession>>();
        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => cache.FindByIdAsync(identifier: string.Empty, CancellationToken.None).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsCachedsessionOnCacheHit()
    {
        // Arrange
        var session = new OpenIddictSession();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictSessionStore<OpenIddictSession>>();

        store.Setup(store => store.GetIdAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync("session-id");

        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store.Object);

        await cache.AddAsync(session, CancellationToken.None);

        // Act
        var result = await cache.FindByIdAsync("session-id", CancellationToken.None);

        // Assert
        Assert.Same(session, result);
        store.Verify(store => store.FindByIdAsync("session-id", It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByIdAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var session = new OpenIddictSession();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictSessionStore<OpenIddictSession>>();

        store.Setup(store => store.FindByIdAsync("session-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(session);
        store.Setup(store => store.GetIdAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync("session-id");

        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store.Object);

        // Act
        var result = await cache.FindByIdAsync("session-id", CancellationToken.None);

        // Assert
        Assert.Same(session, result);
        store.Verify(store => store.FindByIdAsync("session-id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByIdAsync_ReturnsNullWhensessionNotFound()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictSessionStore<OpenIddictSession>>();

        store.Setup(store => store.FindByIdAsync("session-id", It.IsAny<CancellationToken>()))
             .ReturnsAsync((OpenIddictSession?) null);

        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store.Object);

        // Act
        var result = await cache.FindByIdAsync("session-id", CancellationToken.None);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task FindByLoginIdAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var sessions = new[]
        {
            new OpenIddictSession(),
            new OpenIddictSession()
        };
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictSessionStore<OpenIddictSession>>();

        store.Setup(store => store.GetIdAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("session-id-1");
        store.Setup(store => store.GetApplicationIdAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetAuthorizationIdAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetLoginIdAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("login-id");
        store.Setup(store => store.GetSubjectAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("subject");

        store.Setup(store => store.GetIdAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("session-id-2");
        store.Setup(store => store.GetApplicationIdAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetAuthorizationIdAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetLoginIdAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("login-id");
        store.Setup(store => store.GetSubjectAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("subject");

        store.Setup(store => store.FindByLoginIdAsync("login-id", It.IsAny<CancellationToken>()))
             .Returns(sessions.ToAsyncEnumerable());

        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store.Object);

        // Act
        var results = await cache.FindByLoginIdAsync("login-id", CancellationToken.None).ToListAsync();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(sessions[0], results);
        Assert.Contains(sessions[1], results);
        store.Verify(store => store.FindByLoginIdAsync("login-id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByLoginIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<OpenIddictSession>>();
        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => cache.FindByLoginIdAsync(identifier: null!, CancellationToken.None));

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByLoginIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<OpenIddictSession>>();
        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(
            () => cache.FindByLoginIdAsync(identifier: string.Empty, CancellationToken.None));

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindBySubjectAsync_QueriesStoreOnCacheMiss()
    {
        // Arrange
        var sessions = new[]
        {
            new OpenIddictSession(),
            new OpenIddictSession()
        };
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictSessionStore<OpenIddictSession>>();

        store.Setup(store => store.GetIdAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("session-id-1");
        store.Setup(store => store.GetApplicationIdAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetAuthorizationIdAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetSubjectAsync(sessions[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("subject");

        store.Setup(store => store.GetIdAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("session-id-2");
        store.Setup(store => store.GetApplicationIdAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetAuthorizationIdAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);
        store.Setup(store => store.GetSubjectAsync(sessions[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("subject");

        store.Setup(store => store.FindBySubjectAsync("subject", It.IsAny<CancellationToken>()))
             .Returns(sessions.ToAsyncEnumerable());

        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store.Object);

        // Act
        var results = await cache.FindBySubjectAsync("subject", CancellationToken.None).ToListAsync();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(sessions[0], results);
        Assert.Contains(sessions[1], results);
        store.Verify(store => store.FindBySubjectAsync("subject", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindBySubjectAsync_ThrowsAnExceptionForNullSubject()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<OpenIddictSession>>();
        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => cache.FindBySubjectAsync(subject: null!, CancellationToken.None));

        Assert.Equal("subject", exception.ParamName);
    }

    [Fact]
    public async Task FindBySubjectAsync_ThrowsAnExceptionForEmptySubject()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<OpenIddictSession>>();
        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(
            () => cache.FindBySubjectAsync(subject: string.Empty, CancellationToken.None));

        Assert.Equal("subject", exception.ParamName);
    }

    [Fact]
    public async Task RemoveAsync_ThrowsAnExceptionForNullsession()
    {
        // Arrange
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictSessionStore<OpenIddictSession>>();
        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.RemoveAsync(session: null!, CancellationToken.None).AsTask());

        Assert.Equal("session", exception.ParamName);
    }

    [Fact]
    public async Task RemoveAsync_InvalidatesCachedEntries()
    {
        // Arrange
        var session = new OpenIddictSession();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictSessionStore<OpenIddictSession>>();

        store.Setup(store => store.GetIdAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync("session-id");

        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store.Object);

        await cache.AddAsync(session, CancellationToken.None);

        // Act
        await cache.RemoveAsync(session, CancellationToken.None);

        var result = await cache.FindByIdAsync("session-id", CancellationToken.None);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task RemoveAsync_ThrowsForsessionWithoutId()
    {
        // Arrange
        var session = new OpenIddictSession();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictSessionStore<OpenIddictSession>>();

        store.Setup(store => store.GetIdAsync(session, It.IsAny<CancellationToken>()))
             .ReturnsAsync((string?) null);

        var cache = new OpenIddictSessionCache<OpenIddictSession>(options, store.Object);

        // Act and assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => cache.RemoveAsync(session, CancellationToken.None).AsTask());
    }

    public sealed class OpenIddictSession;
}
