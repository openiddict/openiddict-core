/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace OpenIddict.Core.Tests;

public class OpenIddictScopeManagerTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullCache()
    {
        // Arrange
        var cache = (IOpenIddictScopeCache<CustomScope>) null!;
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictScopeManager<CustomScope>(cache, logger, options, store));

        Assert.Equal("cache", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullLogger()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = (ILogger<OpenIddictScopeManager<CustomScope>>) null!;
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictScopeManager<CustomScope>(cache, logger, options, store));

        Assert.Equal("logger", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = (IOptionsMonitor<OpenIddictCoreOptions>) null!;
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictScopeManager<CustomScope>(cache, logger, options, store));

        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullStore()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = (IOpenIddictScopeStore<CustomScope>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictScopeManager<CustomScope>(cache, logger, options, store));

        Assert.Equal("store", exception.ParamName);
    }

    [Fact]
    public async Task CountAsync_CallsStoreMethod()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictScopeStore<CustomScope>>();

        store.Setup(store => store.CountAsync(It.IsAny<CancellationToken>()))
             .ReturnsAsync(42);

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store.Object);

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
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.CountAsync<CustomScope>(query: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task CreateAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.CreateAsync(scope: null!).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task DeleteAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.DeleteAsync(scope: null!).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task DeleteAsync_RemovesScopeFromCache_WhenCachingIsEnabled()
    {
        // Arrange
        var cache = new Mock<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = false });
        var store = new Mock<IOpenIddictScopeStore<CustomScope>>();
        var scope = new CustomScope();

        var manager = new OpenIddictScopeManager<CustomScope>(cache.Object, logger, options, store.Object);

        // Act
        await manager.DeleteAsync(scope);

        // Assert
        cache.Verify(cache => cache.RemoveAsync(scope, It.IsAny<CancellationToken>()), Times.Once());
        store.Verify(store => store.DeleteAsync(scope, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task DeleteAsync_DoesNotRemoveFromCache_WhenCachingIsDisabled()
    {
        // Arrange
        var cache = new Mock<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictScopeStore<CustomScope>>();
        var scope = new CustomScope();

        var manager = new OpenIddictScopeManager<CustomScope>(cache.Object, logger, options, store.Object);

        // Act
        await manager.DeleteAsync(scope);

        // Assert
        cache.Verify(cache => cache.RemoveAsync(It.IsAny<CustomScope>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(store => store.DeleteAsync(scope, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.FindByIdAsync(identifier: null!).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.FindByIdAsync(identifier: string.Empty).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_UsesCache_WhenCachingIsEnabled()
    {
        // Arrange
        var scope = new CustomScope();
        var cache = new Mock<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = false });
        var store = new Mock<IOpenIddictScopeStore<CustomScope>>();

        cache.Setup(cache => cache.FindByIdAsync("id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(scope);

        store.Setup(store => store.GetIdAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("id");

        var manager = new OpenIddictScopeManager<CustomScope>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByIdAsync("id");

        // Assert
        Assert.Same(scope, result);
        cache.Verify(cache => cache.FindByIdAsync("id", It.IsAny<CancellationToken>()), Times.Once());
        store.Verify(store => store.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByIdAsync_UsesStore_WhenCachingIsDisabled()
    {
        // Arrange
        var scope = new CustomScope();
        var cache = new Mock<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictScopeStore<CustomScope>>();

        store.Setup(store => store.FindByIdAsync("id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(scope);

        store.Setup(store => store.GetIdAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("id");

        var manager = new OpenIddictScopeManager<CustomScope>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByIdAsync("id");

        // Assert
        Assert.Same(scope, result);
        cache.Verify(cache => cache.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(store => store.FindByIdAsync("id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByNameAsync_ThrowsAnExceptionForNullName()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.FindByNameAsync(name: null!).AsTask());

        Assert.Equal("name", exception.ParamName);
    }

    [Fact]
    public async Task FindByNameAsync_ThrowsAnExceptionForEmptyName()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.FindByNameAsync(name: string.Empty).AsTask());

        Assert.Equal("name", exception.ParamName);
    }

    [Fact]
    public async Task FindByNamesAsync_ReturnsEmptyWhenNoScopesMatch()
    {
        // Arrange
        var cache = new Mock<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        cache.Setup(cache => cache.FindByNamesAsync(It.IsAny<ImmutableArray<string>>(), It.IsAny<CancellationToken>()))
             .Returns((ImmutableArray<string> names, CancellationToken cancellationToken) =>
             {
                 return Enumerable.Empty<CustomScope>().ToAsyncEnumerable();
             });

        var manager = new OpenIddictScopeManager<CustomScope>(cache.Object, logger, options, store);

        // Act
        var results = new List<CustomScope>();
        await foreach (var scope in manager.FindByNamesAsync(["scope1", "scope2"]))
        {
            results.Add(scope);
        }

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public void FindByResourceAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => manager.FindByResourceAsync(resource: null!));

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public void FindByResourceAsync_ThrowsAnExceptionForEmptyResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(
            () => manager.FindByResourceAsync(resource: string.Empty));

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task GetAsync_WithQuery_ThrowsAnExceptionForNullQuery()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetAsync<CustomScope>(query: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task GetAsync_WithQueryAndState_ThrowsAnExceptionForNullQuery()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetAsync<object, CustomScope>(query: null!, state: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task GetDescriptionAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetDescriptionAsync(scope: null!).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task GetDescriptionsAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetDescriptionsAsync(scope: null!).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task GetDisplayNameAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetDisplayNameAsync(scope: null!).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task GetDisplayNamesAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetDisplayNamesAsync(scope: null!).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task GetIdAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetIdAsync(scope: null!).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task GetIdAsync_ReturnsIdentifierFromStore()
    {
        // Arrange
        var scope = new CustomScope();
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictScopeStore<CustomScope>>();

        store.Setup(store => store.GetIdAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("unique-scope-id");

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store.Object);

        // Act
        var id = await manager.GetIdAsync(scope);

        // Assert
        Assert.Equal("unique-scope-id", id);
        store.Verify(store => store.GetIdAsync(scope, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetLocalizedDescriptionAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetLocalizedDescriptionAsync(scope: null!, CultureInfo.InvariantCulture).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task GetLocalizedDescriptionAsync_ReturnsDescriptionForMatchingCulture()
    {
        // Arrange
        var scope = new CustomScope();
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictScopeStore<CustomScope>>();

        store.Setup(store => store.GetDescriptionsAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ImmutableDictionary.Create<CultureInfo, string>()
                 .Add(CultureInfo.GetCultureInfo("en-US"), "English description")
                 .Add(CultureInfo.GetCultureInfo("fr-FR"), "Description française"));

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store.Object);

        // Act
        var description = await manager.GetLocalizedDescriptionAsync(scope, CultureInfo.GetCultureInfo("fr-FR"));

        // Assert
        Assert.Equal("Description française", description);
    }

    [Fact]
    public async Task GetLocalizedDescriptionAsync_FallsBackToNonLocalizedDescriptionWhenNoCultureMatches()
    {
        // Arrange
        var scope = new CustomScope();
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictScopeStore<CustomScope>>();

        store.Setup(store => store.GetDescriptionsAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ImmutableDictionary.Create<CultureInfo, string>()
                 .Add(CultureInfo.GetCultureInfo("en-US"), "English description"));

        store.Setup(store => store.GetDescriptionAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("Default description");

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store.Object);

        // Act
        var description = await manager.GetLocalizedDescriptionAsync(scope, CultureInfo.GetCultureInfo("ja-JP"));

        // Assert
        Assert.Equal("Default description", description);
    }

    [Fact]
    public async Task GetLocalizedDisplayNameAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetLocalizedDisplayNameAsync(scope: null!, CultureInfo.InvariantCulture).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task GetLocalizedDisplayNameAsync_ReturnsDisplayNameForMatchingCulture()
    {
        // Arrange
        var scope = new CustomScope();
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictScopeStore<CustomScope>>();

        store.Setup(store => store.GetDisplayNamesAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ImmutableDictionary.Create<CultureInfo, string>()
                 .Add(CultureInfo.GetCultureInfo("en-US"), "English name")
                 .Add(CultureInfo.GetCultureInfo("fr-FR"), "Nom fran�ais"));

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store.Object);

        // Act
        var name = await manager.GetLocalizedDisplayNameAsync(scope, CultureInfo.GetCultureInfo("fr-FR"));

        // Assert
        Assert.Equal("Nom fran�ais", name);
    }

    [Fact]
    public async Task GetNameAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetNameAsync(scope: null!).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task GetPropertiesAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetPropertiesAsync(scope: null!).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task GetResourcesAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetResourcesAsync(scope: null!).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task ListAsync_ReturnsAllScopes()
    {
        // Arrange
        var scopes = new[] { new CustomScope(), new CustomScope() };
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictScopeStore<CustomScope>>();

        store.Setup(store => store.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()))
             .Returns(scopes.ToAsyncEnumerable());

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store.Object);

        // Act
        var results = new List<CustomScope>();
        await foreach (var scp in manager.ListAsync())
        {
            results.Add(scp);
        }

        // Assert
        Assert.Equal(2, results.Count);
        store.Verify(store => store.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ListResourcesAsync_ReturnsDeduplicatedResourcesFromMatchingScopes()
    {
        // Arrange
        var scopes = new[] { new CustomScope(), new CustomScope() };
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictScopeStore<CustomScope>>();

        store.Setup(store => store.FindByNamesAsync(It.IsAny<ImmutableArray<string>>(), It.IsAny<CancellationToken>()))
             .Returns(scopes.ToAsyncEnumerable());

        store.Setup(store => store.GetNameAsync(scopes[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync("openid");

        store.Setup(store => store.GetNameAsync(scopes[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync("profile");

        store.Setup(store => store.GetResourcesAsync(scopes[0], It.IsAny<CancellationToken>()))
             .ReturnsAsync(["resource1", "resource2"]);

        store.Setup(store => store.GetResourcesAsync(scopes[1], It.IsAny<CancellationToken>()))
             .ReturnsAsync(["resource2", "resource3"]);

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store.Object);

        // Act
        var resources = await manager.ListResourcesAsync(["openid", "profile"]).ToListAsync();

        // Assert
        Assert.Equal(3, resources.Count);
        Assert.Contains("resource1", resources);
        Assert.Contains("resource2", resources);
        Assert.Contains("resource3", resources);
    }

    [Fact]
    public async Task PopulateAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);
        var descriptor = new OpenIddictScopeDescriptor();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.PopulateAsync(scope: null!, descriptor).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task PopulateAsync_ThrowsAnExceptionForNullDescriptor()
    {
        // Arrange
        var scope = new CustomScope();
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.PopulateAsync(scope, descriptor: null!).AsTask());

        Assert.Equal("descriptor", exception.ParamName);
    }

    [Fact]
    public async Task UpdateAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.UpdateAsync(scope: null!).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task UpdateAsync_WithDescriptor_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);
        var descriptor = new OpenIddictScopeDescriptor();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.UpdateAsync(scope: null!, descriptor).AsTask());

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public void ValidateAsync_ThrowsAnExceptionForNullScope()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictScopeStore<CustomScope>>();

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => manager.ValidateAsync(scope: null!));

        Assert.Equal("scope", exception.ParamName);
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenNameIsEmpty()
    {
        // Arrange
        var scope = new CustomScope();
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictScopeStore<CustomScope>>();

        store.Setup(store => store.GetNameAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(scope).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2044));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenNameContainsSpace()
    {
        // Arrange
        var scope = new CustomScope();
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictScopeStore<CustomScope>>();

        store.Setup(store => store.GetNameAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope name with space");

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(scope).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2045));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenNameIsAlreadyUsed()
    {
        // Arrange
        var scope = new CustomScope();
        var other = new CustomScope();
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictScopeStore<CustomScope>>();

        store.Setup(store => store.GetNameAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("openid");

        store.Setup(store => store.FindByNameAsync("openid", It.IsAny<CancellationToken>()))
             .ReturnsAsync(other);

        store.Setup(store => store.GetIdAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("scope-id");

        store.Setup(store => store.GetIdAsync(other, It.IsAny<CancellationToken>()))
             .ReturnsAsync("other-scope-id");

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(scope).ToListAsync();

        // Assert
        Assert.Contains(results, result => result.ErrorMessage == SR.GetResourceString(SR.ID2060));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsNoErrorsForValidScope()
    {
        // Arrange
        var scope = new CustomScope();
        var cache = Mock.Of<IOpenIddictScopeCache<CustomScope>>();
        var logger = Mock.Of<ILogger<OpenIddictScopeManager<CustomScope>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictScopeStore<CustomScope>>();

        store.Setup(store => store.GetNameAsync(scope, It.IsAny<CancellationToken>()))
             .ReturnsAsync("openid");

        store.Setup(store => store.FindByNameAsync("openid", It.IsAny<CancellationToken>()))
             .ReturnsAsync((CustomScope?) null);

        var manager = new OpenIddictScopeManager<CustomScope>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(scope).ToListAsync();

        // Assert
        Assert.DoesNotContain(results, static result => result != ValidationResult.Success);
    }

    public class CustomScope;
}
