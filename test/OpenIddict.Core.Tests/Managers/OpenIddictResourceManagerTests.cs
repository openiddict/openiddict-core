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

public class OpenIddictResourceManagerTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullCache()
    {
        // Arrange
        var cache = (IOpenIddictResourceCache<CustomResource>) null!;
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictResourceManager<CustomResource>(cache, logger, options, store));

        Assert.Equal("cache", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullLogger()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = (ILogger<OpenIddictResourceManager<CustomResource>>) null!;
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictResourceManager<CustomResource>(cache, logger, options, store));

        Assert.Equal("logger", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = (IOptionsMonitor<OpenIddictCoreOptions>) null!;
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictResourceManager<CustomResource>(cache, logger, options, store));

        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForNullStore()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = (IOpenIddictResourceStore<CustomResource>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => new OpenIddictResourceManager<CustomResource>(cache, logger, options, store));

        Assert.Equal("store", exception.ParamName);
    }

    [Fact]
    public async Task CountAsync_CallsStoreMethod()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictResourceStore<CustomResource>>();

        store.Setup(store => store.CountAsync(It.IsAny<CancellationToken>()))
             .ReturnsAsync(42);

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store.Object);

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
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.CountAsync<CustomResource>(query: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task CreateAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.CreateAsync(resource: null!).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task DeleteAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.DeleteAsync(resource: null!).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task DeleteAsync_RemovesResourceFromCache_WhenCachingIsEnabled()
    {
        // Arrange
        var cache = new Mock<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = false });
        var store = new Mock<IOpenIddictResourceStore<CustomResource>>();
        var resource = new CustomResource();

        var manager = new OpenIddictResourceManager<CustomResource>(cache.Object, logger, options, store.Object);

        // Act
        await manager.DeleteAsync(resource);

        // Assert
        cache.Verify(cache => cache.RemoveAsync(resource, It.IsAny<CancellationToken>()), Times.Once());
        store.Verify(store => store.DeleteAsync(resource, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task DeleteAsync_DoesNotRemoveFromCache_WhenCachingIsDisabled()
    {
        // Arrange
        var cache = new Mock<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictResourceStore<CustomResource>>();
        var resource = new CustomResource();

        var manager = new OpenIddictResourceManager<CustomResource>(cache.Object, logger, options, store.Object);

        // Act
        await manager.DeleteAsync(resource);

        // Assert
        cache.Verify(cache => cache.RemoveAsync(It.IsAny<CustomResource>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(store => store.DeleteAsync(resource, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForNullIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.FindByIdAsync(identifier: null!).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_ThrowsAnExceptionForEmptyIdentifier()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.FindByIdAsync(identifier: string.Empty).AsTask());

        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public async Task FindByIdAsync_UsesCache_WhenCachingIsEnabled()
    {
        // Arrange
        var resource = new CustomResource();
        var cache = new Mock<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = false });
        var store = new Mock<IOpenIddictResourceStore<CustomResource>>();

        cache.Setup(cache => cache.FindByIdAsync("id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(resource);

        store.Setup(store => store.GetIdAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("id");

        var manager = new OpenIddictResourceManager<CustomResource>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByIdAsync("id");

        // Assert
        Assert.Same(resource, result);
        cache.Verify(cache => cache.FindByIdAsync("id", It.IsAny<CancellationToken>()), Times.Once());
        store.Verify(store => store.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task FindByIdAsync_UsesStore_WhenCachingIsDisabled()
    {
        // Arrange
        var resource = new CustomResource();
        var cache = new Mock<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions { DisableEntityCaching = true });
        var store = new Mock<IOpenIddictResourceStore<CustomResource>>();

        store.Setup(store => store.FindByIdAsync("id", It.IsAny<CancellationToken>()))
             .ReturnsAsync(resource);

        store.Setup(store => store.GetIdAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("id");

        var manager = new OpenIddictResourceManager<CustomResource>(cache.Object, logger, options, store.Object);

        // Act
        var result = await manager.FindByIdAsync("id");

        // Assert
        Assert.Same(resource, result);
        cache.Verify(cache => cache.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
        store.Verify(store => store.FindByIdAsync("id", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByNameAsync_ThrowsAnExceptionForNullName()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.FindByNameAsync(name: null!).AsTask());

        Assert.Equal("name", exception.ParamName);
    }

    [Fact]
    public async Task FindByNameAsync_ThrowsAnExceptionForEmptyName()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => manager.FindByNameAsync(name: string.Empty).AsTask());

        Assert.Equal("name", exception.ParamName);
    }

    [Fact]
    public async Task FindByNamesAsync_ReturnsEmptyWhenNoResourcesMatch()
    {
        // Arrange
        var cache = new Mock<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        cache.Setup(cache => cache.FindByNamesAsync(It.IsAny<ImmutableArray<string>>(), It.IsAny<CancellationToken>()))
             .Returns((ImmutableArray<string> names, CancellationToken cancellationToken) =>
             {
                 return Enumerable.Empty<CustomResource>().ToAsyncEnumerable();
             });

        var manager = new OpenIddictResourceManager<CustomResource>(cache.Object, logger, options, store);

        // Act
        var results = new List<CustomResource>();
        await foreach (var resource in manager.FindByNamesAsync(["resource1", "resource2"]))
        {
            results.Add(resource);
        }

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public async Task GetAsync_WithQuery_ThrowsAnExceptionForNullQuery()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetAsync<CustomResource>(query: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task GetAsync_WithQueryAndState_ThrowsAnExceptionForNullQuery()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetAsync<object, CustomResource>(query: null!, state: null!).AsTask());

        Assert.Equal("query", exception.ParamName);
    }

    [Fact]
    public async Task GetDescriptionAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetDescriptionAsync(resource: null!).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task GetDescriptionsAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetDescriptionsAsync(resource: null!).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task GetDisplayNameAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetDisplayNameAsync(resource: null!).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task GetDisplayNamesAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetDisplayNamesAsync(resource: null!).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task GetIdAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetIdAsync(resource: null!).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task GetIdAsync_ReturnsIdentifierFromStore()
    {
        // Arrange
        var resource = new CustomResource();
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictResourceStore<CustomResource>>();

        store.Setup(store => store.GetIdAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("unique-resource-id");

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store.Object);

        // Act
        var id = await manager.GetIdAsync(resource);

        // Assert
        Assert.Equal("unique-resource-id", id);
        store.Verify(store => store.GetIdAsync(resource, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetLocalizedDescriptionAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetLocalizedDescriptionAsync(resource: null!, CultureInfo.InvariantCulture).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task GetLocalizedDescriptionAsync_ReturnsDescriptionForMatchingCulture()
    {
        // Arrange
        var resource = new CustomResource();
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictResourceStore<CustomResource>>();

        store.Setup(store => store.GetDescriptionsAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ImmutableDictionary.Create<CultureInfo, string>()
                 .Add(CultureInfo.GetCultureInfo("en-US"), "English description")
                 .Add(CultureInfo.GetCultureInfo("fr-FR"), "Description française"));

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store.Object);

        // Act
        var description = await manager.GetLocalizedDescriptionAsync(resource, CultureInfo.GetCultureInfo("fr-FR"));

        // Assert
        Assert.Equal("Description française", description);
    }

    [Fact]
    public async Task GetLocalizedDescriptionAsync_FallsBackToNonLocalizedDescriptionWhenNoCultureMatches()
    {
        // Arrange
        var resource = new CustomResource();
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictResourceStore<CustomResource>>();

        store.Setup(store => store.GetDescriptionsAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ImmutableDictionary.Create<CultureInfo, string>()
                 .Add(CultureInfo.GetCultureInfo("en-US"), "English description"));

        store.Setup(store => store.GetDescriptionAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("Default description");

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store.Object);

        // Act
        var description = await manager.GetLocalizedDescriptionAsync(resource, CultureInfo.GetCultureInfo("ja-JP"));

        // Assert
        Assert.Equal("Default description", description);
    }

    [Fact]
    public async Task GetLocalizedDisplayNameAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetLocalizedDisplayNameAsync(resource: null!, CultureInfo.InvariantCulture).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task GetLocalizedDisplayNameAsync_ReturnsDisplayNameForMatchingCulture()
    {
        // Arrange
        var resource = new CustomResource();
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = new Mock<IOpenIddictResourceStore<CustomResource>>();

        store.Setup(store => store.GetDisplayNamesAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync(ImmutableDictionary.Create<CultureInfo, string>()
                 .Add(CultureInfo.GetCultureInfo("en-US"), "English name")
                 .Add(CultureInfo.GetCultureInfo("fr-FR"), "Nom fran�ais"));

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store.Object);

        // Act
        var name = await manager.GetLocalizedDisplayNameAsync(resource, CultureInfo.GetCultureInfo("fr-FR"));

        // Assert
        Assert.Equal("Nom fran�ais", name);
    }

    [Fact]
    public async Task GetNameAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetNameAsync(resource: null!).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task GetPropertiesAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.GetPropertiesAsync(resource: null!).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task ListAsync_ReturnsAllResources()
    {
        // Arrange
        var resources = new[] { new CustomResource(), new CustomResource() };
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictResourceStore<CustomResource>>();

        store.Setup(store => store.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()))
             .Returns(resources.ToAsyncEnumerable());

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store.Object);

        // Act
        var results = new List<CustomResource>();
        await foreach (var scp in manager.ListAsync())
        {
            results.Add(scp);
        }

        // Assert
        Assert.Equal(2, results.Count);
        store.Verify(store => store.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task PopulateAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);
        var descriptor = new OpenIddictResourceDescriptor();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.PopulateAsync(resource: null!, descriptor).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task PopulateAsync_ThrowsAnExceptionForNullDescriptor()
    {
        // Arrange
        var resource = new CustomResource();
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.PopulateAsync(resource, descriptor: null!).AsTask());

        Assert.Equal("descriptor", exception.ParamName);
    }

    [Fact]
    public async Task UpdateAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.UpdateAsync(resource: null!).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task UpdateAsync_WithDescriptor_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);
        var descriptor = new OpenIddictResourceDescriptor();

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(
            () => manager.UpdateAsync(resource: null!, descriptor).AsTask());

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public void ValidateAsync_ThrowsAnExceptionForNullResource()
    {
        // Arrange
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>();
        var store = Mock.Of<IOpenIddictResourceStore<CustomResource>>();

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => manager.ValidateAsync(resource: null!));

        Assert.Equal("resource", exception.ParamName);
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenNameIsEmpty()
    {
        // Arrange
        var resource = new CustomResource();
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictResourceStore<CustomResource>>();

        store.Setup(store => store.GetNameAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync(string.Empty);

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(resource).ToListAsync();

        // Assert
        Assert.Contains(results, result => string.Equals(result.ErrorMessage, SR.GetResourceString(SR.ID2206), StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("resource")]
    [InlineData("/resource")]
    [InlineData("urn:resource#fragment")]
    public async Task ValidateAsync_ReturnsErrorWhenNameIsNotValidUri(string name)
    {
        // Arrange
        var resource = new CustomResource();
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictResourceStore<CustomResource>>();

        store.Setup(store => store.GetNameAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync(name);

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(resource).ToListAsync();

        // Assert
        Assert.Contains(results, result => string.Equals(result.ErrorMessage, SR.GetResourceString(SR.ID2207), StringComparison.Ordinal));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsErrorWhenNameIsAlreadyUsed()
    {
        // Arrange
        var resource = new CustomResource();
        var other = new CustomResource();
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictResourceStore<CustomResource>>();

        store.Setup(store => store.GetNameAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("urn:resource");

        store.Setup(store => store.FindByNameAsync("urn:resource", It.IsAny<CancellationToken>()))
             .ReturnsAsync(other);

        store.Setup(store => store.GetIdAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("urn:resource-id");

        store.Setup(store => store.GetIdAsync(other, It.IsAny<CancellationToken>()))
             .ReturnsAsync("urn:other-resource-id");

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(resource).ToListAsync();

        // Assert
        Assert.Contains(results, result => string.Equals(result.ErrorMessage, SR.GetResourceString(SR.ID2208), StringComparison.Ordinal));
    }

    [Fact]
    public async Task ValidateAsync_ReturnsNoErrorsForValidResource()
    {
        // Arrange
        var resource = new CustomResource();
        var cache = Mock.Of<IOpenIddictResourceCache<CustomResource>>();
        var logger = Mock.Of<ILogger<OpenIddictResourceManager<CustomResource>>>();
        var options = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            mock => mock.CurrentValue == new OpenIddictCoreOptions());
        var store = new Mock<IOpenIddictResourceStore<CustomResource>>();

        store.Setup(store => store.GetNameAsync(resource, It.IsAny<CancellationToken>()))
             .ReturnsAsync("urn:resource");

        store.Setup(store => store.FindByNameAsync("urn:resource", It.IsAny<CancellationToken>()))
             .ReturnsAsync((CustomResource?) null);

        var manager = new OpenIddictResourceManager<CustomResource>(cache, logger, options, store.Object);

        // Act
        var results = await manager.ValidateAsync(resource).ToListAsync();

        // Assert
        Assert.DoesNotContain(results, static result => result != ValidationResult.Success);
    }

    public class CustomResource;
}
