/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Core;
using OpenIddict.Server.SystemNetHttp;
using Xunit;

namespace OpenIddict.Server.SystemNetHttp.Tests;

public class OpenIddictServerSystemNetHttpApplicationManagerTests
{
    [Fact]
    public async Task FindByClientIdAsync_ReturnsBaseResult_WhenPreRegisteredClientExists()
    {
        // Arrange
        var application = new TestApplication();
        var store = CreateStore();
        store.Setup(s => s.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
            .ReturnsAsync(application);

        var cimdContext = new OpenIddictServerSystemNetHttpCimdContext();
        var manager = CreateManager(store, cimdContext);

        // Act
        var result = await manager.FindByClientIdAsync("Fabrikam");

        // Assert
        Assert.Same(application, result);
    }

    [Fact]
    public async Task FindByClientIdAsync_ReturnsNull_WhenNoCimdContext()
    {
        // Arrange
        var store = CreateStore();
        store.Setup(s => s.FindByClientIdAsync("https://example.com/client", It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestApplication?) null);

        var cimdContext = new OpenIddictServerSystemNetHttpCimdContext();
        var manager = CreateManager(store, cimdContext);

        // Act
        var result = await manager.FindByClientIdAsync("https://example.com/client");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task FindByClientIdAsync_ReturnsNull_WhenCimdClientIdDoesNotMatch()
    {
        // Arrange
        var store = CreateStore();
        store.Setup(s => s.FindByClientIdAsync("https://example.com/client-a", It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestApplication?) null);

        var cimdContext = new OpenIddictServerSystemNetHttpCimdContext
        {
            ClientId = "https://example.com/client-b",
            MetadataDocument = CreateMetadataDocument()
        };

        var manager = CreateManager(store, cimdContext);

        // Act
        var result = await manager.FindByClientIdAsync("https://example.com/client-a");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task FindByClientIdAsync_SynthesizesVirtualApp_WhenCimdContextPopulated()
    {
        // Arrange
        var store = CreateStore();
        store.Setup(s => s.FindByClientIdAsync("https://example.com/client", It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestApplication?) null);

        using var document = CreateMetadataDocument("""
        {
            "client_id": "https://example.com/client",
            "client_name": "Test Client"
        }
        """);

        var cimdContext = new OpenIddictServerSystemNetHttpCimdContext
        {
            ClientId = "https://example.com/client",
            MetadataDocument = document
        };

        var manager = CreateManager(store, cimdContext);

        // Act
        var result = await manager.FindByClientIdAsync("https://example.com/client");

        // Assert
        Assert.NotNull(result);
        store.Verify(s => s.SetClientIdAsync(result, "https://example.com/client", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByClientIdAsync_ReturnsCachedVirtualApp_OnSecondCall()
    {
        // Arrange
        var store = CreateStore();
        store.Setup(s => s.FindByClientIdAsync("https://example.com/client", It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestApplication?) null);

        using var document = CreateMetadataDocument();

        var cimdContext = new OpenIddictServerSystemNetHttpCimdContext
        {
            ClientId = "https://example.com/client",
            MetadataDocument = document
        };

        var manager = CreateManager(store, cimdContext);

        // Act
        var first = await manager.FindByClientIdAsync("https://example.com/client");
        var second = await manager.FindByClientIdAsync("https://example.com/client");

        // Assert
        Assert.NotNull(first);
        Assert.Same(first, second);
        store.Verify(s => s.InstantiateAsync(It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByClientIdAsync_SynthesizedApp_HasCorrectClientType()
    {
        // Arrange
        var (manager, store, _) = CreateManagerWithCimdContext();

        // Act
        var result = await manager.FindByClientIdAsync("https://example.com/client");

        // Assert
        Assert.NotNull(result);
        store.Verify(s => s.SetClientTypeAsync(result, ClientTypes.Public, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByClientIdAsync_SynthesizedApp_HasCorrectApplicationType()
    {
        // Arrange
        using var document = CreateMetadataDocument("""
        {
            "application_type": "native"
        }
        """);

        var (manager, store, _) = CreateManagerWithCimdContext(document);

        // Act
        var result = await manager.FindByClientIdAsync("https://example.com/client");

        // Assert
        Assert.NotNull(result);
        store.Verify(s => s.SetApplicationTypeAsync(result, "native", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByClientIdAsync_SynthesizedApp_DefaultsToWebApplicationType()
    {
        // Arrange
        using var document = CreateMetadataDocument("{}");
        var (manager, store, _) = CreateManagerWithCimdContext(document);

        // Act
        var result = await manager.FindByClientIdAsync("https://example.com/client");

        // Assert
        Assert.NotNull(result);
        store.Verify(s => s.SetApplicationTypeAsync(result, ApplicationTypes.Web, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByClientIdAsync_SynthesizedApp_HasCorrectDisplayName()
    {
        // Arrange
        using var document = CreateMetadataDocument("""
        {
            "client_name": "My Cool App"
        }
        """);

        var (manager, store, _) = CreateManagerWithCimdContext(document);

        // Act
        var result = await manager.FindByClientIdAsync("https://example.com/client");

        // Assert
        Assert.NotNull(result);
        store.Verify(s => s.SetDisplayNameAsync(result, "My Cool App", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByClientIdAsync_SynthesizedApp_HasCorrectRedirectUris()
    {
        // Arrange
        using var document = CreateMetadataDocument("""
        {
            "redirect_uris": ["https://example.com/callback", "https://example.com/callback2"]
        }
        """);

        var (manager, store, _) = CreateManagerWithCimdContext(document);

        // Act
        var result = await manager.FindByClientIdAsync("https://example.com/client");

        // Assert
        Assert.NotNull(result);
        store.Verify(s => s.SetRedirectUrisAsync(
            result,
            It.Is<ImmutableArray<string>>(uris =>
                uris.Length == 2 &&
                uris[0] == "https://example.com/callback" &&
                uris[1] == "https://example.com/callback2"),
            It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByClientIdAsync_SynthesizedApp_HasCorrectGrantTypePermissions()
    {
        // Arrange
        using var document = CreateMetadataDocument("""
        {
            "grant_types": ["authorization_code", "refresh_token"]
        }
        """);

        var (manager, store, _) = CreateManagerWithCimdContext(document);

        // Act
        var result = await manager.FindByClientIdAsync("https://example.com/client");

        // Assert
        Assert.NotNull(result);
        store.Verify(s => s.SetPermissionsAsync(
            result,
            It.Is<ImmutableArray<string>>(perms =>
                perms.Contains(Permissions.GrantTypes.AuthorizationCode) &&
                perms.Contains(Permissions.GrantTypes.RefreshToken)),
            It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByClientIdAsync_SynthesizedApp_DefaultsToAuthorizationCodeGrant()
    {
        // Arrange — no grant_types in metadata
        using var document = CreateMetadataDocument("{}");
        var (manager, store, _) = CreateManagerWithCimdContext(document);

        // Act
        var result = await manager.FindByClientIdAsync("https://example.com/client");

        // Assert
        Assert.NotNull(result);
        store.Verify(s => s.SetPermissionsAsync(
            result,
            It.Is<ImmutableArray<string>>(perms =>
                perms.Contains(Permissions.GrantTypes.AuthorizationCode)),
            It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByClientIdAsync_SynthesizedApp_HasCorrectResponseTypePermissions()
    {
        // Arrange
        using var document = CreateMetadataDocument("""
        {
            "response_types": ["code", "code id_token"]
        }
        """);

        var (manager, store, _) = CreateManagerWithCimdContext(document);

        // Act
        var result = await manager.FindByClientIdAsync("https://example.com/client");

        // Assert
        Assert.NotNull(result);
        store.Verify(s => s.SetPermissionsAsync(
            result,
            It.Is<ImmutableArray<string>>(perms =>
                perms.Contains(Permissions.ResponseTypes.Code) &&
                perms.Contains(Permissions.ResponseTypes.CodeIdToken)),
            It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByClientIdAsync_SynthesizedApp_DefaultsToCodeResponseType()
    {
        // Arrange — no response_types in metadata
        using var document = CreateMetadataDocument("{}");
        var (manager, store, _) = CreateManagerWithCimdContext(document);

        // Act
        var result = await manager.FindByClientIdAsync("https://example.com/client");

        // Assert
        Assert.NotNull(result);
        store.Verify(s => s.SetPermissionsAsync(
            result,
            It.Is<ImmutableArray<string>>(perms =>
                perms.Contains(Permissions.ResponseTypes.Code)),
            It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByClientIdAsync_SynthesizedApp_RequiresPkce()
    {
        // Arrange
        var (manager, store, _) = CreateManagerWithCimdContext();

        // Act
        var result = await manager.FindByClientIdAsync("https://example.com/client");

        // Assert
        Assert.NotNull(result);
        store.Verify(s => s.SetRequirementsAsync(
            result,
            It.Is<ImmutableArray<string>>(reqs =>
                reqs.Contains(Requirements.Features.ProofKeyForCodeExchange)),
            It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task GetIdAsync_ReturnsNull_ForVirtualApplication()
    {
        // Arrange
        var (manager, _, cimdContext) = CreateManagerWithCimdContext();

        var virtualApp = await manager.FindByClientIdAsync("https://example.com/client");
        Assert.NotNull(virtualApp);

        // Act
        var id = await manager.GetIdAsync(virtualApp);

        // Assert
        Assert.Null(id);
    }

    [Fact]
    public async Task GetIdAsync_DelegatesToBase_ForNonVirtualApplication()
    {
        // Arrange
        var regularApp = new TestApplication();
        var store = CreateStore();
        store.Setup(s => s.GetIdAsync(regularApp, It.IsAny<CancellationToken>()))
            .ReturnsAsync("some-id");

        var cimdContext = new OpenIddictServerSystemNetHttpCimdContext();
        var manager = CreateManager(store, cimdContext);

        // Act
        var id = await manager.GetIdAsync(regularApp);

        // Assert
        Assert.Equal("some-id", id);
    }

    [Fact]
    public async Task FindByClientIdAsync_SynthesizedApp_HasEndpointPermissions()
    {
        // Arrange
        var (manager, store, _) = CreateManagerWithCimdContext();

        // Act
        var result = await manager.FindByClientIdAsync("https://example.com/client");

        // Assert
        Assert.NotNull(result);
        store.Verify(s => s.SetPermissionsAsync(
            result,
            It.Is<ImmutableArray<string>>(perms =>
                perms.Contains(Permissions.Endpoints.Authorization) &&
                perms.Contains(Permissions.Endpoints.Token)),
            It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task FindByClientIdAsync_SynthesizedApp_HasScopePermissions()
    {
        // Arrange
        var (manager, store, _) = CreateManagerWithCimdContext();

        // Act
        var result = await manager.FindByClientIdAsync("https://example.com/client");

        // Assert
        Assert.NotNull(result);
        store.Verify(s => s.SetPermissionsAsync(
            result,
            It.Is<ImmutableArray<string>>(perms =>
                perms.Contains(Permissions.Scopes.Email) &&
                perms.Contains(Permissions.Scopes.Profile) &&
                perms.Contains(Permissions.Scopes.Address) &&
                perms.Contains(Permissions.Scopes.Phone) &&
                perms.Contains(Permissions.Scopes.Roles)),
            It.IsAny<CancellationToken>()), Times.Once());
    }

    private static Mock<IOpenIddictApplicationStore<TestApplication>> CreateStore()
    {
        var store = new Mock<IOpenIddictApplicationStore<TestApplication>>();
        store.Setup(s => s.InstantiateAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new TestApplication());
        return store;
    }

    private static OpenIddictServerSystemNetHttpApplicationManager<TestApplication> CreateManager(
        Mock<IOpenIddictApplicationStore<TestApplication>> store,
        OpenIddictServerSystemNetHttpCimdContext cimdContext)
    {
        var cache = Mock.Of<IOpenIddictApplicationCache<TestApplication>>();
        var logger = NullLogger<OpenIddictApplicationManager<TestApplication>>.Instance;

        var coreOptions = new OpenIddictCoreOptions
        {
            DisableEntityCaching = true,
            DisableAdditionalFiltering = true
        };

        var optionsMonitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(
            m => m.CurrentValue == coreOptions);

        return new OpenIddictServerSystemNetHttpApplicationManager<TestApplication>(
            cache, logger, optionsMonitor, store.Object, cimdContext);
    }

    private static (OpenIddictServerSystemNetHttpApplicationManager<TestApplication> Manager,
                     Mock<IOpenIddictApplicationStore<TestApplication>> Store,
                     OpenIddictServerSystemNetHttpCimdContext CimdContext)
        CreateManagerWithCimdContext(JsonDocument? document = null)
    {
        var store = CreateStore();
        store.Setup(s => s.FindByClientIdAsync("https://example.com/client", It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestApplication?) null);

        var cimdContext = new OpenIddictServerSystemNetHttpCimdContext
        {
            ClientId = "https://example.com/client",
            MetadataDocument = document ?? CreateMetadataDocument()
        };

        var manager = CreateManager(store, cimdContext);
        return (manager, store, cimdContext);
    }

    private static JsonDocument CreateMetadataDocument(string? json = null)
        => JsonDocument.Parse(json ?? """{"client_id": "https://example.com/client"}""");

    public class TestApplication { }
}
