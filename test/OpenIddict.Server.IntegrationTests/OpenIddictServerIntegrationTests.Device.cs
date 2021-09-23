/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OpenIddict.Abstractions;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    [Theory]
    [InlineData(nameof(HttpMethod.Delete))]
    [InlineData(nameof(HttpMethod.Get))]
    [InlineData(nameof(HttpMethod.Head))]
    [InlineData(nameof(HttpMethod.Options))]
    [InlineData(nameof(HttpMethod.Put))]
    [InlineData(nameof(HttpMethod.Trace))]
    public async Task ExtractDeviceRequest_UnexpectedMethodReturnsAnError(string method)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendAsync(method, "/connect/device", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2084), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2084), response.ErrorUri);
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task ExtractDeviceRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractDeviceRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest());

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task ExtractDeviceRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractDeviceRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest());

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ExtractDeviceRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractDeviceRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest());

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Fact]
    public async Task ValidateDeviceRequest_MissingClientIdCausesAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = null
        });

        // Assert
        Assert.Equal(Errors.InvalidClient, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.ClientId), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateDeviceRequest_RequestWithOfflineAccessScopeIsRejectedWhenRefreshTokenFlowIsDisabled()
    {
        // Arrange
        var application = new OpenIddictApplication();

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            }));

            options.Configure(options => options.GrantTypes.Remove(GrantTypes.RefreshToken));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Scope = Scopes.OfflineAccess
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2035(Scopes.OfflineAccess), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2035), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateDeviceRequest_RequestIsRejectedWhenUnregisteredScopeIsSpecified()
    {
        // Arrange
        var application = new OpenIddictApplication();

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            }));

            options.Services.AddSingleton(CreateScopeManager(mock =>
            {
                mock.Setup(manager => manager.FindByNamesAsync(
                    It.Is<ImmutableArray<string>>(scopes => scopes.Length == 1 && scopes[0] == "unregistered_scope"),
                    It.IsAny<CancellationToken>()))
                    .Returns(AsyncEnumerable.Empty<OpenIddictScope>());
            }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Scope = "unregistered_scope"
        });

        // Assert
        Assert.Equal(Errors.InvalidScope, response.Error);
        Assert.Equal(SR.FormatID2052(Parameters.Scope), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2052), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateDeviceRequest_RequestIsValidatedWhenScopeRegisteredInOptionsIsSpecified()
    {
        // Arrange
        var application = new OpenIddictApplication();

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            }));

            options.RegisterScopes("registered_scope");
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.DisableAuthorizationStorage();
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.AddEventHandler<HandleDeviceRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity());

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Scope = "registered_scope"
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.DeviceCode);
        Assert.NotNull(response.UserCode);
    }

    [Fact]
    public async Task ValidateDeviceRequest_RequestIsValidatedWhenRegisteredScopeIsSpecified()
    {
        // Arrange
        var application = new OpenIddictApplication();
        var scope = new OpenIddictScope();

        var manager = CreateScopeManager(mock =>
        {
            mock.Setup(manager => manager.FindByNamesAsync(
                It.Is<ImmutableArray<string>>(scopes => scopes.Length == 1 && scopes[0] == "scope_registered_in_database"),
                It.IsAny<CancellationToken>()))
                .Returns(new[] { scope }.ToAsyncEnumerable());

            mock.Setup(manager => manager.GetNameAsync(scope, It.IsAny<CancellationToken>()))
                .ReturnsAsync("scope_registered_in_database");
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            }));

            options.RegisterScopes("scope_registered_in_options");
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.DisableAuthorizationStorage();
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Services.AddSingleton(manager);

            options.AddEventHandler<HandleDeviceRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity());

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Scope = "scope_registered_in_database scope_registered_in_options"
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.DeviceCode);
        Assert.NotNull(response.UserCode);
    }

    [Fact]
    public async Task ValidateDeviceRequest_RequestIsRejectedWhenClientCannotBeFound()
    {
        // Arrange
        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(value: null);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam"
        });

        // Assert
        Assert.Equal(Errors.InvalidClient, response.Error);
        Assert.Equal(SR.FormatID2052(Parameters.ClientId), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2052), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
    }

    [Fact]
    public async Task ValidateDeviceRequest_ClientSecretCannotBeUsedByPublicClients()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw"
        });

        // Assert
        Assert.Equal(Errors.InvalidClient, response.Error);
        Assert.Equal(SR.FormatID2053(Parameters.ClientSecret), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2053), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateDeviceRequest_ClientSecretIsRequiredForNonPublicClients()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            ClientSecret = null
        });

        // Assert
        Assert.Equal(Errors.InvalidClient, response.Error);
        Assert.Equal(SR.FormatID2054(Parameters.ClientSecret), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2054), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateDeviceRequest_RequestIsRejectedWhenClientCredentialsAreInvalid()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);

            mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw"
        });

        // Assert
        Assert.Equal(Errors.InvalidClient, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2055), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2055), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateDeviceRequest_RequestIsRejectedWhenEndpointPermissionIsNotGranted()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.Endpoints.Device, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);

            options.Configure(options => options.IgnoreEndpointPermissions = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam"
        });

        // Assert
        Assert.Equal(Errors.UnauthorizedClient, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2056), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2056), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.Endpoints.Device, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateDeviceRequest_RequestIsRejectedWhenGrantTypePermissionIsNotGranted()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.GrantTypes.DeviceCode, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);

            options.Configure(options => options.IgnoreGrantTypePermissions = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam"
        });

        // Assert
        Assert.Equal(Errors.UnauthorizedClient, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2027), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2027), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.GrantTypes.DeviceCode, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateDeviceRequest_RequestWithOfflineAccessScopeIsRejectedWhenRefreshTokenPermissionIsNotGranted()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.GrantTypes.DeviceCode, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.GrantTypes.RefreshToken, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);

            options.Configure(options => options.IgnoreGrantTypePermissions = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Scope = Scopes.OfflineAccess
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2065(Scopes.OfflineAccess), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2065), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.GrantTypes.RefreshToken, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateDeviceRequest_RequestIsRejectedWhenScopePermissionIsNotGranted()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.Prefixes.Scope + Scopes.Profile, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.Prefixes.Scope + Scopes.Email, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);

            options.RegisterScopes(Scopes.Email, Scopes.Profile);
            options.Configure(options => options.IgnoreScopePermissions = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Scope = "openid offline_access profile email"
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2051), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2051), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.Prefixes.Scope + Scopes.OpenId, It.IsAny<CancellationToken>()), Times.Never());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.Prefixes.Scope + Scopes.OfflineAccess, It.IsAny<CancellationToken>()), Times.Never());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.Prefixes.Scope + Scopes.Profile, It.IsAny<CancellationToken>()), Times.Once());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.Prefixes.Scope + Scopes.Email, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task ValidateDeviceRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateDeviceRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam"
        });

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task ValidateDeviceRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateDeviceRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam"
        });

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ValidateDeviceRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractDeviceRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task HandleDeviceRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleDeviceRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam"
        });

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task HandleDeviceRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateDeviceRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam"
        });

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task HandleDeviceRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateDeviceRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Fact]
    public async Task HandleDeviceRequest_ResponseContainsCustomParameters()
    {
        // Arrange
        var application = new OpenIddictApplication();

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            }));

            options.EnableDegradedMode();

            options.AddEventHandler<HandleDeviceRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity());

                    context.Parameters["custom_parameter"] = "custom_value";
                    context.Parameters["parameter_with_multiple_values"] = new[]
                    {
                        "custom_value_1",
                        "custom_value_2"
                    };

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam"
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.DeviceCode);
        Assert.Equal("custom_value", (string?) response["custom_parameter"]);
        Assert.Equal(new[] { "custom_value_1", "custom_value_2" }, (string[]?) response["parameter_with_multiple_values"]);
    }

    [Fact]
    public async Task ApplyDeviceResponse_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleDeviceRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity());

                    return default;
                }));

            options.AddEventHandler<ApplyDeviceResponseContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam"
        });

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ApplyDeviceResponse_ResponseContainsCustomParameters()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleDeviceRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity());

                    return default;
                }));

            options.AddEventHandler<ApplyDeviceResponseContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Response["custom_parameter"] = "custom_value";
                    context.Response["parameter_with_multiple_values"] = new[]
                    {
                        "custom_value_1",
                        "custom_value_2"
                    };

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam"
        });

        // Assert
        Assert.Equal("custom_value", (string?) response["custom_parameter"]);
        Assert.Equal(new[] { "custom_value_1", "custom_value_2" }, (string[]?) response["parameter_with_multiple_values"]);
    }

    [Theory]
    [InlineData(nameof(HttpMethod.Delete))]
    [InlineData(nameof(HttpMethod.Head))]
    [InlineData(nameof(HttpMethod.Options))]
    [InlineData(nameof(HttpMethod.Put))]
    [InlineData(nameof(HttpMethod.Trace))]
    public async Task ExtractVerificationRequest_UnexpectedMethodReturnsAnError(string method)
    {
        // Arrange
        await using var server = await CreateServerAsync();
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendAsync(method, "/connect/verification", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2084), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2084), response.ErrorUri);
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task ExtractVerificationRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/verification", new OpenIddictRequest());

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task ExtractVerificationRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/connect/verification");

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ExtractVerificationRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/connect/verification");

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task ValidateVerificationRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/verification", new OpenIddictRequest());

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task ValidateVerificationRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/verification", new OpenIddictRequest());

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ValidateVerificationRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/verification", new OpenIddictRequest());

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task HandleVerificationRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/verification", new OpenIddictRequest());

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task HandleVerificationRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/verification", new OpenIddictRequest());

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task HandleVerificationRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/verification", new OpenIddictRequest());

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Fact]
    public async Task HandleVerificationRequest_ResponseContainsCustomParameters()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("WDJB-MJHT", context.Token);
                    Assert.Equal(new[] { TokenTypeHints.UserCode }, context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity())
                        .SetTokenType(TokenTypeHints.UserCode);

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<HandleVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    context.Parameters["custom_parameter"] = "custom_value";
                    context.Parameters["parameter_with_multiple_values"] = new[]
                    {
                        "custom_value_1",
                        "custom_value_2"
                    };

                    return default;
                }));

            options.AddEventHandler<ApplyVerificationResponseContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", context.Response);
                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/verification", new OpenIddictRequest
        {
            UserCode = "WDJB-MJHT"
        });

        // Assert
        Assert.Equal("custom_value", (string?) response["custom_parameter"]);
        Assert.Equal(new[] { "custom_value_1", "custom_value_2" }, (string[]?) response["parameter_with_multiple_values"]);
    }

    [Fact]
    public async Task ApplyVerificationResponse_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject();

                    return default;
                }));

            options.AddEventHandler<ApplyVerificationResponseContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/verification", new OpenIddictRequest());

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ApplyVerificationResponse_ResponseContainsCustomParameters()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject();

                    return default;
                }));

            options.AddEventHandler<ApplyVerificationResponseContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Response["custom_parameter"] = "custom_value";

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/verification", new OpenIddictRequest());

        // Assert
        Assert.Equal("custom_value", (string?) response["custom_parameter"]);
    }
}
