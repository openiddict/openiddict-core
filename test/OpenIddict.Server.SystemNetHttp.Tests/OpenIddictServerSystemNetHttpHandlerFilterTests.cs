/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Logging;
using Moq;
using OpenIddict.Server.SystemNetHttp;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.SystemNetHttp.OpenIddictServerSystemNetHttpHandlerFilters;

namespace OpenIddict.Server.SystemNetHttp.Tests;

public class OpenIddictServerSystemNetHttpHandlerFilterTests
{
    [Fact]
    public async Task IsActiveAsync_ReturnsTrue_WhenCimdEnabled()
    {
        // Arrange
        var filter = new RequireClientIdMetadataDocumentSupportEnabled();
        var context = CreateBaseContext(enableCimd: true);

        // Act
        var result = await filter.IsActiveAsync(context);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task IsActiveAsync_ReturnsFalse_WhenCimdDisabled()
    {
        // Arrange
        var filter = new RequireClientIdMetadataDocumentSupportEnabled();
        var context = CreateBaseContext(enableCimd: false);

        // Act
        var result = await filter.IsActiveAsync(context);

        // Assert
        Assert.False(result);
    }

    private static HandleConfigurationRequestContext CreateBaseContext(bool enableCimd)
    {
        var options = new OpenIddictServerOptions
        {
            EnableClientIdMetadataDocumentSupport = enableCimd
        };

        var transaction = new OpenIddictServerTransaction
        {
            Options = options,
            Logger = Mock.Of<ILogger>()
        };

        return new HandleConfigurationRequestContext(transaction)
        {
            Issuer = new Uri("https://localhost/")
        };
    }
}
