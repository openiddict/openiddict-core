/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Text.Json;
using OpenIddict.Server.SystemNetHttp;
using Xunit;

namespace OpenIddict.Server.SystemNetHttp.Tests;

public class OpenIddictServerSystemNetHttpCimdContextTests
{
    [Fact]
    public void Properties_DefaultToNull()
    {
        // Arrange
        var context = new OpenIddictServerSystemNetHttpCimdContext();

        // Assert
        Assert.Null(context.ClientId);
        Assert.Null(context.MetadataDocument);
        Assert.Null(context.VirtualApplication);
    }

    [Fact]
    public void Properties_CanBeSetAndRead()
    {
        // Arrange
        var context = new OpenIddictServerSystemNetHttpCimdContext();
        using var document = JsonDocument.Parse("""{"client_name": "Test"}""");
        var virtualApp = new object();

        // Act
        context.ClientId = "https://example.com/client";
        context.MetadataDocument = document;
        context.VirtualApplication = virtualApp;

        // Assert
        Assert.Equal("https://example.com/client", context.ClientId);
        Assert.Same(document, context.MetadataDocument);
        Assert.Same(virtualApp, context.VirtualApplication);
    }
}
