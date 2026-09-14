/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Text;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace OpenIddict.Client.AspNetCore.Tests;

public class OpenIddictClientAspNetCoreHelpersTests
{
    [Fact]
    public async Task ReadBackchannelNotificationAsync_ReturnsNotification()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Post;
        context.Request.ContentType = "application/json";
        context.Request.Headers.Authorization = "Bearer 8C3C7A6D";
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("""{ "auth_req_id": "F6B3B1E4" }"""));

        // Act
        var notification = await context.Request.ReadBackchannelNotificationAsync();

        // Assert
        Assert.NotNull(notification);
        Assert.Equal("8C3C7A6D", notification.ClientNotificationToken);
        Assert.Equal("F6B3B1E4", notification.AuthenticationRequestId);
    }

    [Fact]
    public async Task ReadBackchannelNotificationAsync_ReturnsNullForNonPostRequests()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.ContentType = "application/json";
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("""{ "auth_req_id": "F6B3B1E4" }"""));

        // Act and assert
        Assert.Null(await context.Request.ReadBackchannelNotificationAsync());
    }
}
