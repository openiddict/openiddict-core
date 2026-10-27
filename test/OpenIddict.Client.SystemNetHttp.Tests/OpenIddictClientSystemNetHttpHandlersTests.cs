/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;
using static OpenIddict.Client.OpenIddictClientEvents;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpConstants;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers;

namespace OpenIddict.Client.SystemNetHttp.Tests;

public class OpenIddictClientSystemNetHttpHandlersTests
{
    private const string Payload = "SENSITIVE_PAYLOAD";

    public static TheoryData<string, DecompressionMethods> SupportedEncodings => new()
    {
        { ContentEncodings.Gzip, DecompressionMethods.GZip },
#if NET
        { ContentEncodings.Deflate, DecompressionMethods.Deflate },
        { ContentEncodings.Brotli, DecompressionMethods.Brotli }
#endif
    };

    [Theory]
    [MemberData(nameof(SupportedEncodings))]
    public async Task DecompressResponseContent_DecompressesContentWhenMethodIsAllowed(string encoding, DecompressionMethods method)
    {
        // Arrange
        using var response = CreateCompressedResponse(encoding);

        var context = new PrepareDeviceAuthorizationRequestContext(
            CreateTransaction(Mock.Of<ILogger<OpenIddictClientDispatcher>>(), response));
        var handler = new DecompressResponseContent<PrepareDeviceAuthorizationRequestContext>(CreateOptions(method));

        // Act
        await handler.HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
        Assert.Empty(response.Content.Headers.ContentEncoding);
        Assert.Equal(Payload, await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [MemberData(nameof(SupportedEncodings))]
    public async Task DecompressResponseContent_RejectsContentWhenMethodIsNotAllowed(string encoding, DecompressionMethods method)
    {
        // Arrange
        using var response = CreateCompressedResponse(encoding);

        var context = new PrepareDeviceAuthorizationRequestContext(
            CreateTransaction(Mock.Of<ILogger<OpenIddictClientDispatcher>>(), response));

        // Note: all the methods except the one used to encode the response are allowed.
        var handler = new DecompressResponseContent<PrepareDeviceAuthorizationRequestContext>(CreateOptions(~method));

        // Act
        await handler.HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(Errors.ServerError, context.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2211), context.ErrorDescription);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExtractJsonHttpResponse_OnlyLogsPayloadWhenSensitivePayloadLoggingIsEnabled(bool enabled)
    {
        // Arrange
        var logger = new Mock<ILogger<OpenIddictClientDispatcher>>();

        using var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            // Note: the payload is deliberately malformed to trigger the JSON deserialization error.
            Content = new StringContent("{\"access_token\":\"" + Payload + "\"", Encoding.UTF8, "application/json")
        };

        var context = new PrepareDeviceAuthorizationRequestContext(CreateTransaction(logger.Object, response));
        var handler = new ExtractJsonHttpResponse<PrepareDeviceAuthorizationRequestContext>(CreateOptions(enabled));

        // Act
        await handler.HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(Errors.ServerError, context.Error);

        logger.Verify(logger => logger.Log(
            LogLevel.Error,
            It.Is<EventId>(id => id.Id == 6183),
            It.Is<It.IsAnyType>((state, type) => Convert.ToString(state, CultureInfo.InvariantCulture)!.Contains(Payload) == enabled),
            It.IsAny<Exception>(),
            It.IsAny<Func<It.IsAnyType, Exception?, string>>()), Times.Once());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ValidateHttpResponse_OnlyLogsPayloadOfGenericErrorsWhenSensitivePayloadLoggingIsEnabled(bool enabled)
    {
        // Arrange
        var logger = new Mock<ILogger<OpenIddictClientDispatcher>>();

        using var response = new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent(Payload, Encoding.UTF8, "text/plain")
        };

        var context = new PrepareDeviceAuthorizationRequestContext(CreateTransaction(logger.Object, response));
        var handler = new ValidateHttpResponse<PrepareDeviceAuthorizationRequestContext>(CreateOptions(enabled));

        // Act
        await handler.HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(Errors.ServerError, context.Error);

        logger.Verify(logger => logger.Log(
            LogLevel.Error,
            It.Is<EventId>(id => id.Id == 6184),
            It.Is<It.IsAnyType>((state, type) => Convert.ToString(state, CultureInfo.InvariantCulture)!.Contains(Payload) == enabled),
            It.IsAny<Exception>(),
            It.IsAny<Func<It.IsAnyType, Exception?, string>>()), Times.Once());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ValidateHttpResponse_OnlyLogsPayloadOfUnsupportedResponsesWhenSensitivePayloadLoggingIsEnabled(bool enabled)
    {
        // Arrange
        var logger = new Mock<ILogger<OpenIddictClientDispatcher>>();

        using var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(Payload, Encoding.UTF8, "text/plain")
        };

        var context = new PrepareDeviceAuthorizationRequestContext(CreateTransaction(logger.Object, response));
        var handler = new ValidateHttpResponse<PrepareDeviceAuthorizationRequestContext>(CreateOptions(enabled));

        // Act
        await handler.HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(Errors.ServerError, context.Error);

        logger.Verify(logger => logger.Log(
            LogLevel.Error,
            It.Is<EventId>(id => id.Id == 6185),
            It.Is<It.IsAnyType>((state, type) => Convert.ToString(state, CultureInfo.InvariantCulture)!.Contains(Payload) == enabled),
            It.IsAny<Exception>(),
            It.IsAny<Func<It.IsAnyType, Exception?, string>>()), Times.Once());
    }

    private static HttpResponseMessage CreateCompressedResponse(string encoding)
    {
        using var buffer = new MemoryStream();

        using (Stream stream = encoding switch
        {
            ContentEncodings.Gzip => new GZipStream(buffer, CompressionMode.Compress, leaveOpen: true),
#if NET
            ContentEncodings.Deflate => new ZLibStream(buffer, CompressionMode.Compress, leaveOpen: true),
            ContentEncodings.Brotli => new BrotliStream(buffer, CompressionMode.Compress, leaveOpen: true),
#endif
            _ => throw new ArgumentOutOfRangeException(nameof(encoding))
        })
        {
            var bytes = Encoding.UTF8.GetBytes(Payload);
            stream.Write(bytes, 0, bytes.Length);
        }

        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(buffer.ToArray())
        };

        response.Content.Headers.ContentEncoding.Add(encoding);

        return response;
    }

    private static IOptionsMonitor<OpenIddictClientSystemNetHttpOptions> CreateOptions(bool enabled)
        => Mock.Of<IOptionsMonitor<OpenIddictClientSystemNetHttpOptions>>(monitor =>
            monitor.CurrentValue == new OpenIddictClientSystemNetHttpOptions
            {
                EnableSensitivePayloadLogging = enabled
            });

    private static IOptionsMonitor<OpenIddictClientSystemNetHttpOptions> CreateOptions(DecompressionMethods methods)
        => Mock.Of<IOptionsMonitor<OpenIddictClientSystemNetHttpOptions>>(monitor =>
            monitor.CurrentValue == new OpenIddictClientSystemNetHttpOptions
            {
                AllowedDecompressionMethods = methods
            });

    private static OpenIddictClientTransaction CreateTransaction(
        ILogger<OpenIddictClientDispatcher> logger, HttpResponseMessage response)
    {
        var services = new ServiceCollection();
        services.AddSingleton(logger);

        var transaction = new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Options = new OpenIddictClientOptions(),
            ServiceProvider = services.BuildServiceProvider()
        };

        transaction.Properties[typeof(HttpResponseMessage).FullName!] = response;

        return transaction;
    }
}
