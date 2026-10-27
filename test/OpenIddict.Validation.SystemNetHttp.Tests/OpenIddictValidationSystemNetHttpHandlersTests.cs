/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.SystemNetHttp.OpenIddictValidationSystemNetHttpHandlers;

namespace OpenIddict.Validation.SystemNetHttp.Tests;

public class OpenIddictValidationSystemNetHttpHandlersTests
{
    private const string Payload = "SENSITIVE_PAYLOAD";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExtractJsonHttpResponse_OnlyLogsPayloadWhenSensitivePayloadLoggingIsEnabled(bool enabled)
    {
        // Arrange
        var logger = new Mock<ILogger<OpenIddictValidationDispatcher>>();

        using var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            // Note: the payload is deliberately malformed to trigger the JSON deserialization error.
            Content = new StringContent("{\"access_token\":\"" + Payload + "\"", Encoding.UTF8, "application/json")
        };

        var context = new PrepareConfigurationRequestContext(CreateTransaction(logger.Object, response));
        var handler = new ExtractJsonHttpResponse<PrepareConfigurationRequestContext>(CreateOptions(enabled));

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
        var logger = new Mock<ILogger<OpenIddictValidationDispatcher>>();

        using var response = new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent(Payload, Encoding.UTF8, "text/plain")
        };

        var context = new PrepareConfigurationRequestContext(CreateTransaction(logger.Object, response));
        var handler = new ValidateHttpResponse<PrepareConfigurationRequestContext>(CreateOptions(enabled));

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
        var logger = new Mock<ILogger<OpenIddictValidationDispatcher>>();

        using var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(Payload, Encoding.UTF8, "text/plain")
        };

        var context = new PrepareConfigurationRequestContext(CreateTransaction(logger.Object, response));
        var handler = new ValidateHttpResponse<PrepareConfigurationRequestContext>(CreateOptions(enabled));

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

    private static IOptionsMonitor<OpenIddictValidationSystemNetHttpOptions> CreateOptions(bool enabled)
        => Mock.Of<IOptionsMonitor<OpenIddictValidationSystemNetHttpOptions>>(monitor =>
            monitor.CurrentValue == new OpenIddictValidationSystemNetHttpOptions
            {
                EnableSensitivePayloadLogging = enabled
            });

    private static OpenIddictValidationTransaction CreateTransaction(
        ILogger<OpenIddictValidationDispatcher> logger, HttpResponseMessage response)
    {
        var services = new ServiceCollection();
        services.AddSingleton(logger);

        var transaction = new OpenIddictValidationTransaction
        {
            CancellationToken = CancellationToken.None,
            Options = new OpenIddictValidationOptions(),
            ServiceProvider = services.BuildServiceProvider()
        };

        transaction.Properties[typeof(HttpResponseMessage).FullName!] = response;

        return transaction;
    }
}
