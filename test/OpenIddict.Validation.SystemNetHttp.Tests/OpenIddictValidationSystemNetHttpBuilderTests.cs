/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Validation.SystemNetHttp.Tests;

public class OpenIddictValidationSystemNetHttpBuilderTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullServices()
    {
        // Arrange
        var services = (IServiceCollection) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictValidationSystemNetHttpBuilder(services));

        Assert.Equal("services", exception.ParamName);
    }

    [Fact]
    public void EnableSensitivePayloadLogging_IsDisabledByDefault()
    {
        // Arrange
        var services = CreateServices();
        CreateBuilder(services);

        // Act
        var options = GetOptions(services);

        // Assert
        Assert.False(options.EnableSensitivePayloadLogging);
    }

    [Fact]
    public void EnableSensitivePayloadLogging_SetsSensitivePayloadLoggingEnabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.EnableSensitivePayloadLogging();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.EnableSensitivePayloadLogging);
    }

    private static IServiceCollection CreateServices()
        => new ServiceCollection().AddOptions();

    private static OpenIddictValidationSystemNetHttpBuilder CreateBuilder(IServiceCollection services)
        => new(services);

    private static OpenIddictValidationSystemNetHttpOptions GetOptions(IServiceCollection services)
    {
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<OpenIddictValidationSystemNetHttpOptions>>();
        return options.Value;
    }
}
