/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Client.SystemNetHttp.Tests;

public class OpenIddictClientSystemNetHttpBuilderTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullServices()
    {
        // Arrange
        var services = (IServiceCollection) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictClientSystemNetHttpBuilder(services));

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

    private static OpenIddictClientSystemNetHttpBuilder CreateBuilder(IServiceCollection services)
        => new(services);

    private static OpenIddictClientSystemNetHttpOptions GetOptions(IServiceCollection services)
    {
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<OpenIddictClientSystemNetHttpOptions>>();
        return options.Value;
    }
}
