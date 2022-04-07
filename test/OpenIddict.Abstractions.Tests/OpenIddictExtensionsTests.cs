/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace OpenIddict.Abstractions.Tests;

public class OpenIddictExtensionsTests
{
    [Fact]
    public void AddOpenIddict_ThrowsAnExceptionForNullServices()
    {
        // Arrange
        var services = (IServiceCollection) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(services.AddOpenIddict);

        Assert.Equal("services", exception.ParamName);
    }

    [Fact]
    public void AddOpenIddict_ThrowsAnExceptionForNullConfigurationDelegate()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => services.AddOpenIddict(configuration: null!));

        Assert.Equal("configuration", exception.ParamName);
    }
}
