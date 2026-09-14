/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Server.Tests;

public class OpenIddictServerRequestObjectReferenceTests
{
    [Fact]
    public void EnableRequestObjectReferenceSupport_OptionIsEnabled()
    {
        // Arrange
        var services = new ServiceCollection().AddOptions();
        var builder = new OpenIddictServerBuilder(services);

        // Act
        builder.EnableRequestObjectReferenceSupport();

        // Assert
        var options = services.BuildServiceProvider().GetRequiredService<IOptions<OpenIddictServerOptions>>().Value;
        Assert.True(options.EnableRequestObjectReferenceSupport);
        Assert.True(options.RequireRequestUriRegistration);
    }

    [Fact]
    public void DisableRequestUriRegistrationRequirement_RequirementIsDisabled()
    {
        // Arrange
        var services = new ServiceCollection().AddOptions();
        var builder = new OpenIddictServerBuilder(services);

        // Act
        builder.DisableRequestUriRegistrationRequirement();

        // Assert
        var options = services.BuildServiceProvider().GetRequiredService<IOptions<OpenIddictServerOptions>>().Value;
        Assert.False(options.RequireRequestUriRegistration);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenReferenceSupportIsEnabledWithoutRequestObjectSupport()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = new OpenIddictServerOptions
        {
            EnableRequestObjectReferenceSupport = true,
            TimeProvider = TimeProvider.System
        };

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0920), result.Failures!, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void Validate_ReturnsAnErrorWhenRegistrationIsRequiredInDegradedMode(bool required, bool error)
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = new OpenIddictServerOptions
        {
            EnableDegradedMode = true,
            EnableRequestObjectReferenceSupport = true,
            EnableRequestObjectSupport = true,
            RequireRequestUriRegistration = required,
            TimeProvider = TimeProvider.System
        };

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Equal(error, (result.Failures ?? []).Contains(SR.GetResourceString(SR.ID0922), StringComparer.Ordinal));
        Assert.DoesNotContain(SR.GetResourceString(SR.ID0920), result.Failures ?? [], StringComparer.Ordinal);
    }
}
