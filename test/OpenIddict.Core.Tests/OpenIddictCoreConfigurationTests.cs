/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace OpenIddict.Core.Tests;

public class OpenIddictCoreConfigurationTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullProvider()
    {
        // Arrange
        var provider = (IServiceProvider) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictCoreConfiguration(provider));

        Assert.Equal("provider", exception.ParamName);
    }

    [Fact]
    public void PostConfigure_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var services = new ServiceCollection();
        var provider = services.BuildServiceProvider();
        var configuration = new OpenIddictCoreConfiguration(provider);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => configuration.PostConfigure(null, null!));

        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void PostConfigure_SetsTimeProviderToSystemWhenNotRegistered()
    {
        // Arrange
        var services = new ServiceCollection();
        var provider = services.BuildServiceProvider();
        var configuration = new OpenIddictCoreConfiguration(provider);
        var options = new OpenIddictCoreOptions();

        // Act
        configuration.PostConfigure(null, options);

        // Assert
        Assert.Same(TimeProvider.System, options.TimeProvider);
    }

    [Fact]
    public void PostConfigure_UsesRegisteredTimeProvider()
    {
        // Arrange
        var customTimeProvider = new CustomTimeProvider();
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(customTimeProvider);
        var provider = services.BuildServiceProvider();
        var configuration = new OpenIddictCoreConfiguration(provider);
        var options = new OpenIddictCoreOptions();

        // Act
        configuration.PostConfigure(null, options);

        // Assert
        Assert.Same(customTimeProvider, options.TimeProvider);
    }

    [Fact]
    public void PostConfigure_DoesNotOverrideExplicitlySetTimeProvider()
    {
        // Arrange
        var explicitTimeProvider = new CustomTimeProvider();
        var registeredTimeProvider = new CustomTimeProvider();
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(registeredTimeProvider);
        var provider = services.BuildServiceProvider();
        var configuration = new OpenIddictCoreConfiguration(provider);
        var options = new OpenIddictCoreOptions
        {
            TimeProvider = explicitTimeProvider
        };

        // Act
        configuration.PostConfigure(null, options);

        // Assert
        Assert.Same(explicitTimeProvider, options.TimeProvider);
    }

    [Fact]
    public void Validate_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var services = new ServiceCollection();
        var provider = services.BuildServiceProvider();
        var configuration = new OpenIddictCoreConfiguration(provider);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => configuration.Validate(null, null!));

        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Validate_SucceedsForDefaultOptions()
    {
        // Arrange
        var services = new ServiceCollection();
        var provider = services.BuildServiceProvider();
        var configuration = new OpenIddictCoreConfiguration(provider);
        var options = new OpenIddictCoreOptions();

        // Act
        var result = configuration.Validate(null, options);

        // Assert
        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(nameof(HashAlgorithmName.SHA1))]
    [InlineData(nameof(HashAlgorithmName.SHA256))]
    [InlineData(nameof(HashAlgorithmName.SHA512))]
    public void Validate_SucceedsForValidHashAlgorithm(string algorithmName)
    {
        // Arrange
        var services = new ServiceCollection();
        var provider = services.BuildServiceProvider();
        var configuration = new OpenIddictCoreConfiguration(provider);
        var options = new OpenIddictCoreOptions
        {
            ClientSecretKeyDerivationHashAlgorithm = new HashAlgorithmName(algorithmName)
        };

        // Act
        var result = configuration.Validate(null, options);

        // Assert
        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_FailsForInvalidHashAlgorithm()
    {
        // Arrange
        var services = new ServiceCollection();
        var provider = services.BuildServiceProvider();
        var configuration = new OpenIddictCoreConfiguration(provider);
        var options = new OpenIddictCoreOptions
        {
            ClientSecretKeyDerivationHashAlgorithm = new HashAlgorithmName("MD5")
        };

        // Act
        var result = configuration.Validate(null, options);

        // Assert
        Assert.True(result.Failed);
        Assert.Contains(SR.FormatID0217("MD5"), result.Failures, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData(9_999)]
    [InlineData(10_000_001)]
    public void Validate_FailsForInvalidIterationCount(int iterations)
    {
        // Arrange
        var services = new ServiceCollection();
        var provider = services.BuildServiceProvider();
        var configuration = new OpenIddictCoreConfiguration(provider);
        var options = new OpenIddictCoreOptions
        {
            ClientSecretKeyDerivationIterations = iterations
        };

        // Act
        var result = configuration.Validate(null, options);

        // Assert
        Assert.True(result.Failed);
        Assert.Contains(SR.FormatID0518(10_000, 10_000_000), result.Failures, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData(10_000)]
    [InlineData(100_000)]
    [InlineData(10_000_000)]
    public void Validate_SucceedsForValidIterationCount(int iterations)
    {
        // Arrange
        var services = new ServiceCollection();
        var provider = services.BuildServiceProvider();
        var configuration = new OpenIddictCoreConfiguration(provider);
        var options = new OpenIddictCoreOptions
        {
            ClientSecretKeyDerivationIterations = iterations
        };

        // Act
        var result = configuration.Validate(null, options);

        // Assert
        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(127)]
    [InlineData(1025)]
    public void Validate_FailsForInvalidSaltLength(int saltLength)
    {
        // Arrange
        var services = new ServiceCollection();
        var provider = services.BuildServiceProvider();
        var configuration = new OpenIddictCoreConfiguration(provider);
        var options = new OpenIddictCoreOptions
        {
            ClientSecretKeyDerivationSaltLength = saltLength
        };

        // Act
        var result = configuration.Validate(null, options);

        // Assert
        Assert.True(result.Failed);
        Assert.Contains(SR.FormatID0519(128, 1024), result.Failures, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData(128)]
    [InlineData(256)]
    [InlineData(1024)]
    public void Validate_SucceedsForValidSaltLength(int saltLength)
    {
        // Arrange
        var services = new ServiceCollection();
        var provider = services.BuildServiceProvider();
        var configuration = new OpenIddictCoreConfiguration(provider);
        var options = new OpenIddictCoreOptions
        {
            ClientSecretKeyDerivationSaltLength = saltLength
        };

        // Act
        var result = configuration.Validate(null, options);

        // Assert
        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(255)]
    [InlineData(2049)]
    public void Validate_FailsForInvalidOutputLength(int outputLength)
    {
        // Arrange
        var services = new ServiceCollection();
        var provider = services.BuildServiceProvider();
        var configuration = new OpenIddictCoreConfiguration(provider);
        var options = new OpenIddictCoreOptions
        {
            ClientSecretKeyDerivationOutputLength = outputLength
        };

        // Act
        var result = configuration.Validate(null, options);

        // Assert
        Assert.True(result.Failed);
        Assert.Contains(SR.FormatID0520(256, 2048), result.Failures, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData(256)]
    [InlineData(512)]
    [InlineData(2048)]
    public void Validate_SucceedsForValidOutputLength(int outputLength)
    {
        // Arrange
        var services = new ServiceCollection();
        var provider = services.BuildServiceProvider();
        var configuration = new OpenIddictCoreConfiguration(provider);
        var options = new OpenIddictCoreOptions
        {
            ClientSecretKeyDerivationOutputLength = outputLength
        };

        // Act
        var result = configuration.Validate(null, options);

        // Assert
        Assert.True(result.Succeeded);
    }
    private sealed class CustomTimeProvider : TimeProvider
    {
    }
}
