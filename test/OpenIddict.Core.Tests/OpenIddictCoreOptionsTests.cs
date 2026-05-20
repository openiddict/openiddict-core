/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Cryptography;
using Xunit;

namespace OpenIddict.Core.Tests;

public class OpenIddictCoreOptionsTests
{
    [Fact]
    public void Constructor_SetsDefaultValues()
    {
        // Act
        var options = new OpenIddictCoreOptions();

        // Assert
        Assert.Equal(HashAlgorithmName.SHA512, options.ClientSecretKeyDerivationHashAlgorithm);
        Assert.Equal(100_000, options.ClientSecretKeyDerivationIterations);
        Assert.Equal(512, options.ClientSecretKeyDerivationOutputLength);
        Assert.Equal(256, options.ClientSecretKeyDerivationSaltLength);
        Assert.False(options.DisableAdditionalFiltering);
        Assert.False(options.DisableAutomaticClientSecretRehashing);
        Assert.False(options.DisableEntityCaching);
        Assert.Equal(250, options.EntityCacheLimit);
    }

    [Fact]
    public void ClientSecretKeyDerivationHashAlgorithm_CanBeSet()
    {
        // Arrange
        var options = new OpenIddictCoreOptions();

        // Act
        options.ClientSecretKeyDerivationHashAlgorithm = HashAlgorithmName.SHA256;

        // Assert
        Assert.Equal(HashAlgorithmName.SHA256, options.ClientSecretKeyDerivationHashAlgorithm);
    }

    [Fact]
    public void ClientSecretKeyDerivationIterations_CanBeSet()
    {
        // Arrange
        var options = new OpenIddictCoreOptions();

        // Act
        options.ClientSecretKeyDerivationIterations = 50_000;

        // Assert
        Assert.Equal(50_000, options.ClientSecretKeyDerivationIterations);
    }

    [Fact]
    public void ClientSecretKeyDerivationOutputLength_CanBeSet()
    {
        // Arrange
        var options = new OpenIddictCoreOptions();

        // Act
        options.ClientSecretKeyDerivationOutputLength = 1024;

        // Assert
        Assert.Equal(1024, options.ClientSecretKeyDerivationOutputLength);
    }

    [Fact]
    public void ClientSecretKeyDerivationSaltLength_CanBeSet()
    {
        // Arrange
        var options = new OpenIddictCoreOptions();

        // Act
        options.ClientSecretKeyDerivationSaltLength = 512;

        // Assert
        Assert.Equal(512, options.ClientSecretKeyDerivationSaltLength);
    }

    [Fact]
    public void DisableAdditionalFiltering_CanBeSet()
    {
        // Arrange
        var options = new OpenIddictCoreOptions();

        // Act
        options.DisableAdditionalFiltering = true;

        // Assert
        Assert.True(options.DisableAdditionalFiltering);
    }

    [Fact]
    public void DisableAutomaticClientSecretRehashing_CanBeSet()
    {
        // Arrange
        var options = new OpenIddictCoreOptions();

        // Act
        options.DisableAutomaticClientSecretRehashing = true;

        // Assert
        Assert.True(options.DisableAutomaticClientSecretRehashing);
    }

    [Fact]
    public void DisableEntityCaching_CanBeSet()
    {
        // Arrange
        var options = new OpenIddictCoreOptions();

        // Act
        options.DisableEntityCaching = true;

        // Assert
        Assert.True(options.DisableEntityCaching);
    }

    [Fact]
    public void EntityCacheLimit_CanBeSet()
    {
        // Arrange
        var options = new OpenIddictCoreOptions();

        // Act
        options.EntityCacheLimit = 500;

        // Assert
        Assert.Equal(500, options.EntityCacheLimit);
    }

    [Fact]
    public void TimeProvider_CanBeSet()
    {
        // Arrange
        var options = new OpenIddictCoreOptions();
        var customTimeProvider = new CustomTimeProvider();

        // Act
        options.TimeProvider = customTimeProvider;

        // Assert
        Assert.Same(customTimeProvider, options.TimeProvider);
    }

    private class CustomTimeProvider : TimeProvider
    {
    }
}
