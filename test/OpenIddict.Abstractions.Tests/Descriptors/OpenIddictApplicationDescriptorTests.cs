using System.Globalization;
using Xunit;

namespace OpenIddict.Abstractions.Tests.Descriptors;

public class OpenIddictApplicationDescriptorTests
{
    [Fact]
    public void AddAudiencePermissions_AddsPermissions()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();

        // Act
        descriptor.AddAudiencePermissions("Fabrikam", "Contoso");

        // Assert
        Assert.Contains(OpenIddictConstants.Permissions.Prefixes.Audience + "Fabrikam", descriptor.Permissions);
        Assert.Contains(OpenIddictConstants.Permissions.Prefixes.Audience + "Contoso", descriptor.Permissions);
    }

    [Fact]
    public void AddAudiencePermissions_ThrowsAnExceptionForNullAudiences()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();

        // Act and assert
        Assert.Throws<ArgumentNullException>(() => descriptor.AddAudiencePermissions(null!));
    }

    [Fact]
    public void AddResourcePermissions_AddsPermissions()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();

        // Act
        descriptor.AddResourcePermissions("urn:fabrikam", "urn:contoso");

        // Assert
        Assert.Contains(OpenIddictConstants.Permissions.Prefixes.Resource + "urn:fabrikam", descriptor.Permissions);
        Assert.Contains(OpenIddictConstants.Permissions.Prefixes.Resource + "urn:contoso", descriptor.Permissions);
    }

    [Fact]
    public void AddResourcePermissions_ThrowsAnExceptionForNullResources()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();

        // Act and assert
        Assert.Throws<ArgumentNullException>(() => descriptor.AddResourcePermissions(null!));
    }

    [Fact]
    public void AddScopePermissions_AddsPermissions()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();

        // Act
        descriptor.AddScopePermissions("scope1", "scope2");

        // Assert
        Assert.Contains(OpenIddictConstants.Permissions.Prefixes.Scope + "scope1", descriptor.Permissions);
        Assert.Contains(OpenIddictConstants.Permissions.Prefixes.Scope + "scope2", descriptor.Permissions);
    }

    [Fact]
    public void AddScopePermissions_ThrowsAnExceptionForNullScopes()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();

        // Act and assert
        Assert.Throws<ArgumentNullException>(() => descriptor.AddScopePermissions(null!));
    }

    [Fact]
    public void SetAccessTokenLifetime_SetsAndRemovesCorrectly()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();
        var lifetime = TimeSpan.FromHours(1);

        // Act
        descriptor.SetAccessTokenLifetime(lifetime);

        // Assert
        Assert.Equal(lifetime.ToString("c", CultureInfo.InvariantCulture),
            descriptor.Settings[OpenIddictConstants.Settings.TokenLifetimes.AccessToken]);

        // Act
        descriptor.SetAccessTokenLifetime(null);

        // Assert
        Assert.False(descriptor.Settings.ContainsKey(OpenIddictConstants.Settings.TokenLifetimes.AccessToken));
    }

    [Fact]
    public void SetAuthorizationCodeLifetime_SetsAndRemovesCorrectly()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();
        var lifetime = TimeSpan.FromHours(1);

        // Act
        descriptor.SetAuthorizationCodeLifetime(lifetime);

        // Assert
        Assert.Equal(lifetime.ToString("c", CultureInfo.InvariantCulture),
            descriptor.Settings[OpenIddictConstants.Settings.TokenLifetimes.AuthorizationCode]);

        // Act
        descriptor.SetAuthorizationCodeLifetime(null);

        // Assert
        Assert.False(descriptor.Settings.ContainsKey(OpenIddictConstants.Settings.TokenLifetimes.AuthorizationCode));
    }

    [Fact]
    public void SetDeviceCodeLifetime_SetsAndRemovesCorrectly()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();
        var lifetime = TimeSpan.FromHours(1);

        // Act
        descriptor.SetDeviceCodeLifetime(lifetime);

        // Assert
        Assert.Equal(lifetime.ToString("c", CultureInfo.InvariantCulture),
            descriptor.Settings[OpenIddictConstants.Settings.TokenLifetimes.DeviceCode]);

        // Act
        descriptor.SetDeviceCodeLifetime(null);

        // Assert
        Assert.False(descriptor.Settings.ContainsKey(OpenIddictConstants.Settings.TokenLifetimes.DeviceCode));
    }

    [Fact]
    public void SetIdentityTokenLifetime_SetsAndRemovesCorrectly()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();
        var lifetime = TimeSpan.FromHours(1);

        // Act
        descriptor.SetIdentityTokenLifetime(lifetime);

        // Assert
        Assert.Equal(lifetime.ToString("c", CultureInfo.InvariantCulture),
            descriptor.Settings[OpenIddictConstants.Settings.TokenLifetimes.IdentityToken]);

        // Act
        descriptor.SetIdentityTokenLifetime(null);

        // Assert
        Assert.False(descriptor.Settings.ContainsKey(OpenIddictConstants.Settings.TokenLifetimes.IdentityToken));
    }

    [Fact]
    public void SetIssuedTokenLifetime_SetsAndRemovesCorrectly()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();
        var lifetime = TimeSpan.FromHours(1);

        // Act
        descriptor.SetIssuedTokenLifetime(lifetime);

        // Assert
        Assert.Equal(lifetime.ToString("c", CultureInfo.InvariantCulture),
            descriptor.Settings[OpenIddictConstants.Settings.TokenLifetimes.IssuedToken]);

        // Act
        descriptor.SetIssuedTokenLifetime(null);

        // Assert
        Assert.False(descriptor.Settings.ContainsKey(OpenIddictConstants.Settings.TokenLifetimes.IssuedToken));
    }

    [Fact]
    public void SetRefreshTokenLifetime_SetsAndRemovesCorrectly()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();
        var lifetime = TimeSpan.FromHours(1);

        // Act
        descriptor.SetRefreshTokenLifetime(lifetime);

        // Assert
        Assert.Equal(lifetime.ToString("c", CultureInfo.InvariantCulture),
            descriptor.Settings[OpenIddictConstants.Settings.TokenLifetimes.RefreshToken]);

        // Act
        descriptor.SetRefreshTokenLifetime(null);

        // Assert
        Assert.False(descriptor.Settings.ContainsKey(OpenIddictConstants.Settings.TokenLifetimes.RefreshToken));
    }

    [Fact]
    public void SetRequestTokenLifetime_SetsAndRemovesCorrectly()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();
        var lifetime = TimeSpan.FromHours(1);

        // Act
        descriptor.SetRequestTokenLifetime(lifetime);

        // Assert
        Assert.Equal(lifetime.ToString("c", CultureInfo.InvariantCulture),
            descriptor.Settings[OpenIddictConstants.Settings.TokenLifetimes.RequestToken]);

        // Act
        descriptor.SetRequestTokenLifetime(null);

        // Assert
        Assert.False(descriptor.Settings.ContainsKey(OpenIddictConstants.Settings.TokenLifetimes.RequestToken));
    }

    [Fact]
    public void SetUserCodeLifetime_SetsAndRemovesCorrectly()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();
        var lifetime = TimeSpan.FromHours(1);

        // Act
        descriptor.SetUserCodeLifetime(lifetime);

        // Assert
        Assert.Equal(lifetime.ToString("c", CultureInfo.InvariantCulture),
            descriptor.Settings[OpenIddictConstants.Settings.TokenLifetimes.UserCode]);

        // Act
        descriptor.SetUserCodeLifetime(null);

        // Assert
        Assert.False(descriptor.Settings.ContainsKey(OpenIddictConstants.Settings.TokenLifetimes.UserCode));
    }

    [Fact]
    public void RemoveAudiencePermissions_RemovesPermissions()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();
        descriptor.AddAudiencePermissions("Fabrikam", "Contoso");

        // Act
        descriptor.RemoveAudiencePermissions("Fabrikam");

        // Assert
        Assert.DoesNotContain(OpenIddictConstants.Permissions.Prefixes.Audience + "Fabrikam", descriptor.Permissions);
        Assert.Contains(OpenIddictConstants.Permissions.Prefixes.Audience + "Contoso", descriptor.Permissions);
    }

    [Fact]
    public void RemoveAudiencePermissions_ThrowsAnExceptionForNullAudiences()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();

        // Act and assert
        Assert.Throws<ArgumentNullException>(() => descriptor.RemoveAudiencePermissions(null!));
    }

    [Fact]
    public void RemoveResourcePermissions_RemovesPermissions()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();
        descriptor.AddResourcePermissions("urn:fabrikam", "urn:contoso");

        // Act
        descriptor.RemoveResourcePermissions("urn:contoso");

        // Assert
        Assert.Contains(OpenIddictConstants.Permissions.Prefixes.Resource + "urn:fabrikam", descriptor.Permissions);
        Assert.DoesNotContain(OpenIddictConstants.Permissions.Prefixes.Resource + "urn:contoso", descriptor.Permissions);
    }

    [Fact]
    public void RemoveResourcePermissions_ThrowsAnExceptionForNullResources()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();

        // Act and assert
        Assert.Throws<ArgumentNullException>(() => descriptor.RemoveResourcePermissions(null!));
    }

    [Fact]
    public void RemoveScopePermissions_RemovesPermissions()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();
        descriptor.AddScopePermissions("scope1", "scope2");

        // Act
        descriptor.RemoveScopePermissions("scope1");

        // Assert
        Assert.DoesNotContain(OpenIddictConstants.Permissions.Prefixes.Scope + "scope1", descriptor.Permissions);
        Assert.Contains(OpenIddictConstants.Permissions.Prefixes.Scope + "scope2", descriptor.Permissions);
    }

    [Fact]
    public void RemoveScopePermissions_ThrowsAnExceptionForNullScopes()
    {
        // Arrange
        var descriptor = new OpenIddictApplicationDescriptor();

        // Act and assert
        Assert.Throws<ArgumentNullException>(() => descriptor.RemoveScopePermissions(null!));
    }
}
