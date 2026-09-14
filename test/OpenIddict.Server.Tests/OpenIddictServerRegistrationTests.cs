/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace OpenIddict.Server.Tests;

public class OpenIddictServerRegistrationTests
{
    [Fact]
    public void SetRegistrationEndpointUris_AddsUris()
    {
        // Arrange
        var services = new ServiceCollection().AddOptions();
        var builder = new OpenIddictServerBuilder(services);

        // Act
        builder.SetRegistrationEndpointUris("http://localhost/connect/register");

        // Assert
        Assert.Contains(new Uri("http://localhost/connect/register"), GetOptions(services).RegistrationEndpointUris);
    }

    [Fact]
    public void SetRegistrationEndpointUris_ThrowsAnExceptionForUriStartingWithTilde()
    {
        // Arrange
        var builder = new OpenIddictServerBuilder(new ServiceCollection());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetRegistrationEndpointUris("~/connect/register"));
        Assert.Equal("uris", exception.ParamName);
    }

    [Fact]
    public void RegistrationMethods_UpdateTheOptions()
    {
        // Arrange
        var services = new ServiceCollection().AddOptions();
        var builder = new OpenIddictServerBuilder(services);
        var key = new RsaSecurityKey(RSA.Create(2048));

        // Act
        builder.EnableDynamicClientRegistration()
               .AllowAnonymousClientRegistration()
               .SetInitialAccessTokenScopes("dcr")
               .SetRegistrationAccessTokenLifetime(TimeSpan.FromDays(1))
               .RequireSoftwareStatement()
               .AddSoftwareStatementSigningKey(key, "https://issuer.example.com/");

        var options = GetOptions(services);

        // Assert
        Assert.True(options.EnableDynamicClientRegistration);
        Assert.True(options.AllowAnonymousClientRegistration);
        Assert.Equal(["dcr"], options.InitialAccessTokenScopes);
        Assert.Equal(TimeSpan.FromDays(1), options.RegistrationAccessTokenLifetime);
        Assert.True(options.RequireSoftwareStatement);
        Assert.Same(key, Assert.Single(options.SoftwareStatementSigningKeys));
        Assert.Equal(["https://issuer.example.com/"], options.SoftwareStatementIssuers);
    }

    [Fact]
    public void SetInitialAccessTokenScopes_ThrowsAnExceptionForEmptyScope()
    {
        // Arrange
        var builder = new OpenIddictServerBuilder(new ServiceCollection());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetInitialAccessTokenScopes(string.Empty));
        Assert.Equal("scopes", exception.ParamName);
    }

    [Fact]
    public void AddSoftwareStatementSigningKey_ThrowsAnExceptionForNullKey()
    {
        // Arrange
        var builder = new OpenIddictServerBuilder(new ServiceCollection());

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddSoftwareStatementSigningKey(null!));
        Assert.Equal("key", exception.ParamName);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenRegistrationEndpointIsMissing()
    {
        // Arrange
        var options = CreateBaseOptions();
        options.EnableDynamicClientRegistration = true;

        // Act
        var result = Validate(options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0800), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenDynamicClientRegistrationIsDisabled()
    {
        // Arrange
        var options = CreateBaseOptions();
        options.RegistrationEndpointUris.Add(new Uri("connect/register", UriKind.Relative));

        // Act
        var result = Validate(options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0801), result.Failures!, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Validate_ReturnsAnErrorWhenIncompatibleSettingsAreUsed(bool degraded, bool storage)
    {
        // Arrange
        var options = CreateRegistrationOptions();
        options.EnableDegradedMode = degraded;
        options.DisableTokenStorage = storage;

        // Act
        var result = Validate(options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0802), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenNoInitialAccessTokenScopeIsConfigured()
    {
        // Arrange
        var options = CreateRegistrationOptions();
        options.InitialAccessTokenScopes.Clear();

        // Act
        var result = Validate(options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0803), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_DoesNotRequireInitialAccessTokenScopesForAnonymousRegistration()
    {
        // Arrange
        var options = CreateRegistrationOptions();
        options.InitialAccessTokenScopes.Clear();
        options.AllowAnonymousClientRegistration = true;

        // Act
        var result = Validate(options);

        // Assert
        Assert.DoesNotContain(SR.GetResourceString(SR.ID0803), result.Failures ?? [], StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenSoftwareStatementsAreRequiredWithoutSigningKeys()
    {
        // Arrange
        var options = CreateRegistrationOptions();
        options.RequireSoftwareStatement = true;

        // Act
        var result = Validate(options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0804), result.Failures!, StringComparer.Ordinal);
    }

    private static OpenIddictServerOptions CreateBaseOptions() => new() { TimeProvider = TimeProvider.System };

    private static OpenIddictServerOptions CreateRegistrationOptions()
    {
        var options = CreateBaseOptions();
        options.EnableDynamicClientRegistration = true;
        options.RegistrationEndpointUris.Add(new Uri("connect/register", UriKind.Relative));
        options.InitialAccessTokenScopes.Add("dcr");

        return options;
    }

    private static ValidateOptionsResult Validate(OpenIddictServerOptions options)
        => new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider()).Validate(name: null, options);

    private static OpenIddictServerOptions GetOptions(IServiceCollection services)
        => services.BuildServiceProvider().GetRequiredService<IOptions<OpenIddictServerOptions>>().Value;
}
