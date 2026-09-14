/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Server.Tests;

public class OpenIddictServerIssuerResolutionTests
{
    [Fact]
    public void AddIssuers_IssuersAreAddedAndResolutionIsEnabled()
    {
        // Arrange
        var services = new ServiceCollection().AddOptions();
        var builder = new OpenIddictServerBuilder(services);

        // Act
        builder.AddIssuers("https://contoso.com/tenant1/", "https://fabrikam.com/");

        // Assert
        var options = services.BuildServiceProvider().GetRequiredService<IOptions<OpenIddictServerOptions>>().Value;
        Assert.True(options.EnableIssuerResolution);
        Assert.Equal([new Uri("https://contoso.com/tenant1/"), new Uri("https://fabrikam.com/")], options.Issuers);
    }

    [Theory]
    [InlineData("contoso/tenant1")]
    [InlineData("https://contoso.com/?tenant=1")]
    [InlineData("https://contoso.com/#tenant1")]
    public void AddIssuers_InvalidIssuerThrowsAnException(string issuer)
    {
        // Arrange
        var builder = new OpenIddictServerBuilder(new ServiceCollection());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.AddIssuers(issuer));

        Assert.StartsWith(SR.GetResourceString(SR.ID0924), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SetIssuerResolver_ResolverIsRegisteredAndResolutionIsEnabled()
    {
        // Arrange
        var services = new ServiceCollection().AddOptions();
        var builder = new OpenIddictServerBuilder(services);

        // Act
        builder.SetIssuerResolver<NullIssuerResolver>();
        builder.SetIssuerCredentialsProvider<NullCredentialsProvider>();

        // Assert
        using var provider = services.BuildServiceProvider();
        Assert.True(provider.GetRequiredService<IOptions<OpenIddictServerOptions>>().Value.EnableIssuerResolution);
        Assert.IsType<NullIssuerResolver>(provider.GetRequiredService<IOpenIddictServerIssuerResolver>());
        Assert.IsType<NullCredentialsProvider>(provider.GetRequiredService<IOpenIddictServerIssuerCredentialsProvider>());
    }

    [Fact]
    public void Validate_DefaultOptionsDontEnableIssuerResolution()
    {
        // Arrange
        var options = new OpenIddictServerOptions();

        // Act and assert
        Assert.False(options.EnableIssuerResolution);
        Assert.Empty(options.Issuers);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenStaticIssuerIsUsedWithIssuerResolution()
    {
        // Arrange
        var options = CreateOptions();
        options.Issuer = new Uri("https://contoso.com/");

        // Act
        var failures = Validate(options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0923), failures, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenInvalidIssuerIsRegistered()
    {
        // Arrange
        var options = CreateOptions();
        options.Issuers.Add(new Uri("https://contoso.com/?tenant=1"));

        // Act
        var failures = Validate(options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0924), failures, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenFeatureRequiringStaticIssuerIsEnabled()
    {
        // Arrange
        var options = CreateOptions();
        options.MtlsTokenEndpointAliasUri = new Uri("https://mtls.contoso.com/connect/token");

        // Act
        var failures = Validate(options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0927), failures, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData("https://contoso.com/connect/token", true)]
    [InlineData("/connect/token", true)]
    [InlineData("connect/token", false)]
    public void Validate_ReturnsAnErrorWhenEndpointUriIsNotRelativeToIssuer(string uri, bool error)
    {
        // Arrange
        var options = CreateOptions();
        options.TokenEndpointUris.Add(new Uri(uri, UriKind.RelativeOrAbsolute));

        // Act
        var failures = Validate(options);

        // Assert
        Assert.Equal(error, failures.Contains(SR.GetResourceString(SR.ID0928), StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("https://contoso.com/tenant1/connect/token", "https://contoso.com/tenant1/")]
    [InlineData("https://CONTOSO.com/TENANT1", "https://contoso.com/tenant1/")]
    [InlineData("https://contoso.com/tenant1/nested/connect/token", "https://contoso.com/tenant1/nested")]
    [InlineData("https://contoso.com/tenant10/connect/token", "https://contoso.com/")]
    [InlineData("https://contoso.com/connect/token", "https://contoso.com/")]
    [InlineData("https://fabrikam.com/connect/token", "https://fabrikam.com/")]
    [InlineData("http://contoso.com/connect/token", null)]
    [InlineData("https://contoso.com:8443/connect/token", null)]
    [InlineData("https://www.fabrikam.com/connect/token", null)]
    public void MatchIssuer_ReturnsMostSpecificIssuer(string uri, string? issuer)
    {
        // Arrange
        Uri[] issuers =
        [
            new("https://contoso.com/"),
            new("https://contoso.com/tenant1/"),
            new("https://contoso.com/tenant1/nested"),
            new("https://fabrikam.com")
        ];

        // Act
        var result = OpenIddictServerIssuerResolution.MatchIssuer(issuers, new Uri(uri));

        // Assert
        Assert.Equal(issuer is null ? null : new Uri(issuer), result);
    }

    [Theory]
    [InlineData(Claims.Private.Issuer, "https://contoso.com/tenant1/", "https://contoso.com/tenant1/", true)]
    [InlineData(Claims.Issuer, "https://contoso.com/tenant1/", "https://contoso.com/tenant1/", true)]
    [InlineData(Claims.Issuer, "https://contoso.com", "https://contoso.com/", true)]
    [InlineData(Claims.Issuer, "https://contoso.com/tenant1", "https://contoso.com/tenant1/", false)]
    [InlineData(Claims.Issuer, "https://contoso.com/tenant2/", "https://contoso.com/tenant1/", false)]
    [InlineData(Claims.Issuer, "tenant1", "https://contoso.com/tenant1/", false)]
    public void IsIssuedBy_ReturnsExpectedResult(string type, string value, string issuer, bool result)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(type, value)], "Bearer"));

        // Act and assert
        Assert.Equal(result, OpenIddictServerIssuerResolution.IsIssuedBy(principal, new Uri(issuer)));
    }

    [Fact]
    public void IsIssuedBy_ReturnsFalseWhenNoIssuerClaimIsPresent()
        => Assert.False(OpenIddictServerIssuerResolution.IsIssuedBy(
            new ClaimsPrincipal(new ClaimsIdentity()), new Uri("https://contoso.com/")));

    private static OpenIddictServerOptions CreateOptions() => new()
    {
        EnableIssuerResolution = true,
        TimeProvider = TimeProvider.System
    };

    private static string[] Validate(OpenIddictServerOptions options)
    {
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());

        return [.. configuration.Validate(name: null, options).Failures ?? []];
    }

    private sealed class NullIssuerResolver : IOpenIddictServerIssuerResolver
    {
        public ValueTask<Uri?> ResolveIssuerAsync(OpenIddictServerIssuerResolutionContext context) => new((Uri?) null);
    }

    private sealed class NullCredentialsProvider : IOpenIddictServerIssuerCredentialsProvider
    {
        public ValueTask<OpenIddictServerCredentials?> GetCredentialsAsync(
            Uri issuer, IServiceProvider provider, CancellationToken cancellationToken) => new((OpenIddictServerCredentials?) null);
    }
}
