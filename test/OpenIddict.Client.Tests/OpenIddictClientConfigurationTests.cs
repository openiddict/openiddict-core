using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;

namespace OpenIddict.Client.Tests;

public class OpenIddictClientConfigurationTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullProvider()
    {
        // Arrange
        var provider = (IServiceProvider) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictClientConfiguration(provider));
        Assert.Equal("provider", exception.ParamName);
    }

    [Fact]
    public void PostConfigure_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => configuration.PostConfigure(name: null, options: null!));
        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void PostConfigure_SetsTimeProviderToSystemWhenNotRegistered()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = new OpenIddictClientOptions();

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.Same(TimeProvider.System, options.TimeProvider);
    }

    [Fact]
    public void PostConfigure_UsesRegisteredTimeProvider()
    {
        // Arrange
        var timeProvider = new FakeTimeProvider();
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(timeProvider);

        var configuration = new OpenIddictClientConfiguration(services.BuildServiceProvider());
        var options = new OpenIddictClientOptions();

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.Same(timeProvider, options.TimeProvider);
    }

    [Fact]
    public void PostConfigure_DoesNotOverrideExplicitlySetTimeProvider()
    {
        // Arrange
        var explicitProvider = new FakeTimeProvider();
        var registeredProvider = new FakeTimeProvider();

        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(registeredProvider);

        var configuration = new OpenIddictClientConfiguration(services.BuildServiceProvider());
        var options = new OpenIddictClientOptions { TimeProvider = explicitProvider };

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.Same(explicitProvider, options.TimeProvider);
    }

    [Fact]
    public void PostConfigure_ComputesDefaultRegistrationIdentifierAndClientType()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());

        var registration = new OpenIddictClientRegistration
        {
            Issuer = new Uri("https://www.contoso.com/"),
            ClientSecret = "secret",
            Configuration = new OpenIddictConfiguration()
        };

        var options = new OpenIddictClientOptions();
        options.Registrations.Add(registration);

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.False(string.IsNullOrEmpty(registration.RegistrationId));
        Assert.Equal(ClientTypes.Confidential, registration.ClientType);
    }

    [Fact]
    public void PostConfigure_AssignsPublicClientTypeWhenNoSecretOrSigningCredentialsAreConfigured()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());

        var registration = new OpenIddictClientRegistration
        {
            Issuer = new Uri("https://www.contoso.com/"),
            Configuration = new OpenIddictConfiguration()
        };

        var options = new OpenIddictClientOptions();
        options.Registrations.Add(registration);

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.Equal(ClientTypes.Public, registration.ClientType);
    }

    [Fact]
    public void PostConfigure_AddsRedirectionUrisFromRegistrations()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());

        var options = new OpenIddictClientOptions();
        options.Registrations.Add(new OpenIddictClientRegistration
        {
            RedirectUri = new Uri("https://www.contoso.com/callback")
        });

        options.Registrations.Add(new OpenIddictClientRegistration
        {
            PostLogoutRedirectUri = new Uri("https://www.contoso.com/logout-callback")
        });

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.Contains(new Uri("https://www.contoso.com/callback"), options.RedirectionEndpointUris);
        Assert.Contains(new Uri("https://www.contoso.com/logout-callback"), options.PostLogoutRedirectionEndpointUris);
    }

    [Fact]
    public void Validate_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => configuration.Validate(name: null, options: null!));
        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenJsonWebTokenHandlerIsMissing()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.JsonWebTokenHandler = null!;

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0075), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenRegistrationIdentifierContainsSeparator()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.Registrations.Add(new OpenIddictClientRegistration
        {
            RegistrationId = "invalid\u001eidentifier",
            Issuer = new Uri("https://www.contoso.com/"),
            ConfigurationManager = new StaticConfigurationManager<OpenIddictConfiguration>(new OpenIddictConfiguration())
        });

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0455), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenRegistrationIdentifierIsMissing()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.Registrations.Add(new OpenIddictClientRegistration
        {
            Issuer = new Uri("https://www.contoso.com/"),
            ConfigurationManager = new StaticConfigurationManager<OpenIddictConfiguration>(new OpenIddictConfiguration())
        });

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0521), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenIssuerIsInvalid()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.Registrations.Add(new OpenIddictClientRegistration
        {
            RegistrationId = "contoso",
            Issuer = new Uri("/relative", UriKind.Relative),
            ConfigurationManager = new StaticConfigurationManager<OpenIddictConfiguration>(new OpenIddictConfiguration())
        });

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0136), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenIssuerContainsQueryOrFragment()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.Registrations.Add(new OpenIddictClientRegistration
        {
            RegistrationId = "contoso",
            Issuer = new Uri("https://www.contoso.com/?query=parameter#fragment"),
            ConfigurationManager = new StaticConfigurationManager<OpenIddictConfiguration>(new OpenIddictConfiguration())
        });

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0137), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenRegistrationConfigurationIssuerDoesNotMatchRegistrationIssuer()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.Registrations.Add(new OpenIddictClientRegistration
        {
            RegistrationId = "contoso",
            Issuer = new Uri("https://www.contoso.com/"),
            Configuration = new OpenIddictConfiguration { Issuer = new Uri("https://www.fabrikam.com/") },
            ConfigurationManager = new StaticConfigurationManager<OpenIddictConfiguration>(new OpenIddictConfiguration())
        });

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0395), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenConfigurationManagerIsMissing()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.Registrations.Add(new OpenIddictClientRegistration
        {
            RegistrationId = "contoso",
            Issuer = new Uri("https://www.contoso.com/")
        });

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0522), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenNonStaticConfigurationManagerIsUsedWithoutRequiredHandlers()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.Registrations.Add(new OpenIddictClientRegistration
        {
            RegistrationId = "contoso",
            Issuer = new Uri("https://www.contoso.com/"),
            ConfigurationManager = Mock.Of<IConfigurationManager<OpenIddictConfiguration>>()
        });

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0313), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenNoFlowIsEnabled()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = new OpenIddictClientOptions();

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0076), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenEndpointUrisAreNotUnique()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        var uri = new Uri("https://www.contoso.com/callback");
        options.RedirectionEndpointUris.Add(uri);
        options.PostLogoutRedirectionEndpointUris.Add(uri);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0285), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenRedirectionEndpointIsMissingForAuthorizationCodeGrant()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.GrantTypes.Add(GrantTypes.AuthorizationCode);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0356), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenStateTokenCredentialsAreMissing()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.RedirectionEndpointUris.Add(new Uri("https://www.contoso.com/callback"));

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0357), result.Failures!);
        Assert.Contains(SR.GetResourceString(SR.ID0358), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenResponseTypeIsInconsistentWithEnabledGrantTypes()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.ResponseTypes.Add(ResponseTypes.Code);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.FormatID0281(ResponseTypes.Code), result.Failures!);
    }

    [Fact]
    public void Validate_SucceedsForConsistentMinimalConfiguration()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.Registrations.Add(new OpenIddictClientRegistration
        {
            RegistrationId = "contoso",
            Issuer = new Uri("https://www.contoso.com/"),
            ConfigurationManager = new StaticConfigurationManager<OpenIddictConfiguration>(new OpenIddictConfiguration())
        });

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenRegistrationIdentifiersAreDuplicated()
    {
        // Arrange
        var configuration = new OpenIddictClientConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        var manager = new StaticConfigurationManager<OpenIddictConfiguration>(new OpenIddictConfiguration());

        options.Registrations.Add(new OpenIddictClientRegistration
        {
            RegistrationId = "duplicate",
            Issuer = new Uri("https://www.contoso.com/"),
            ConfigurationManager = manager
        });

        options.Registrations.Add(new OpenIddictClientRegistration
        {
            RegistrationId = "DUPLICATE",
            Issuer = new Uri("https://www.fabrikam.com/"),
            ConfigurationManager = manager
        });

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0347), result.Failures!);
    }

    private static OpenIddictClientOptions CreateBaseOptions()
    {
        var options = new OpenIddictClientOptions
        {
            TimeProvider = TimeProvider.System
        };

        options.GrantTypes.Add(GrantTypes.ClientCredentials);

        return options;
    }

    private sealed class FakeTimeProvider : TimeProvider;
}
