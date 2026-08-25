using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace OpenIddict.Validation.Tests;

public class OpenIddictValidationConfigurationTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullProvider()
    {
        // Arrange
        var provider = (IServiceProvider) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictValidationConfiguration(provider));
        Assert.Equal("provider", exception.ParamName);
    }

    [Fact]
    public void PostConfigure_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => configuration.PostConfigure(name: null, options: null!));
        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void PostConfigure_SetsTimeProviderToSystemWhenNotRegistered()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = new OpenIddictValidationOptions();

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

        var configuration = new OpenIddictValidationConfiguration(services.BuildServiceProvider());
        var options = new OpenIddictValidationOptions();

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

        var configuration = new OpenIddictValidationConfiguration(services.BuildServiceProvider());
        var options = new OpenIddictValidationOptions { TimeProvider = explicitProvider };

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.Same(explicitProvider, options.TimeProvider);
    }

    [Fact]
    public void PostConfigure_CreatesStaticConfigurationManagerFromStaticConfiguration()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = new OpenIddictValidationOptions
        {
            Issuer = new Uri("https://www.contoso.com/"),
            Configuration = new OpenIddictConfiguration()
        };

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.IsType<StaticConfigurationManager<OpenIddictConfiguration>>(options.ConfigurationManager);
        Assert.Equal(options.Issuer, options.Configuration.Issuer);
    }

    [Fact]
    public void PostConfigure_AttachesEncryptionKeysToTokenValidationParameters()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = new OpenIddictValidationOptions();

        var key = new SymmetricSecurityKey(new byte[32]);
        options.EncryptionCredentials.Add(new EncryptingCredentials(
            key,
            SecurityAlgorithms.Aes256KW,
            SecurityAlgorithms.Aes256CbcHmacSha512));

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.Contains(key, options.TokenValidationParameters.TokenDecryptionKeys);
    }

    [Fact]
    public void Validate_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => configuration.Validate(name: null, options: null!));
        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenJsonWebTokenHandlerIsMissing()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.JsonWebTokenHandler = null!;

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0075), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenNoIssuerOrConfigurationInformationIsProvided()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0128), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenIssuerIsInvalid()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.Issuer = new Uri("/relative", UriKind.Relative);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0136), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenIssuerContainsQueryOrFragment()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.Issuer = new Uri("https://www.contoso.com/?query=parameter#fragment");

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0137), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenConfigurationIssuerDoesNotMatchOptionsIssuer()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.Issuer = new Uri("https://www.contoso.com/");
        options.Configuration = new OpenIddictConfiguration
        {
            Issuer = new Uri("https://www.fabrikam.com/")
        };

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0394), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenConfigurationManagerIsMissing()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.Issuer = new Uri("https://www.contoso.com/");

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0523), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenNonStaticConfigurationManagerIsUsedWithoutRequiredHandlers()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.Issuer = new Uri("https://www.contoso.com/");
        options.ConfigurationManager = Mock.Of<IConfigurationManager<OpenIddictConfiguration>>();

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0135), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenIntrospectionHandlersAreMissing()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.ValidationType = OpenIddictValidationType.Introspection;
        options.Issuer = new Uri("https://www.contoso.com/");
        options.ConfigurationEndpoint = new Uri("https://www.contoso.com/.well-known/openid-configuration");
        options.ClientId = "client_id";
        options.ClientSecret = "client_secret";
        options.ConfigurationManager = new StaticConfigurationManager<OpenIddictConfiguration>(new OpenIddictConfiguration());

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0129), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenIntrospectionIssuerAndConfigurationEndpointAreMissing()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.ValidationType = OpenIddictValidationType.Introspection;
        options.ClientId = "client_id";
        options.ClientSecret = "client_secret";
        options.ConfigurationManager = new StaticConfigurationManager<OpenIddictConfiguration>(new OpenIddictConfiguration());
        options.Handlers.Add(OpenIddictValidationHandlerDescriptor.CreateBuilder<ApplyIntrospectionRequestContext>()
            .UseSingletonHandler<CustomIntrospectionHandler>().Build());

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0130), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenIntrospectionClientCredentialsAreMissing()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.ValidationType = OpenIddictValidationType.Introspection;
        options.Issuer = new Uri("https://www.contoso.com/");
        options.ConfigurationEndpoint = new Uri("https://www.contoso.com/.well-known/openid-configuration");
        options.ConfigurationManager = new StaticConfigurationManager<OpenIddictConfiguration>(new OpenIddictConfiguration());

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0131), result.Failures!, StringComparer.Ordinal);
        Assert.Contains(SR.GetResourceString(SR.ID0132), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenAuthorizationEntryValidationIsEnabledInIntrospectionMode()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.ValidationType = OpenIddictValidationType.Introspection;
        options.Issuer = new Uri("https://www.contoso.com/");
        options.ConfigurationEndpoint = new Uri("https://www.contoso.com/.well-known/openid-configuration");
        options.ClientId = "client_id";
        options.ClientSecret = "client_secret";
        options.EnableAuthorizationEntryValidation = true;
        options.ConfigurationManager = new StaticConfigurationManager<OpenIddictConfiguration>(new OpenIddictConfiguration());

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0133), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenSessionEntryValidationIsEnabledInIntrospectionMode()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.ValidationType = OpenIddictValidationType.Introspection;
        options.Issuer = new Uri("https://www.contoso.com/");
        options.ConfigurationEndpoint = new Uri("https://www.contoso.com/.well-known/openid-configuration");
        options.ClientId = "client_id";
        options.ClientSecret = "client_secret";
        options.EnableSessionEntryValidation = true;
        options.ConfigurationManager = new StaticConfigurationManager<OpenIddictConfiguration>(new OpenIddictConfiguration());

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0133), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenTokenEntryValidationIsEnabledInIntrospectionMode()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.ValidationType = OpenIddictValidationType.Introspection;
        options.Issuer = new Uri("https://www.contoso.com/");
        options.ConfigurationEndpoint = new Uri("https://www.contoso.com/.well-known/openid-configuration");
        options.ClientId = "client_id";
        options.ClientSecret = "client_secret";
        options.EnableTokenEntryValidation = true;
        options.ConfigurationManager = new StaticConfigurationManager<OpenIddictConfiguration>(new OpenIddictConfiguration());

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0133), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_SucceedsForValidIntrospectionConfigurationUsingClientAssertion()
    {
        // Arrange
        var configuration = new OpenIddictValidationConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.ValidationType = OpenIddictValidationType.Introspection;
        options.Issuer = new Uri("https://www.contoso.com/");
        options.ConfigurationEndpoint = new Uri("https://www.contoso.com/.well-known/openid-configuration");
        options.ClientId = "client_id";
        options.ConfigurationManager = new StaticConfigurationManager<OpenIddictConfiguration>(new OpenIddictConfiguration());
        options.SigningCredentials.Add(new SigningCredentials(
            new SymmetricSecurityKey(new byte[32]),
            SecurityAlgorithms.HmacSha256));

        options.Handlers.Add(OpenIddictValidationHandlerDescriptor.CreateBuilder<ApplyIntrospectionRequestContext>()
            .UseSingletonHandler<CustomIntrospectionHandler>().Build());

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.True(result.Succeeded);
    }

    private static OpenIddictValidationOptions CreateBaseOptions()
        => new()
        {
            TimeProvider = TimeProvider.System
        };

    private sealed class CustomIntrospectionHandler : IOpenIddictValidationHandler<ApplyIntrospectionRequestContext>
    {
        public ValueTask HandleAsync(ApplyIntrospectionRequestContext context) => ValueTask.CompletedTask;
    }

    private sealed class FakeTimeProvider : TimeProvider;
}
