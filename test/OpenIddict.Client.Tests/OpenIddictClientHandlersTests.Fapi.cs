using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using static OpenIddict.Client.OpenIddictClientEvents;
using static OpenIddict.Client.OpenIddictClientHandlerFilters;
using static OpenIddict.Client.OpenIddictClientHandlers;

namespace OpenIddict.Client.Tests;

public class OpenIddictClientHandlersFapiTests
{
    [Fact]
    public void PostConfigure_ProfileDefaultsAreAppliedToRegistration()
    {
        // Arrange
        using var provider = CreateProvider(registration => registration.SigningCredentials.Add(
            new SigningCredentials(new RsaSecurityKey(RSA.Create(2048)), SecurityAlgorithms.RsaSha256)));

        // Act
        var registration = GetRegistration(provider);

        // Assert
        Assert.Equal(ClientTypes.Confidential, registration.ClientType);
        Assert.True(registration.ClientAuthenticationMethods.SetEquals(OpenIddictClientFapi2Profile.ClientAuthenticationMethods));
        Assert.Equal([CodeChallengeMethods.Sha256], registration.CodeChallengeMethods);
        Assert.Equal([ResponseTypes.Code], registration.ResponseTypes);
        Assert.Contains(GrantTypes.AuthorizationCode, registration.GrantTypes);
        Assert.Contains(GrantTypes.RefreshToken, registration.GrantTypes);
        Assert.DoesNotContain(GrantTypes.Implicit, registration.GrantTypes);
        Assert.DoesNotContain(GrantTypes.Password, registration.GrantTypes);
        Assert.Contains(TokenBindingMethods.Private.DPoP, registration.TokenBindingMethods);
        Assert.Contains(TokenBindingMethods.Private.TlsClientCertificate, registration.TokenBindingMethods);
        Assert.True(registration.IntrospectionResponseSigningAlgorithms.SetEquals(OpenIddictClientFapi2Profile.SigningAlgorithms));
        Assert.Equal(OpenIddictClientFapi2Profile.SigningAlgorithms, registration.TokenValidationParameters.ValidAlgorithms, StringComparer.Ordinal);
        Assert.Equal(SecurityAlgorithms.RsaSsaPssSha256, Assert.Single(registration.SigningCredentials,
            static credentials => credentials.Key is RsaSecurityKey).Algorithm);
        Assert.NotNull(registration.DPoPSigningCredentials);
    }

    [Fact]
    public void PostConfigure_ExplicitRegistrationSettingsAreNotOverridden()
    {
        // Arrange
        using var provider = CreateProvider(registration =>
        {
            registration.ClientAuthenticationMethods.Add(ClientAuthenticationMethods.PrivateKeyJwt);
            registration.TokenBindingMethods.Add(TokenBindingMethods.Private.DPoP);
        });

        // Act
        var registration = GetRegistration(provider);

        // Assert
        Assert.Equal([ClientAuthenticationMethods.PrivateKeyJwt], registration.ClientAuthenticationMethods);
        Assert.Equal([TokenBindingMethods.Private.DPoP], registration.TokenBindingMethods);
    }

    [Fact]
    public void PostConfigure_MessageSigningProfileEnablesSecurityProfileAndSignedMessages()
    {
        // Arrange
        using var provider = CreateProvider(registration =>
        {
            registration.EnableFapi2SecurityProfile = false;
            registration.EnableFapi2MessageSigningProfile = true;
        });

        // Act
        var registration = GetRegistration(provider);

        // Assert
        Assert.True(registration.EnableFapi2SecurityProfile);
        Assert.True(registration.UseSignedRequestObjects);
        Assert.True(registration.RequireJsonWebTokenIntrospectionResponses);
    }

    [Fact]
    public void PostConfigure_ProfileIsNotAppliedWhenDisabled()
    {
        // Arrange
        using var provider = CreateProvider(registration => registration.EnableFapi2SecurityProfile = false);

        // Act
        var registration = GetRegistration(provider);

        // Assert
        Assert.Empty(registration.ClientAuthenticationMethods);
        Assert.Empty(registration.CodeChallengeMethods);
        Assert.Empty(registration.ResponseTypes);
        Assert.Null(registration.TokenValidationParameters.ValidAlgorithms);
    }

    public static TheoryData<string, Action<OpenIddictClientRegistration>> InvalidRegistrations => new()
    {
        { SR.FormatID0973("Contoso"), registration => registration.ClientType = ClientTypes.Public },
        { SR.FormatID0974("Contoso"), registration => registration.DisablePushedAuthorizationRequests = true },
        { SR.FormatID0975("Contoso"), registration => registration.CodeChallengeMethods.Add(CodeChallengeMethods.Plain) },
        { SR.FormatID0976("Contoso"), registration => registration.ClientAuthenticationMethods.Add(ClientAuthenticationMethods.ClientSecretPost) },
        { SR.FormatID0977("Contoso"), registration => registration.GrantTypes.Add(GrantTypes.Password) },
        { SR.FormatID0977("Contoso"), registration => registration.ResponseTypes.Add(ResponseTypes.Code + " " + ResponseTypes.IdToken) },
        { SR.FormatID0978("Contoso"), registration => registration.TokenBindingMethods.Add("custom") },
        { SR.FormatID0979("Contoso"), registration => registration.DPoPSigningCredentials = new SigningCredentials(
            new RsaSecurityKey(RSA.Create(2048)), SecurityAlgorithms.RsaSha256) },
        { SR.FormatID0979("Contoso"), registration => registration.SigningCredentials.Add(new SigningCredentials(
            new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP384)), SecurityAlgorithms.EcdsaSha384)) },
        { SR.FormatID0980("Contoso"), registration => registration.SigningCredentials.Clear() }
    };

    [Theory]
    [MemberData(nameof(InvalidRegistrations))]
    public void Validate_NonCompliantRegistrationIsRejected(string message, Action<OpenIddictClientRegistration> configuration)
    {
        // Arrange
        using var provider = CreateProvider(registration =>
        {
            registration.ClientSecret = null;
            configuration(registration);
        });

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(() => GetRegistration(provider));
        Assert.Contains(message, exception.Failures, StringComparer.Ordinal);
    }

    [Fact]
    public void Validate_CompliantRegistrationIsAccepted()
    {
        // Arrange
        using var provider = CreateProvider();

        // Act and assert
        Assert.True(GetRegistration(provider).EnableFapi2SecurityProfile);
    }

    [Fact]
    public async Task RequireFapi2SecurityProfileEnabled_ReturnsFalseWhenProfileIsDisabled()
    {
        // Arrange
        using var provider = CreateProvider(registration => registration.EnableFapi2SecurityProfile = false);
        var context = CreateAuthenticationContext(provider);

        // Act and assert
        Assert.False(await new RequireFapi2SecurityProfileEnabled().IsActiveAsync(context));
    }

    [Fact]
    public async Task RequireFapi2SecurityProfileEnabled_ReturnsTrueWhenProfileIsEnabled()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateAuthenticationContext(provider);

        // Act and assert
        Assert.True(await new RequireFapi2SecurityProfileEnabled().IsActiveAsync(context));
    }

    [Fact]
    public async Task ValidateAuthorizationResponseIssuer_RejectsResponseWhenServerDoesNotAdvertiseIssParameter()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateAuthenticationContext(provider);
        context.Request = new OpenIddictRequest();
        context.Request.SetParameter(Parameters.Iss, "https://www.contoso.com/");

        // Act
        await new Fapi.ValidateAuthorizationResponseIssuer().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(Errors.InvalidRequest, context.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2486), context.ErrorDescription);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("https://www.fabrikam.com/")]
    public async Task ValidateAuthorizationResponseIssuer_RejectsMissingOrInvalidIssParameter(string? issuer)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateAuthenticationContext(provider);
        context.Configuration.AuthorizationResponseIssParameterSupported = true;
        context.Request = new OpenIddictRequest();
        context.Request.SetParameter(Parameters.Iss, issuer);

        // Act
        await new Fapi.ValidateAuthorizationResponseIssuer().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(Errors.InvalidRequest, context.Error);
    }

    [Fact]
    public async Task ValidateAuthorizationResponseIssuer_AcceptsMatchingIssParameter()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateAuthenticationContext(provider);
        context.Configuration.AuthorizationResponseIssParameterSupported = true;
        context.Request = new OpenIddictRequest();
        context.Request.SetParameter(Parameters.Iss, "https://www.contoso.com/");

        // Act
        await new Fapi.ValidateAuthorizationResponseIssuer().HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
    }

    [Theory]
    [InlineData(GrantTypes.Password)]
    [InlineData(GrantTypes.Implicit)]
    public async Task ValidateAuthenticationGrantType_ThrowsForDisallowedGrantTypes(string type)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateAuthenticationContext(provider);
        context.GrantType = type;

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await new Fapi.ValidateAuthenticationGrantType().HandleAsync(context));
        Assert.Equal(SR.FormatID0983(type), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(ClientAuthenticationMethods.None)]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic)]
    [InlineData(ClientAuthenticationMethods.ClientSecretPost)]
    public async Task ValidateTokenEndpointClientAuthenticationMethod_ThrowsForDisallowedMethods(string? method)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateAuthenticationContext(provider);
        context.TokenEndpointClientAuthenticationMethod = method;

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await new Fapi.ValidateTokenEndpointClientAuthenticationMethod().HandleAsync(context));
        Assert.Equal(SR.FormatID0984(Metadata.TokenEndpoint), exception.Message);
    }

    [Theory]
    [InlineData(ClientAuthenticationMethods.PrivateKeyJwt)]
    [InlineData(ClientAuthenticationMethods.TlsClientAuth)]
    [InlineData(ClientAuthenticationMethods.SelfSignedTlsClientAuth)]
    public async Task ValidateTokenEndpointClientAuthenticationMethod_AcceptsAllowedMethods(string method)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateAuthenticationContext(provider);
        context.TokenEndpointClientAuthenticationMethod = method;

        // Act
        await new Fapi.ValidateTokenEndpointClientAuthenticationMethod().HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
    }

    [Fact]
    public async Task ValidateTokenEndpointTokenBindingMethod_ThrowsWhenNoBindingMethodWasNegotiated()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateAuthenticationContext(provider);

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await new Fapi.ValidateTokenEndpointTokenBindingMethod().HandleAsync(context));
        Assert.Equal(SR.GetResourceString(SR.ID0985), exception.Message);
    }

    [Theory]
    [InlineData(TokenBindingMethods.Private.DPoP)]
    [InlineData(TokenBindingMethods.Private.TlsClientCertificate)]
    [InlineData(TokenBindingMethods.Private.SelfSignedTlsClientCertificate)]
    public async Task ValidateTokenEndpointTokenBindingMethod_AcceptsSenderConstrainingMethods(string method)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateAuthenticationContext(provider);
        context.TokenEndpointTokenBindingMethod = method;

        // Act
        await new Fapi.ValidateTokenEndpointTokenBindingMethod().HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
    }

    [Fact]
    public async Task AttachTokenEndpointClientAuthenticationMethod_ClientSecretIsNotNegotiatedForProfileRegistration()
    {
        // Arrange
        using var provider = CreateProvider(registration => registration.ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw");
        var context = CreateAuthenticationContext(provider);
        context.Configuration.TokenEndpointAuthMethodsSupported.Add(ClientAuthenticationMethods.ClientSecretPost);
        context.Configuration.TokenEndpointAuthMethodsSupported.Add(ClientAuthenticationMethods.PrivateKeyJwt);

        // Act
        await new AttachTokenEndpointClientAuthenticationMethod().HandleAsync(context);
        await new Fapi.ValidateTokenEndpointClientAuthenticationMethod().HandleAsync(context);

        // Assert
        Assert.Equal(ClientAuthenticationMethods.PrivateKeyJwt, context.TokenEndpointClientAuthenticationMethod);
    }

    [Theory]
    [InlineData(GrantTypes.Implicit, ResponseTypes.IdToken)]
    [InlineData(GrantTypes.AuthorizationCode, "code id_token")]
    [InlineData(null, ResponseTypes.None)]
    public async Task ValidateChallengeGrantType_ThrowsForDisallowedFlows(string? type, string response)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.GrantType = type;
        context.ResponseType = response;

        // Act and assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await new Fapi.ValidateChallengeGrantType().HandleAsync(context));
    }

    [Fact]
    public async Task ValidateChallengeGrantType_AcceptsCodeFlow()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);

        // Act
        await new Fapi.ValidateChallengeGrantType().HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(CodeChallengeMethods.Plain)]
    public async Task ValidateCodeChallengeMethod_ThrowsWhenS256IsNotUsed(string? method)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.CodeChallengeMethod = method;
        context.CodeChallenge = method is null ? null : "challenge";

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await new Fapi.ValidateCodeChallengeMethod().HandleAsync(context));
        Assert.Equal(SR.GetResourceString(SR.ID0982), exception.Message);
    }

    [Fact]
    public async Task AttachCodeChallengeParameters_ThrowsWhenServerDoesNotSupportS256()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.Configuration.CodeChallengeMethodsSupported.Add(CodeChallengeMethods.Plain);

        // Act
        await new AttachCodeChallengeParameters().HandleAsync(context);

        // Assert
        Assert.Null(context.CodeChallengeMethod);
        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await new Fapi.ValidateCodeChallengeMethod().HandleAsync(context));
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_ThrowsWhenServerDoesNotSupportPushedAuthorizationRequests()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);

        // Act
        await new EvaluatePushedAuthorizationRequest().HandleAsync(context);

        // Assert
        Assert.False(context.SendPushedAuthorizationRequest);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await new Fapi.ValidatePushedAuthorizationRequest().HandleAsync(context));
        Assert.Equal(SR.GetResourceString(SR.ID0981), exception.Message);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_AcceptsPushedAuthorizationRequests()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.Configuration.PushedAuthorizationEndpoint = new Uri("https://www.contoso.com/connect/par");

        // Act
        await new EvaluatePushedAuthorizationRequest().HandleAsync(context);
        await new Fapi.ValidatePushedAuthorizationRequest().HandleAsync(context);

        // Assert
        Assert.True(context.SendPushedAuthorizationRequest);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationEndpointClientAuthenticationMethod_ThrowsForClientSecret()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.PushedAuthorizationEndpointClientAuthenticationMethod = ClientAuthenticationMethods.ClientSecretBasic;

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await new Fapi.ValidatePushedAuthorizationEndpointClientAuthenticationMethod().HandleAsync(context));
        Assert.Equal(SR.FormatID0984(Metadata.PushedAuthorizationRequestEndpoint), exception.Message);
    }

    [Fact]
    public void DefaultHandlers_IncludeFapiHandlers()
    {
        // Act and assert
        Assert.All(Fapi.DefaultHandlers, descriptor => Assert.Contains(descriptor, OpenIddictClientHandlers.DefaultHandlers));
    }

    private static OpenIddictClientRegistration GetRegistration(IServiceProvider provider)
        => provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue.Registrations[0];

    private static ServiceProvider CreateProvider(Action<OpenIddictClientRegistration>? configuration = null)
    {
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddClient(options =>
            {
                options.AllowAuthorizationCodeFlow()
                       .AllowImplicitFlow()
                       .AllowPasswordFlow()
                       .AllowRefreshTokenFlow();

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                options.EnableDPoPTokenBinding();

                options.SetRedirectionEndpointUris("https://www.fabrikam.com/callback");

                var registration = new OpenIddictClientRegistration
                {
                    ClientId = "Fabrikam",
                    Configuration = new OpenIddictConfiguration
                    {
                        Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute),
                        TokenEndpoint = new Uri("https://www.contoso.com/connect/token", UriKind.Absolute)
                    },
                    EnableFapi2SecurityProfile = true,
                    Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute),
                    RegistrationId = "Contoso",
                    SigningCredentials =
                    {
                        new SigningCredentials(new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256)), SecurityAlgorithms.EcdsaSha256)
                    }
                };

                configuration?.Invoke(registration);

                options.AddRegistration(registration);
            });

        return services.BuildServiceProvider();
    }

    private static OpenIddictClientTransaction CreateTransaction(IServiceProvider provider)
    {
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        return new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Configuration = new OpenIddictConfiguration(),
            Options = options,
            Registration = options.Registrations[0],
            ServiceProvider = provider
        };
    }

    private static ProcessAuthenticationContext CreateAuthenticationContext(IServiceProvider provider)
        => new(CreateTransaction(provider))
        {
            GrantType = GrantTypes.AuthorizationCode
        };

    private static ProcessChallengeContext CreateChallengeContext(IServiceProvider provider)
        => new(CreateTransaction(provider))
        {
            GrantType = GrantTypes.AuthorizationCode,
            ResponseType = ResponseTypes.Code
        };
}
