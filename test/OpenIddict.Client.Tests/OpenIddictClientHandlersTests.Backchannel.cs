using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using static OpenIddict.Client.OpenIddictClientEvents;
using static OpenIddict.Client.OpenIddictClientHandlers;

namespace OpenIddict.Client.Tests;

public class OpenIddictClientHandlersBackchannelTests
{
    [Fact]
    public async Task EvaluateBackchannelAuthenticationRequest_RequestIsSentForCibaGrant()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.LoginHint = "bob@fabrikam.com";

        // Act
        await new EvaluateBackchannelAuthenticationRequest().HandleAsync(context);

        // Assert
        Assert.True(context.SendBackchannelAuthenticationRequest);
    }

    [Theory]
    [InlineData(null, null, null)]
    [InlineData("bob@fabrikam.com", "token", null)]
    [InlineData("bob@fabrikam.com", null, "id_token")]
    public async Task EvaluateBackchannelAuthenticationRequest_ThrowsAnExceptionForInvalidHints(string? hint, string? token, string? identity)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.LoginHint = hint;
        context.LoginHintToken = token;
        context.IdentityTokenHint = identity;

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await new EvaluateBackchannelAuthenticationRequest().HandleAsync(context));

        Assert.Equal(SR.GetResourceString(SR.ID0541), exception.Message);
    }

    [Fact]
    public async Task AttachBackchannelAuthenticationRequestParameters_ParametersAreAttached()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.BindingMessage = "W4SCT";
        context.LoginHint = "bob@fabrikam.com";
        context.RequestedExpiry = TimeSpan.FromSeconds(119.5);
        context.Scopes.Add(Scopes.Profile);

        // Act
        await new AttachBackchannelAuthenticationRequestParameters().HandleAsync(context);

        // Assert
        Assert.NotNull(context.BackchannelAuthenticationRequest);
        Assert.Equal("openid profile", context.BackchannelAuthenticationRequest.Scope);
        Assert.Equal("bob@fabrikam.com", context.BackchannelAuthenticationRequest.LoginHint);
        Assert.Equal("W4SCT", context.BackchannelAuthenticationRequest.BindingMessage);
        Assert.Equal(120, context.BackchannelAuthenticationRequest.RequestedExpiry);
        Assert.Null(context.BackchannelAuthenticationRequest.IdTokenHint);
    }

    [Fact]
    public async Task ValidateAuthenticationRequestId_MissingIdentifierCausesAnError()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateResponseContext(provider, new OpenIddictResponse { ExpiresIn = 120 });

        // Act
        await new Backchannel.ValidateAuthenticationRequestId().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(Errors.ServerError, context.Error);
        Assert.Equal(SR.FormatID2168(Parameters.AuthReqId), context.ErrorDescription);
    }

    [Fact]
    public async Task ValidateExpiration_MissingExpirationCausesAnError()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateResponseContext(provider, new OpenIddictResponse { AuthReqId = "id" });

        // Act
        await new Backchannel.ValidateExpiration().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.FormatID2168(Parameters.ExpiresIn), context.ErrorDescription);
    }

    [Theory]
    [InlineData(Errors.UnknownUserId, Errors.UnknownUserId)]
    [InlineData(Errors.ExpiredLoginHintToken, Errors.ExpiredLoginHintToken)]
    [InlineData(Errors.InvalidClient, Errors.InvalidRequest)]
    [InlineData("custom_error", Errors.ServerError)]
    public async Task HandleErrorResponse_ErrorsAreMapped(string error, string expected)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateResponseContext(provider, new OpenIddictResponse { Error = error });

        // Act
        await new Backchannel.HandleErrorResponse().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(expected, context.Error);
    }

    [Fact]
    public async Task ValidateWellKnownParameters_InvalidAuthenticationRequestIdTypeCausesAnError()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateResponseContext(provider, new OpenIddictResponse(
            JsonSerializer.Deserialize<JsonElement>("""{ "auth_req_id": 42, "expires_in": 120 }""")));

        // Act
        await new Backchannel.ValidateWellKnownParameters().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.FormatID2107(Parameters.AuthReqId), context.ErrorDescription);
    }

    [Fact]
    public async Task ExtractBackchannelAuthenticationEndpoint_MetadataIsExtracted()
    {
        // Arrange
        using var provider = CreateProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        var context = new HandleConfigurationResponseContext(new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Configuration = new OpenIddictConfiguration(),
            Options = options,
            Registration = options.Registrations[0],
            ServiceProvider = provider
        })
        {
            Response = new OpenIddictResponse(JsonSerializer.Deserialize<JsonElement>("""
            {
              "backchannel_authentication_endpoint": "https://www.contoso.com/connect/ciba",
              "backchannel_token_delivery_modes_supported": [ "poll" ],
              "backchannel_user_code_parameter_supported": false
            }
            """))
        };

        // Act
        await new OpenIddictClientHandlers.Discovery.ExtractBackchannelAuthenticationEndpoint().HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
        Assert.Equal(new Uri("https://www.contoso.com/connect/ciba"), context.Configuration.BackchannelAuthenticationEndpoint);
        Assert.Contains(BackchannelTokenDeliveryModes.Poll, context.Configuration.BackchannelTokenDeliveryModesSupported);
        Assert.False(context.Configuration.BackchannelUserCodeParameterSupported);
    }

    private static ServiceProvider CreateProvider()
    {
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddClient(options =>
            {
                options.AllowClientInitiatedBackchannelAuthenticationFlow();

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                options.AddRegistration(new OpenIddictClientRegistration
                {
                    ClientId = "Fabrikam",
                    Configuration = new OpenIddictConfiguration
                    {
                        Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute)
                    },
                    Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute)
                });
            });

        return services.BuildServiceProvider();
    }

    private static ProcessChallengeContext CreateChallengeContext(IServiceProvider provider)
    {
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        return new ProcessChallengeContext(new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Configuration = new OpenIddictConfiguration(),
            Options = options,
            Registration = options.Registrations[0],
            Request = new OpenIddictRequest(),
            ServiceProvider = provider
        })
        {
            ClientId = "Fabrikam",
            GrantType = GrantTypes.Ciba,
            Principal = new ClaimsPrincipal(new ClaimsIdentity())
        };
    }

    private static HandleBackchannelAuthenticationResponseContext CreateResponseContext(
        IServiceProvider provider, OpenIddictResponse response)
    {
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        return new HandleBackchannelAuthenticationResponseContext(new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Configuration = new OpenIddictConfiguration(),
            Options = options,
            Registration = options.Registrations[0],
            ServiceProvider = provider
        })
        {
            Request = new OpenIddictRequest(),
            Response = response
        };
    }
}
