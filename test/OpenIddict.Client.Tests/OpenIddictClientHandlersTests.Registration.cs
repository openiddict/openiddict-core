using System.Collections.Immutable;
using System.Net.Http;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Client.SystemNetHttp;
using Xunit;
using static OpenIddict.Client.OpenIddictClientEvents;
using static OpenIddict.Client.OpenIddictClientModels;

namespace OpenIddict.Client.Tests;

public class OpenIddictClientHandlersRegistrationTests
{
    [Fact]
    public async Task ExtractRegistrationEndpoint_EndpointIsExtracted()
    {
        // Arrange
        using var provider = CreateProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        var context = new HandleConfigurationResponseContext(CreateTransaction(provider))
        {
            Response = new OpenIddictResponse(JsonSerializer.Deserialize<JsonElement>(
                """{ "registration_endpoint": "https://www.contoso.com/connect/register" }"""))
        };

        // Act
        await new OpenIddictClientHandlers.Discovery.ExtractRegistrationEndpoint().HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
        Assert.Equal(new Uri("https://www.contoso.com/connect/register"), context.Configuration.RegistrationEndpoint);
    }

    [Fact]
    public async Task ExtractRegistrationEndpoint_InvalidEndpointCausesAnError()
    {
        // Arrange
        using var provider = CreateProvider();

        var context = new HandleConfigurationResponseContext(CreateTransaction(provider))
        {
            Response = new OpenIddictResponse(JsonSerializer.Deserialize<JsonElement>(
                """{ "registration_endpoint": "/connect/register" }"""))
        };

        // Act
        await new OpenIddictClientHandlers.Discovery.ExtractRegistrationEndpoint().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.FormatID2100(Metadata.RegistrationEndpoint), context.ErrorDescription);
    }

    [Theory]
    [InlineData("""{ "client_id": 42 }""", ClientMetadata.ClientId)]
    [InlineData("""{ "client_id": "Fabrikam", "client_id_issued_at": "now" }""", ClientMetadata.ClientIdIssuedAt)]
    [InlineData("""{ "client_id": "Fabrikam", "registration_access_token": [ "token" ] }""", ClientMetadata.RegistrationAccessToken)]
    public async Task ValidateWellKnownParameters_InvalidParameterTypeCausesAnError(string payload, string name)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = new HandleRegistrationResponseContext(CreateTransaction(provider))
        {
            Request = new OpenIddictRequest(),
            Response = new OpenIddictResponse(JsonSerializer.Deserialize<JsonElement>(payload))
        };

        // Act
        await new OpenIddictClientHandlers.Registration.ValidateWellKnownParameters().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.FormatID2107(name), context.ErrorDescription);
    }

    [Theory]
    [InlineData(Errors.InvalidRedirectUri, Errors.InvalidRedirectUri)]
    [InlineData(Errors.InvalidClientMetadata, Errors.InvalidClientMetadata)]
    [InlineData(Errors.UnapprovedSoftwareStatement, Errors.UnapprovedSoftwareStatement)]
    [InlineData(Errors.InvalidToken, Errors.InvalidToken)]
    [InlineData("custom_error", Errors.ServerError)]
    public async Task HandleErrorResponse_ErrorsAreMapped(string error, string expected)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = new HandleRegistrationResponseContext(CreateTransaction(provider))
        {
            Request = new OpenIddictRequest(),
            Response = new OpenIddictResponse { Error = error }
        };

        // Act
        await new OpenIddictClientHandlers.Registration.HandleErrorResponse().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(expected, context.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2415), context.ErrorDescription);
    }

    [Theory]
    [InlineData("POST", true)]
    [InlineData("PUT", true)]
    [InlineData("GET", false)]
    [InlineData("DELETE", false)]
    public async Task SystemNetHttpHandlers_RequestIsCorrectlyPrepared(string method, bool payload)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = new PrepareRegistrationRequestContext(CreateTransaction(provider))
        {
            AccessToken = "registration-token",
            RemoteUri = new Uri("https://www.contoso.com/connect/register?client_id=Fabrikam"),
            Request = new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ["redirect_uris"] = new OpenIddictParameter(ImmutableArray.Create<string?>("https://www.fabrikam.com/callback"))
            },
            RequestMethod = method
        };

        // Act
        await new OpenIddictClientSystemNetHttpHandlers.Registration.PrepareRegistrationHttpRequest().HandleAsync(context);
        await new OpenIddictClientSystemNetHttpHandlers.Registration.AttachBearerAccessToken().HandleAsync(context);
        await new OpenIddictClientSystemNetHttpHandlers.Registration.AttachJsonHttpParameters().HandleAsync(context);

        // Assert
        using var request = context.Transaction.GetProperty<HttpRequestMessage>(typeof(HttpRequestMessage).FullName!)!;

        Assert.Equal(method, request.Method.Method);
        Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
        Assert.Equal("registration-token", request.Headers.Authorization?.Parameter);

        if (payload)
        {
            Assert.NotNull(request.Content);
            Assert.Equal("application/json", request.Content.Headers.ContentType?.MediaType);

            using var document = JsonDocument.Parse(await request.Content.ReadAsStringAsync());
            Assert.Equal("Fabrikam", document.RootElement.GetProperty("client_id").GetString());
            Assert.Equal("https://www.fabrikam.com/callback",
                document.RootElement.GetProperty("redirect_uris")[0].GetString());
        }

        else
        {
            Assert.Null(request.Content);
        }
    }

    [Fact]
    public async Task RegisterAsync_RegistrationEndpointIsResolvedFromTheServerConfiguration()
    {
        // Arrange
        BaseRegistrationContext? sent = null;

        using var provider = CreateProvider(options =>
        {
            options.AddEventHandler<ApplyRegistrationRequestContext>(builder => builder.UseInlineHandler(context =>
            {
                sent = context;
                return ValueTask.CompletedTask;
            }));

            options.AddEventHandler<ExtractRegistrationResponseContext>(builder => builder.UseInlineHandler(context =>
            {
                context.Response = new OpenIddictResponse(JsonSerializer.Deserialize<JsonElement>("""
                    {
                      "client_id": "Fabrikam",
                      "client_secret": "secret",
                      "client_id_issued_at": 1700000000,
                      "client_secret_expires_at": 0,
                      "registration_access_token": "registration-token",
                      "registration_client_uri": "https://www.contoso.com/connect/register?client_id=Fabrikam"
                    }
                    """));

                return ValueTask.CompletedTask;
            }));
        });

        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var result = await service.RegisterAsync(new ClientRegistrationRequest
        {
            InitialAccessToken = "initial-token",
            Metadata = new(StringComparer.Ordinal)
            {
                [ClientMetadata.GrantTypes] = new OpenIddictParameter(ImmutableArray.Create<string?>(GrantTypes.ClientCredentials))
            }
        });

        // Assert
        Assert.NotNull(sent);
        Assert.Equal("POST", sent.RequestMethod);
        Assert.Equal("initial-token", sent.AccessToken);
        Assert.Equal(new Uri("https://www.contoso.com/connect/register"), sent.RemoteUri);
        Assert.Equal(GrantTypes.ClientCredentials, ((ImmutableArray<string?>?) sent.Request[ClientMetadata.GrantTypes])?[0]);

        Assert.Equal("Fabrikam", result.ClientId);
        Assert.Equal("secret", result.ClientSecret);
        Assert.Null(result.ClientSecretExpiresAt);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1700000000), result.ClientIdIssuedAt);
        Assert.Equal("registration-token", result.RegistrationAccessToken);
        Assert.Equal(new Uri("https://www.contoso.com/connect/register?client_id=Fabrikam"), result.RegistrationClientUri);
    }

    [Fact]
    public async Task RegisterAsync_ThrowsAnExceptionWhenNoRegistrationEndpointIsAvailable()
    {
        // Arrange
        using var provider = CreateProvider(configuration: new OpenIddictConfiguration
        {
            Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute)
        });

        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await service.RegisterAsync(new ClientRegistrationRequest()));

        Assert.Equal(SR.GetResourceString(SR.ID0809), exception.Message);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    public async Task ClientConfigurationMethods_RequestsAreSentToTheClientConfigurationEndpoint(string method)
    {
        // Arrange
        BaseRegistrationContext? sent = null;

        using var provider = CreateProvider(options =>
        {
            options.AddEventHandler<ApplyRegistrationRequestContext>(builder => builder.UseInlineHandler(context =>
            {
                sent = context;
                return ValueTask.CompletedTask;
            }));

            options.AddEventHandler<ExtractRegistrationResponseContext>(builder => builder.UseInlineHandler(context =>
            {
                context.Response = new OpenIddictResponse();
                return ValueTask.CompletedTask;
            }));
        });

        var service = provider.GetRequiredService<OpenIddictClientService>();
        var request = new ClientConfigurationRequest
        {
            Metadata = new(StringComparer.Ordinal)
            {
                [ClientMetadata.ClientName] = "Updated"
            },
            RegistrationAccessToken = "registration-token",
            RegistrationClientUri = new Uri("https://www.contoso.com/connect/register?client_id=Fabrikam")
        };

        // Act
        var result = method switch
        {
            "GET" => await service.GetRegistrationAsync(request),
            "PUT" => await service.UpdateRegistrationAsync(request),
            _     => await service.DeleteRegistrationAsync(request)
        };

        // Assert
        Assert.NotNull(sent);
        Assert.Equal(method, sent.RequestMethod);
        Assert.Equal("registration-token", sent.AccessToken);
        Assert.Equal(request.RegistrationClientUri, sent.RemoteUri);
        Assert.NotNull(result.RegistrationResponse);

        if (method is "PUT")
        {
            Assert.Equal("Fabrikam", sent.Request.ClientId);
            Assert.Equal("Updated", (string?) sent.Request[ClientMetadata.ClientName]);
        }

        else
        {
            Assert.Equal(0, sent.Request.Count);
        }
    }

    [Fact]
    public async Task ClientConfigurationMethods_ThrowAnExceptionForMissingRegistrationAccessToken()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act and assert
        await Assert.ThrowsAsync<ArgumentException>(async () => await service.GetRegistrationAsync(new ClientConfigurationRequest
        {
            RegistrationAccessToken = string.Empty,
            RegistrationClientUri = new Uri("https://www.contoso.com/connect/register?client_id=Fabrikam")
        }));
    }

    private static ServiceProvider CreateProvider(
        Action<OpenIddictClientBuilder>? configure = null, OpenIddictConfiguration? configuration = null)
    {
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddClient(options =>
            {
                options.AllowClientCredentialsFlow();

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                options.AddRegistration(new OpenIddictClientRegistration
                {
                    ClientId = "Fabrikam",
                    Configuration = configuration ?? new OpenIddictConfiguration
                    {
                        Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute),
                        RegistrationEndpoint = new Uri("https://www.contoso.com/connect/register", UriKind.Absolute)
                    },
                    Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute)
                });

                configure?.Invoke(options);
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
}
