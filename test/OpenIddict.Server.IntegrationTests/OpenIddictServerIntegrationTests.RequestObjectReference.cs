/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Text;
using System.Collections.Immutable;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    private const string ExternalRequestUri = "https://www.fabrikam.com/request_objects/1";

    [Fact]
    public async Task ValidateAuthorizationRequest_ExternalRequestUriIsRejectedWhenReferenceSupportIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRequestObjectServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = ExternalRequestUri
        });

        // Assert
        Assert.Equal(Errors.RequestUriNotSupported, response.Error);
        Assert.Equal(SR.FormatID2028(Parameters.RequestUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2028), response.ErrorUri);
    }

    [Theory]
    [InlineData("http://www.fabrikam.com/request_objects/1")]
    [InlineData("https://user:password@www.fabrikam.com/request_objects/1")]
    [InlineData("/request_objects/1")]
    [InlineData("urn:custom:request_object")]
    public async Task ValidateAuthorizationRequest_InvalidExternalRequestUriIsRejected(string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => ConfigureRequestObjectReferenceServer(options, _ => "request_object"));
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = uri
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestUri, response.Error);
        Assert.Equal(SR.FormatID2460(Parameters.RequestUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2460), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_TooLongExternalRequestUriIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => ConfigureRequestObjectReferenceServer(options, _ => "request_object"));
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = "https://www.fabrikam.com/" + new string('a', 500)
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestUri, response.Error);
        Assert.Equal(SR.FormatID2460(Parameters.RequestUri), response.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestObjectIsResolvedFromExternalRequestUri()
    {
        // Arrange
        Uri? fetched = null;

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRequestObjectReferenceServer(options, uri =>
            {
                fetched = uri;

                return CreateRequestObject(new(StringComparer.Ordinal)
                {
                    [Parameters.Nonce] = "n-0S6_WzA2Mj",
                    [Parameters.RedirectUri] = "http://www.fabrikam.com/path",
                    [Parameters.ResponseType] = ResponseTypes.Token,
                    [Parameters.State] = "af0ifjsldkj"
                });
            });

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Null(context.Request.RequestUri);
                    Assert.Null(context.Request.Request);
                    Assert.Null(context.Request["custom_parameter"]);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = ExternalRequestUri,
            State = "outer_state",
            ["custom_parameter"] = "value"
        });

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(response.AccessToken);
        Assert.Equal("af0ifjsldkj", response.State);
        Assert.Equal(new Uri(ExternalRequestUri), fetched);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_InvalidReferencedRequestObjectIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => ConfigureRequestObjectReferenceServer(options,
            _ => CreateRequestObject(new(StringComparer.Ordinal) { [Parameters.ResponseType] = ResponseTypes.Code },
                audience: "https://www.fabrikam.com/")));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = ExternalRequestUri
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestObject, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2211), response.ErrorDescription);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ValidateAuthorizationRequest_UnretrievableRequestObjectIsRejected(bool exception)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => ConfigureRequestObjectReferenceServer(options,
            _ => exception ? throw new InvalidOperationException() : null));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = ExternalRequestUri
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestUri, response.Error);
        Assert.Equal(SR.FormatID2462(Parameters.RequestUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2462), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestObjectNotMatchingFragmentHashIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => ConfigureRequestObjectReferenceServer(options,
            _ => CreateRequestObject(new(StringComparer.Ordinal) { [Parameters.ResponseType] = ResponseTypes.Code })));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = ExternalRequestUri + "#" + Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes("other")))
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestUri, response.Error);
        Assert.Equal(SR.FormatID2463(Parameters.RequestUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2463), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestObjectMatchingFragmentHashIsAccepted()
    {
        // Arrange
        var token = CreateRequestObject(new(StringComparer.Ordinal)
        {
            [Parameters.Nonce] = "n-0S6_WzA2Mj",
            [Parameters.RedirectUri] = "http://www.fabrikam.com/path",
            [Parameters.ResponseType] = ResponseTypes.Token
        });

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRequestObjectReferenceServer(options, _ => token);

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = ExternalRequestUri + "#" + Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(token)))
        });

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_FragmentHashIsComputedOnUntrimmedContents()
    {
        // Arrange
        var token = CreateRequestObject(new(StringComparer.Ordinal)
        {
            [Parameters.Nonce] = "n-0S6_WzA2Mj",
            [Parameters.RedirectUri] = "http://www.fabrikam.com/path",
            [Parameters.ResponseType] = ResponseTypes.Token
        }) + "\n";

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRequestObjectReferenceServer(options, _ => token);

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = ExternalRequestUri + "#" + Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(token)))
        });

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_ExternalRequestUriIsRejectedWhenPushedAuthorizationRequestsAreRequired()
    {
        // Arrange
        var fetched = false;

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRequestObjectReferenceServer(options, _ =>
            {
                fetched = true;

                return CreateRequestObject(new(StringComparer.Ordinal)
                {
                    [Parameters.Nonce] = "n-0S6_WzA2Mj",
                    [Parameters.RedirectUri] = "http://www.fabrikam.com/path",
                    [Parameters.ResponseType] = ResponseTypes.Token
                });
            });

            options.RequirePushedAuthorizationRequests();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = ExternalRequestUri
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestUri, response.Error);
        Assert.Equal(SR.FormatID2466(Parameters.RequestUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2466), response.ErrorUri);
        Assert.Null(response.AccessToken);
        Assert.False(fetched);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_ReferencedRequestObjectSatisfiesSignedRequestObjectsRequirement()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRequestObjectReferenceServer(options, _ => CreateRequestObject(new(StringComparer.Ordinal)
            {
                [Parameters.Nonce] = "n-0S6_WzA2Mj",
                [Parameters.RedirectUri] = "http://www.fabrikam.com/path",
                [Parameters.ResponseType] = ResponseTypes.Token
            }));

            options.RequireSignedRequestObjects();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = ExternalRequestUri
        });

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_UnsignedReferencedRequestObjectIsRejectedWhenSignedRequestObjectsAreRequired()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRequestObjectReferenceServer(options, _ => CreateRequestObject(new(StringComparer.Ordinal)
            {
                [Parameters.ResponseType] = ResponseTypes.Token
            }, unsigned: true));

            options.RequireSignedRequestObjects();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = ExternalRequestUri
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestObject, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2211), response.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_ThrowsAnExceptionWhenNoFetcherIsRegistered()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRequestObjectServer(options);

            options.EnableRequestObjectReferenceSupport();
            options.DisableRequestUriRegistrationRequirement();
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = ExternalRequestUri
        }));

        Assert.Equal(SR.GetResourceString(SR.ID0921), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("https://www.contoso.com/request_objects/1")]
    [InlineData("https://www.fabrikam.com/request_objects/1")]
    [InlineData("https://www.fabrikam.com/request_obj")]
    [InlineData("https://www.fabrikam.com:8443/request_objects/")]
    [InlineData("http://www.fabrikam.com/request_objects/")]
    public async Task ValidateAuthorizationRequest_UnregisteredRequestUriIsRejected(string? registrations)
    {
        // Arrange
        var fetched = false;

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRequestObjectReferenceApplicationServer(options, registrations);

            options.Services.AddSingleton<IOpenIddictServerRequestObjectFetcher>(new InlineRequestObjectFetcher(_ =>
            {
                fetched = true;
                return null;
            }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = ExternalRequestUri + "0"
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestUri, response.Error);
        Assert.Equal(SR.FormatID2461(Parameters.RequestUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2461), response.ErrorUri);
        Assert.False(fetched);
    }

    [Theory]
    [InlineData("https://www.fabrikam.com/request_objects/10")]
    [InlineData("https://www.fabrikam.com/request_objects/")]
    [InlineData("https://WWW.FABRIKAM.COM/request_objects")]
    [InlineData("https://www.contoso.com/ https://www.fabrikam.com/request_objects/10#hash")]
    public async Task ValidateAuthorizationRequest_RegisteredRequestUriIsAccepted(string registrations)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRequestObjectReferenceApplicationServer(options, registrations);

            options.Services.AddSingleton<IOpenIddictServerRequestObjectFetcher>(new InlineRequestObjectFetcher(
                _ => CreateRequestObject(new(StringComparer.Ordinal)
                {
                    [Parameters.Nonce] = "n-0S6_WzA2Mj",
                    [Parameters.RedirectUri] = "http://www.fabrikam.com/path",
                    [Parameters.ResponseType] = ResponseTypes.Token
                })));

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = ExternalRequestUri + "0"
        });

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task HandleConfigurationRequest_RequestUriMetadataIsReturnedWhenReferenceSupportIsEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableRequestObjectSupport();
            options.EnableRequestObjectReferenceSupport();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.True((bool) response[Metadata.RequestUriParameterSupported]);
        Assert.True((bool) response[Metadata.RequireRequestUriRegistration]);
    }

    [Fact]
    public async Task HandleConfigurationRequest_RequestUriMetadataIsNotAdvertisedWhenReferenceSupportIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableRequestObjectSupport());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.False((bool) response[Metadata.RequestUriParameterSupported]);
        Assert.Null(response[Metadata.RequireRequestUriRegistration]);
    }

    private static void ConfigureRequestObjectReferenceServer(OpenIddictServerBuilder options, Func<Uri, string?> fetcher)
    {
        ConfigureRequestObjectServer(options);

        options.EnableRequestObjectReferenceSupport();
        options.DisableRequestUriRegistrationRequirement();

        options.Services.AddSingleton<IOpenIddictServerRequestObjectFetcher>(new InlineRequestObjectFetcher(fetcher));
    }

    private void ConfigureRequestObjectReferenceApplicationServer(OpenIddictServerBuilder options, string? registrations)
    {
        var application = new OpenIddictApplication();

        options.EnableRequestObjectSupport();
        options.EnableRequestObjectReferenceSupport();
        options.SetIssuer(new Uri(RequestObjectIssuer, UriKind.Absolute));
        options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
        options.SetRevocationEndpointUris(Array.Empty<Uri>());
        options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
        options.DisableTokenStorage();
        options.DisableSlidingRefreshTokenExpiration();

        var settings = ImmutableDictionary.CreateBuilder<string, string>(StringComparer.Ordinal);
        if (registrations is not null)
        {
            settings[Settings.RequestObject.RequestUris] = registrations;
        }

        options.Services.AddSingleton(CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.GetJsonWebKeySetAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(CreateRequestObjectJsonWebKeySet());

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(settings.ToImmutable());
        }));
    }

    private sealed class InlineRequestObjectFetcher(Func<Uri, string?> fetcher) : IOpenIddictServerRequestObjectFetcher
    {
        public ValueTask<string?> FetchAsync(Uri uri, CancellationToken cancellationToken) => new(fetcher(uri));
    }
}
