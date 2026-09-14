/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Server.Saml;
using Xunit;
using static OpenIddict.Client.Saml.OpenIddictClientSamlConstants;
using static OpenIddict.Client.Saml.Tests.OpenIddictClientSamlTestHelpers;
using Claims = OpenIddict.Abstractions.OpenIddictConstants.Claims;
using Parameters = OpenIddict.Client.Saml.OpenIddictClientSamlConstants.Parameters;
using Properties = OpenIddict.Client.Saml.OpenIddictClientSamlConstants.Properties;

namespace OpenIddict.Client.Saml.AspNetCore.Tests;

public class OpenIddictClientSamlAspNetCoreHandlerTests
{
    [Fact]
    public async Task Metadata_ReturnsServiceProviderMetadata()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = CreateClient(host);

        // Act
        using var response = await client.GetAsync("/saml/metadata");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(MediaTypes.Metadata, response.Content.Headers.ContentType?.MediaType);

        var document = Load(await response.Content.ReadAsStringAsync());
        Assert.Equal(ServiceProviderEntityId, document.DocumentElement!.GetAttribute("entityID"));
        Assert.Equal(AssertionConsumerServiceUrl.AbsoluteUri, document.SelectSingleNode(
            "/md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService/@Location", CreateNamespaceManager(document))!.Value);
    }

    [Fact]
    public async Task Endpoints_RejectHttpRequests()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();
        client.BaseAddress = new Uri("http://sp.example.com/");

        // Act
        using var response = await client.GetAsync("/saml/metadata");

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(SR.GetResourceString(SR.ID2458), await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Challenge_RedirectBinding_SignsUserInWithIdentityProviderResponse()
    {
        // Arrange
        using var idp = CreateIdentityProvider();
        using var host = await CreateHostAsync();
        using var client = CreateClient(host);

        // Act: the challenge redirects the user agent to the identity provider.
        using var challenge = await client.GetAsync("/challenge");

        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        var location = challenge.Headers.Location!;
        Assert.StartsWith(SingleSignOnServiceUrl.AbsoluteUri + "?SAMLRequest=", location.AbsoluteUri, StringComparison.Ordinal);

        var cookie = GetCookie(challenge, ".OpenIddict.Client.Saml.Correlation.");
        Assert.Contains("path=/saml/acs", GetSetCookieHeader(challenge, ".OpenIddict.Client.Saml.Correlation."), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=none", GetSetCookieHeader(challenge, ".OpenIddict.Client.Saml.Correlation."), StringComparison.OrdinalIgnoreCase);

        var (response, relayState) = await IssueResponseAsync(idp, location);

        // Act: the response is posted to the assertion consumer service.
        using var acs = await PostResponseAsync(client, response, relayState, cookie);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, acs.StatusCode);
        Assert.Equal("/profile", acs.Headers.Location!.OriginalString);

        using var profile = await GetWithCookieAsync(client, "/profile", GetCookie(acs, ".AspNetCore.Cookies"));
        Assert.Equal("alice|alice@example.com|" + ProviderName, await profile.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Challenge_PostBinding_ReturnsAutoPostPage()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.AuthenticationRequestBinding = Bindings.HttpPost;

        using var idp = CreateIdentityProvider();
        using var host = await CreateHostAsync(registration: registration);
        using var client = CreateClient(host);

        // Act
        using var challenge = await client.GetAsync("/challenge");

        // Assert
        Assert.Equal(HttpStatusCode.OK, challenge.StatusCode);
        Assert.Contains("form-action https://idp.example.com", challenge.Headers.GetValues("Content-Security-Policy").Single(), StringComparison.Ordinal);

        var page = await challenge.Content.ReadAsStringAsync();
        Assert.Contains("action=\"" + SingleSignOnServiceUrl.AbsoluteUri + "\"", page, StringComparison.Ordinal);

        var request = WebUtility.HtmlDecode(Regex.Match(page, "name=\"SAMLRequest\" value=\"(?<value>[^\"]+)\"", RegexOptions.None, TimeSpan.FromSeconds(5)).Groups["value"].Value);
        var relayState = WebUtility.HtmlDecode(Regex.Match(page, "name=\"RelayState\" value=\"(?<value>[^\"]+)\"", RegexOptions.None, TimeSpan.FromSeconds(5)).Groups["value"].Value);

        var result = await idp.GetRequiredService<OpenIddictServerSamlService>()
            .ValidatePostAuthenticationRequestAsync(request, relayState, SingleSignOnServiceUrl);
        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.True(result.Request!.IsSigned);
    }

    [Fact]
    public async Task Challenge_ProviderNameScheme_UsesDynamicRegistration()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.ProviderName = "Dynamic";
        registration.RegistrationId = "dynamic";

        using var idp = CreateIdentityProvider();
        using var host = await CreateHostAsync(saml => saml.AddRegistrationProvider(new StaticRegistrationProvider(registration)));
        using var client = CreateClient(host);

        var schemes = host.Services.GetRequiredService<IAuthenticationSchemeProvider>();
        Assert.Contains(await schemes.GetAllSchemesAsync(), static scheme => scheme.Name is "Dynamic");
        Assert.Null(await schemes.GetSchemeAsync("Unknown"));

        // Act
        using var challenge = await client.GetAsync("/challenge?provider=Dynamic");
        var (response, relayState) = await IssueResponseAsync(idp, challenge.Headers.Location!);
        using var acs = await PostResponseAsync(client, response, relayState, GetCookie(challenge, ".OpenIddict.Client.Saml.Correlation."));

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, acs.StatusCode);

        using var profile = await GetWithCookieAsync(client, "/profile", GetCookie(acs, ".AspNetCore.Cookies"));
        Assert.Equal("alice|alice@example.com|Dynamic", await profile.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Challenge_ThrowsWhenMultipleRegistrationsAreAvailable()
    {
        // Arrange
        var other = CreateRegistration();
        other.ProviderName = "Other";

        using var host = await CreateHostAsync(saml => saml.AddRegistration(other));
        using var client = CreateClient(host);

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetAsync("/challenge"));
        Assert.Equal(SR.GetResourceString(SR.ID0901), exception.Message);
    }

    [Fact]
    public async Task AssertionConsumerService_RejectsResponseWithoutCorrelationCookie()
    {
        // Arrange
        using var idp = CreateIdentityProvider();
        using var host = await CreateHostAsync();
        using var client = CreateClient(host);

        using var challenge = await client.GetAsync("/challenge");
        var (response, relayState) = await IssueResponseAsync(idp, challenge.Headers.Location!);

        // Act
        using var acs = await PostResponseAsync(client, response, relayState, cookie: null);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, acs.StatusCode);
        Assert.Equal(SR.GetResourceString(SR.ID2447), await acs.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task AssertionConsumerService_RejectsCorrelationCookieOfAnotherRequest()
    {
        // Arrange
        using var idp = CreateIdentityProvider();
        using var host = await CreateHostAsync();
        using var client = CreateClient(host);

        using var first = await client.GetAsync("/challenge");
        using var second = await client.GetAsync("/challenge");

        var (response, relayState) = await IssueResponseAsync(idp, first.Headers.Location!);

        // Note: the cookie of the second request is renamed to match the relay state of the first request.
        var cookie = GetCookie(second, ".OpenIddict.Client.Saml.Correlation.");
        cookie = ".OpenIddict.Client.Saml.Correlation." + relayState + cookie.Substring(cookie.IndexOf('=', StringComparison.Ordinal));

        // Act
        using var acs = await PostResponseAsync(client, response, relayState, cookie);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, acs.StatusCode);
        Assert.Equal(SR.GetResourceString(SR.ID2447), await acs.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task AssertionConsumerService_RejectsGetRequests()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = CreateClient(host);

        // Act
        using var response = await client.GetAsync("/saml/acs?SAMLResponse=abc");

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(SR.GetResourceString(SR.ID2440), await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task AssertionConsumerService_Passthrough_ExposesPrincipalToApplication()
    {
        // Arrange
        using var idp = CreateIdentityProvider();
        using var host = await CreateHostAsync(aspnet: aspnet => aspnet.EnableAssertionConsumerServicePassthrough());
        using var client = CreateClient(host);

        using var challenge = await client.GetAsync("/challenge");
        var (response, relayState) = await IssueResponseAsync(idp, challenge.Headers.Location!);

        // Act
        using var acs = await PostResponseAsync(client, response, relayState, GetCookie(challenge, ".OpenIddict.Client.Saml.Correlation."));

        // Assert
        Assert.Equal(HttpStatusCode.OK, acs.StatusCode);
        Assert.Equal("passthrough:alice:/profile", await acs.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("/home", "/home")]
    [InlineData("https://evil.example.com/", "/")]
    [InlineData("//evil.example.com/", "/")]
    public async Task AssertionConsumerService_UnsolicitedResponse_OnlyRedirectsToLocalRelayState(string relayState, string location)
    {
        // Arrange
        var registration = CreateRegistration();
        registration.AllowUnsolicitedResponses = true;

        using var idp = CreateIdentityProvider();
        using var host = await CreateHostAsync(registration: registration);
        using var client = CreateClient(host);

        // Act
        using var acs = await PostResponseAsync(client, CreateResponse(idp, inResponseTo: null), relayState, cookie: null);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, acs.StatusCode);
        Assert.Equal(location, acs.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task AssertionConsumerService_ErrorStatus_ReturnsGenericDescription()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.AllowUnsolicitedResponses = true;

        using var idp = CreateIdentityProvider();
        using var host = await CreateHostAsync(registration: registration);
        using var client = CreateClient(host);

        var provider = idp.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<OpenIddictServerSamlOptions>>().CurrentValue.ServiceProviders[0];
        var response = idp.GetRequiredService<OpenIddictServerSamlService>().CreateResponse(new OpenIddictServerSamlModels.ResponseDescriptor
        {
            AssertionConsumerServiceUrl = AssertionConsumerServiceUrl,
            ServiceProvider = provider,
            Status = OpenIddictClientSamlConstants.StatusCodes.Responder,
            StatusMessage = "<script>alert(1)</script>"
        });

        // Act
        using var acs = await PostResponseAsync(client, response, relayState: null, cookie: null);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, acs.StatusCode);
        Assert.Equal(SR.GetResourceString(SR.ID2449), await acs.Content.ReadAsStringAsync());
        Assert.Equal("nosniff", Assert.Single(acs.Headers.GetValues("X-Content-Type-Options")));
    }

    [Fact]
    public async Task SchemeProvider_RegisteredSchemesTakePrecedenceOverProviderNames()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.ProviderName = CookieAuthenticationDefaults.AuthenticationScheme;
        registration.RegistrationId = "dynamic";

        using var host = await CreateHostAsync(saml => saml.AddRegistrationProvider(new StaticRegistrationProvider(registration)));
        var schemes = host.Services.GetRequiredService<IAuthenticationSchemeProvider>();

        // Act
        var scheme = await schemes.GetSchemeAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        var all = await schemes.GetAllSchemesAsync();

        // Assert
        Assert.Equal(typeof(CookieAuthenticationHandler), scheme!.HandlerType);
        Assert.Single(all, static scheme => string.Equals(scheme.Name, CookieAuthenticationDefaults.AuthenticationScheme, StringComparison.Ordinal));
    }

    private static async Task<(string Response, string RelayState)> IssueResponseAsync(IServiceProvider idp, Uri location)
    {
        var result = await idp.GetRequiredService<OpenIddictServerSamlService>()
            .ValidateRedirectAuthenticationRequestAsync(location.Query, SingleSignOnServiceUrl);

        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.Equal(AssertionConsumerServiceUrl, result.AssertionConsumerServiceUrl);

        return (CreateResponse(idp, result.RequestId), result.RelayState!);
    }

    private static async Task<HttpResponseMessage> PostResponseAsync(HttpClient client, string response, string? relayState, string? cookie)
    {
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal) { [Parameters.SamlResponse] = Encode(response) };
        if (relayState is not null)
        {
            parameters[Parameters.RelayState] = relayState;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, "/saml/acs") { Content = new FormUrlEncodedContent(parameters) };
        if (cookie is not null)
        {
            request.Headers.Add("Cookie", cookie);
        }

        return await client.SendAsync(request);
    }

    private static async Task<HttpResponseMessage> GetWithCookieAsync(HttpClient client, string path, string cookie)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add("Cookie", cookie);

        return await client.SendAsync(request);
    }

    private static string GetSetCookieHeader(HttpResponseMessage response, string prefix)
        => response.Headers.GetValues("Set-Cookie").First(value => value.StartsWith(prefix, StringComparison.Ordinal));

    private static string GetCookie(HttpResponseMessage response, string prefix)
        => GetSetCookieHeader(response, prefix).Split(';')[0];

    private static HttpClient CreateClient(IHost host)
    {
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://sp.example.com/");
        return client;
    }

    private static async Task<IHost> CreateHostAsync(
        Action<OpenIddictClientSamlBuilder>? saml = null,
        Action<OpenIddictClientSamlAspNetCoreBuilder>? aspnet = null,
        OpenIddictClientSamlRegistration? registration = null)
    {
        var host = new HostBuilder()
            .ConfigureWebHost(builder =>
            {
                builder.UseTestServer();

                builder.ConfigureServices(services =>
                {
                    services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();

                    services.AddOpenIddict()
                        .AddClient(options => options.UseSaml(builder =>
                        {
                            builder.SetEntityId(ServiceProviderEntityId)
                                   .AddSigningCertificate(ServiceProviderCertificate)
                                   .AddRegistration(registration ?? CreateRegistration());

                            saml?.Invoke(builder);

                            builder.UseAspNetCore(options => aspnet?.Invoke(options));
                        }));
                });

                builder.Configure(app =>
                {
                    app.UseAuthentication();

                    app.Run(async context =>
                    {
                        if (context.Request.Path == "/challenge")
                        {
                            await context.ChallengeAsync(context.Request.Query["provider"].FirstOrDefault()
                                ?? OpenIddictClientSamlAspNetCoreDefaults.AuthenticationScheme,
                                new AuthenticationProperties { RedirectUri = "/profile" });
                        }

                        else if (context.Request.Path == "/profile")
                        {
                            var result = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                            if (!result.Succeeded)
                            {
                                context.Response.StatusCode = 401;
                                return;
                            }

                            await context.Response.WriteAsync(string.Join("|",
                                result.Principal.FindFirst(Claims.Subject)?.Value,
                                result.Principal.FindFirst(Claims.Email)?.Value,
                                result.Principal.FindFirst(Claims.Private.ProviderName)?.Value));
                        }

                        else if (context.Request.Path == "/saml/acs")
                        {
                            var result = await context.AuthenticateAsync(OpenIddictClientSamlAspNetCoreDefaults.AuthenticationScheme);
                            await context.Response.WriteAsync(result.Succeeded
                                ? string.Join(":", "passthrough", result.Principal.FindFirst(Claims.Subject)?.Value, result.Properties.RedirectUri)
                                : string.Join(":", "failure", result.Failure?.Message));
                        }

                        else
                        {
                            context.Response.StatusCode = 404;
                        }
                    });
                });
            })
            .Build();

        await host.StartAsync();

        return host;
    }

    private sealed class StaticRegistrationProvider(OpenIddictClientSamlRegistration registration) : IOpenIddictClientSamlRegistrationProvider
    {
        public ValueTask<OpenIddictClientSamlRegistration?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
            => new(string.Equals(identifier, registration.RegistrationId, StringComparison.Ordinal) ? registration : null);

        public ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> FindByEntityIdAsync(string entityId, CancellationToken cancellationToken)
            => new(string.Equals(entityId, registration.IdentityProviderEntityId, StringComparison.Ordinal) ? [registration] : []);

        public ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> FindByProviderNameAsync(string name, CancellationToken cancellationToken)
            => new(string.Equals(name, registration.ProviderName, StringComparison.Ordinal) ? [registration] : []);

        public ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> ListAsync(CancellationToken cancellationToken)
            => new([registration]);
    }
}
