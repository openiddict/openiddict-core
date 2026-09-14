/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Testing;
using OpenIddict.Server.Saml;
using Owin;
using Xunit;
using static OpenIddict.Client.Saml.OpenIddictClientSamlConstants;
using static OpenIddict.Client.Saml.Tests.OpenIddictClientSamlTestHelpers;
using Claims = OpenIddict.Abstractions.OpenIddictConstants.Claims;
using Parameters = OpenIddict.Client.Saml.OpenIddictClientSamlConstants.Parameters;
using Properties = OpenIddict.Client.Saml.OpenIddictClientSamlConstants.Properties;

namespace OpenIddict.Client.Saml.Owin.Tests;

public class OpenIddictClientSamlOwinMiddlewareTests
{
    private const string CookieType = CookieAuthenticationDefaults.AuthenticationType;
    private const string CorrelationPrefix = ".OpenIddict.Client.Saml.Correlation.";

    [Fact]
    public async Task Metadata_ReturnsServiceProviderMetadata()
    {
        // Arrange
        using var server = CreateServer();
        using var client = CreateClient(server);

        // Act
        using var response = await client.GetAsync("/saml/metadata");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(MediaTypes.Metadata, response.Content.Headers.ContentType?.MediaType);

        var document = Load(await response.Content.ReadAsStringAsync());
        Assert.Equal(AssertionConsumerServiceUrl.AbsoluteUri, document.SelectSingleNode(
            "/md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService/@Location", CreateNamespaceManager(document))!.Value);
    }

    [Fact]
    public async Task Endpoints_RejectHttpRequests()
    {
        // Arrange
        using var server = CreateServer();
        using var client = server.HttpClient;
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
        using var server = CreateServer();
        using var client = CreateClient(server);

        // Act
        using var challenge = await client.GetAsync("/challenge");

        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        Assert.StartsWith(SingleSignOnServiceUrl.AbsoluteUri + "?SAMLRequest=", challenge.Headers.Location!.AbsoluteUri, StringComparison.Ordinal);

        var header = GetSetCookieHeader(challenge, CorrelationPrefix);
        Assert.Contains("path=/saml/acs", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=none", header, StringComparison.OrdinalIgnoreCase);

        var (response, relayState) = await IssueResponseAsync(idp, challenge.Headers.Location);
        using var acs = await PostResponseAsync(client, response, relayState, GetCookie(challenge, CorrelationPrefix));

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, acs.StatusCode);
        Assert.Equal("/profile", acs.Headers.Location!.OriginalString);

        using var profile = await GetWithCookieAsync(client, "/profile", GetCookie(acs, ".AspNet.Cookies"));
        Assert.Equal("alice|alice@example.com|" + ProviderName, await profile.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Challenge_ProviderName_UsesDynamicRegistration()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.ProviderName = "Dynamic";
        registration.RegistrationId = "dynamic";

        using var idp = CreateIdentityProvider();
        using var server = CreateServer(saml => saml.AddRegistrationProvider(new StaticRegistrationProvider(registration)));
        using var client = CreateClient(server);

        // Act
        using var challenge = await client.GetAsync("/challenge?provider=Dynamic");
        var (response, relayState) = await IssueResponseAsync(idp, challenge.Headers.Location!);
        using var acs = await PostResponseAsync(client, response, relayState, GetCookie(challenge, CorrelationPrefix));

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, acs.StatusCode);

        using var profile = await GetWithCookieAsync(client, "/profile", GetCookie(acs, ".AspNet.Cookies"));
        Assert.Equal("alice|alice@example.com|Dynamic", await profile.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Challenge_IgnoresUnknownAuthenticationType()
    {
        // Arrange
        using var server = CreateServer();
        using var client = CreateClient(server);

        // Act
        using var challenge = await client.GetAsync("/challenge?provider=Unknown");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, challenge.StatusCode);
    }

    [Fact]
    public async Task Challenge_PostBinding_ReturnsAutoPostPage()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.AuthenticationRequestBinding = Bindings.HttpPost;

        using var server = CreateServer(registration: registration);
        using var client = CreateClient(server);

        // Act
        using var challenge = await client.GetAsync("/challenge");

        // Assert
        Assert.Equal(HttpStatusCode.OK, challenge.StatusCode);
        Assert.Contains("form-action https://idp.example.com", challenge.Headers.GetValues("Content-Security-Policy").Single(), StringComparison.Ordinal);
        Assert.Contains("name=\"SAMLRequest\"", await challenge.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AssertionConsumerService_RejectsResponseWithoutCorrelationCookie()
    {
        // Arrange
        using var idp = CreateIdentityProvider();
        using var server = CreateServer();
        using var client = CreateClient(server);

        using var challenge = await client.GetAsync("/challenge");
        var (response, relayState) = await IssueResponseAsync(idp, challenge.Headers.Location!);

        // Act
        using var acs = await PostResponseAsync(client, response, relayState, cookie: null);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, acs.StatusCode);
        Assert.Equal(SR.GetResourceString(SR.ID2447), await acs.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task AssertionConsumerService_Passthrough_ExposesResultToApplication()
    {
        // Arrange
        using var idp = CreateIdentityProvider();
        using var server = CreateServer(owin: owin => owin.EnableAssertionConsumerServicePassthrough());
        using var client = CreateClient(server);

        using var challenge = await client.GetAsync("/challenge");
        var (response, relayState) = await IssueResponseAsync(idp, challenge.Headers.Location!);

        // Act
        using var acs = await PostResponseAsync(client, response, relayState, GetCookie(challenge, CorrelationPrefix));

        // Assert
        Assert.Equal(HttpStatusCode.OK, acs.StatusCode);
        Assert.Equal("passthrough:alice:/profile", await acs.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("/home", "/home")]
    [InlineData("https://evil.example.com/", "/")]
    public async Task AssertionConsumerService_UnsolicitedResponse_OnlyRedirectsToLocalRelayState(string relayState, string location)
    {
        // Arrange
        var registration = CreateRegistration();
        registration.AllowUnsolicitedResponses = true;

        using var idp = CreateIdentityProvider();
        using var server = CreateServer(registration: registration);
        using var client = CreateClient(server);

        // Act
        using var acs = await PostResponseAsync(client, CreateResponse(idp, inResponseTo: null), relayState, cookie: null);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, acs.StatusCode);
        Assert.Equal(location, acs.Headers.Location!.OriginalString);
    }

    private static async Task<(string Response, string RelayState)> IssueResponseAsync(IServiceProvider idp, Uri location)
    {
        var result = await idp.GetRequiredService<OpenIddictServerSamlService>()
            .ValidateRedirectAuthenticationRequestAsync(location.Query, SingleSignOnServiceUrl);

        Assert.True(result.Succeeded, result.ErrorDescription);

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

    private static HttpClient CreateClient(TestServer server)
    {
        var client = server.HttpClient;
        client.BaseAddress = new Uri("https://sp.example.com/");
        return client;
    }

    private static TestServer CreateServer(
        Action<OpenIddictClientSamlBuilder>? saml = null,
        Action<OpenIddictClientSamlOwinBuilder>? owin = null,
        OpenIddictClientSamlRegistration? registration = null)
    {
        var services = CreateServiceProviderServices(builder =>
        {
            saml?.Invoke(builder);

            builder.UseOwin(options =>
            {
                options.SetSignInAuthenticationType(CookieType);
                owin?.Invoke(options);
            });
        }, registration);

        services.AddLogging();

        var provider = services.BuildServiceProvider();

        return TestServer.Create(app =>
        {
            app.Use(async (context, next) =>
            {
                using var scope = provider.CreateScope();

                context.Set(typeof(IServiceProvider).FullName, scope.ServiceProvider);

                try
                {
                    await next();
                }

                finally
                {
                    context.Environment.Remove(typeof(IServiceProvider).FullName);
                }
            });

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationMode = AuthenticationMode.Passive,
                AuthenticationType = CookieType
            });

            app.UseOpenIddictClientSaml();

            app.Run(async context =>
            {
                if (context.Request.Path == new PathString("/challenge"))
                {
                    context.Response.StatusCode = 401;
                    context.Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/profile" },
                        context.Request.Query.Get("provider") ?? OpenIddictClientSamlOwinDefaults.AuthenticationType);
                }

                else if (context.Request.Path == new PathString("/profile"))
                {
                    var result = await context.Authentication.AuthenticateAsync(CookieType);
                    if (result?.Identity is null)
                    {
                        context.Response.StatusCode = 401;
                        return;
                    }

                    await context.Response.WriteAsync(string.Join("|",
                        result.Identity.FindFirst(Claims.Subject)?.Value,
                        result.Identity.FindFirst(Claims.Email)?.Value,
                        result.Identity.FindFirst(Claims.Private.ProviderName)?.Value));
                }

                else if (context.Request.Path == new PathString("/saml/acs"))
                {
                    var result = context.GetOpenIddictClientSamlResponse();
                    await context.Response.WriteAsync(result is { Succeeded: true }
                        ? string.Join(":", "passthrough", result.Principal!.FindFirst(Claims.Subject)?.Value,
                            result.State?.Properties[".redirect"])
                        : string.Join(":", "failure", result?.ErrorDescription));
                }

                else
                {
                    context.Response.StatusCode = 404;
                }
            });
        });
    }

    private sealed class StaticRegistrationProvider(OpenIddictClientSamlRegistration registration) : IOpenIddictClientSamlRegistrationProvider
    {
        public ValueTask<OpenIddictClientSamlRegistration?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
            => new(string.Equals(identifier, registration.RegistrationId, StringComparison.Ordinal) ? registration : null);

        public ValueTask<System.Collections.Immutable.ImmutableArray<OpenIddictClientSamlRegistration>> FindByEntityIdAsync(string entityId, CancellationToken cancellationToken)
            => new(string.Equals(entityId, registration.IdentityProviderEntityId, StringComparison.Ordinal) ? [registration] : []);

        public ValueTask<System.Collections.Immutable.ImmutableArray<OpenIddictClientSamlRegistration>> FindByProviderNameAsync(string name, CancellationToken cancellationToken)
            => new(string.Equals(name, registration.ProviderName, StringComparison.Ordinal) ? [registration] : []);

        public ValueTask<System.Collections.Immutable.ImmutableArray<OpenIddictClientSamlRegistration>> ListAsync(CancellationToken cancellationToken)
            => new([registration]);
    }
}
