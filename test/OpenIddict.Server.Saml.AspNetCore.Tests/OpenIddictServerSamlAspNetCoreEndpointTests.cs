using System.Net;
using System.Security.Claims;
using System.Text;
using System.Xml;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Server.Saml.Tests;
using Xunit;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using static OpenIddict.Server.Saml.Tests.OpenIddictServerSamlTestHelpers;
using Parameters = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.Parameters;
using SamlStatusCodes = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.StatusCodes;

namespace OpenIddict.Server.Saml.AspNetCore.Tests;

public class OpenIddictServerSamlAspNetCoreEndpointTests
{
    [Fact]
    public async Task Metadata_ReturnsEntityDescriptor()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = CreateClient(host);

        // Act
        using var response = await client.GetAsync("/saml/metadata");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(MediaTypes.Metadata, response.Content.Headers.ContentType?.MediaType);

        var document = LoadResponse(await response.Content.ReadAsStringAsync());
        var manager = CreateNamespaceManager(document);

        Assert.Equal(IdentityProviderEntityId, document.DocumentElement!.GetAttribute("entityID"));
        Assert.Equal(SingleSignOnEndpoint, document.SelectSingleNode(
            "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService[@Binding='" + Bindings.HttpPost + "']/@Location", manager)!.Value);
    }

    [Fact]
    public async Task Endpoints_RejectHttpRequests()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();
        client.BaseAddress = new Uri("http://idp.example.com/");

        // Act
        using var response = await client.GetAsync("/saml/metadata");

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(SR.GetResourceString(SR.ID2264), await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task SingleSignOn_RedirectBinding_ChallengesAndReturnsSignedResponse()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = CreateClient(host);

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(id: "_redirect"), relayState: "relay&state", certificate: ServiceProviderCertificate);

        // Act: the user is not authenticated and is redirected to the login page.
        using var challenge = await client.GetAsync("/saml/sso" + query);

        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        Assert.Equal("/login", challenge.Headers.Location!.AbsolutePath);

        var returnUrl = QueryValue(challenge.Headers.Location, "ReturnUrl");
        Assert.StartsWith("/saml/sso?" + Parameters.State + "=", returnUrl, StringComparison.Ordinal);

        // Act: the user logs in and is redirected to the return URL.
        using var login = await client.GetAsync("/login?ReturnUrl=" + Uri.EscapeDataString(returnUrl));
        var cookie = GetCookie(login);

        using var request = new HttpRequestMessage(HttpMethod.Get, returnUrl);
        request.Headers.Add("Cookie", cookie);

        using var response = await client.SendAsync(request);

        // Assert
        var (action, saml, relayState) = await ParseFormAsync(response);
        Assert.Equal(AssertionConsumerServiceUrl.AbsoluteUri, action);
        Assert.Equal("relay&state", relayState);

        var document = LoadResponse(saml);
        var assertion = AssertSuccessfulResponse(document, "_redirect");
        Assert.Equal("alice", assertion.SelectSingleNode("saml:Subject/saml:NameID", CreateNamespaceManager(document))!.InnerText);

        var policy = response.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("form-action https://sp.example.com", policy, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", policy, StringComparison.Ordinal);
        Assert.Contains("no-store", response.Headers.CacheControl!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task SingleSignOn_PostBinding_ReturnsSignedResponseForAuthenticatedUser()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = CreateClient(host);

        var cookie = await LoginAsync(client);
        var document = SignDocument(CreateAuthenticationRequest(id: "_post"), ServiceProviderCertificate);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/saml/sso")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [Parameters.SamlRequest] = EncodePost(document.OuterXml),
                [Parameters.RelayState] = "post-relay"
            })
        };

        request.Headers.Add("Cookie", cookie);

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        var (action, saml, relayState) = await ParseFormAsync(response);
        Assert.Equal(AssertionConsumerServiceUrl.AbsoluteUri, action);
        Assert.Equal("post-relay", relayState);

        var assertion = AssertSuccessfulResponse(LoadResponse(saml), "_post");
        Assert.Equal("alice@example.com", assertion.SelectSingleNode("saml:AttributeStatement/saml:Attribute[@Name='mail']/saml:AttributeValue",
            CreateNamespaceManager(assertion.OwnerDocument))!.InnerText);
    }

    [Fact]
    public async Task SingleSignOn_RejectsUnknownAssertionConsumerService()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = CreateClient(host);

        var cookie = await LoginAsync(client);
        var query = CreateRedirectQueryString(CreateAuthenticationRequest(
            assertionConsumerServiceUrl: "https://attacker.example.com/acs"), certificate: ServiceProviderCertificate);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/saml/sso" + query);
        request.Headers.Add("Cookie", cookie);

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(SR.GetResourceString(SR.ID2256), await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task SingleSignOn_PassiveRequestWithoutSessionReturnsNoPassive()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = CreateClient(host);

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(id: "_passive", attributes: "IsPassive=\"true\""),
            certificate: ServiceProviderCertificate);

        // Act
        using var response = await client.GetAsync("/saml/sso" + query);

        // Assert
        var (_, saml, _) = await ParseFormAsync(response);
        var document = LoadResponse(saml);
        var manager = CreateNamespaceManager(document);

        Assert.Equal("_passive", document.DocumentElement!.GetAttribute("InResponseTo"));
        Assert.Equal(SamlStatusCodes.NoPassive, document.SelectSingleNode("/samlp:Response/samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value", manager)!.Value);
        Assert.Null(document.SelectSingleNode("/samlp:Response/saml:Assertion", manager));
        Assert.True(VerifySignature(document.DocumentElement, IdentityProviderCertificate));
    }

    [Fact]
    public async Task SingleSignOn_ForceAuthnChallengesAuthenticatedUser()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = CreateClient(host);

        var cookie = await LoginAsync(client);
        var query = CreateRedirectQueryString(CreateAuthenticationRequest(attributes: "ForceAuthn=\"true\""), certificate: ServiceProviderCertificate);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/saml/sso" + query);
        request.Headers.Add("Cookie", cookie);

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/login", response.Headers.Location!.AbsolutePath);
    }

    [Fact]
    public async Task SingleSignOn_ForceAuthnReturnsResponseAfterReauthentication()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = CreateClient(host);

        var cookie = await LoginAsync(client);

        // Note: authentication tickets store their issuance date with a precision of one second.
        await Task.Delay(TimeSpan.FromSeconds(1.1), TimeProvider.System);

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(id: "_force", attributes: "ForceAuthn=\"true\""),
            certificate: ServiceProviderCertificate);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/saml/sso" + query);
        request.Headers.Add("Cookie", cookie);

        using var challenge = await client.SendAsync(request);
        var returnUrl = QueryValue(challenge.Headers.Location!, "ReturnUrl");

        // The previous session cannot be used with the state: the user must authenticate again.
        using var stale = new HttpRequestMessage(HttpMethod.Get, returnUrl);
        stale.Headers.Add("Cookie", cookie);

        using var redirect = await client.SendAsync(stale);
        Assert.Equal(HttpStatusCode.Redirect, redirect.StatusCode);

        // Act
        using var login = await client.GetAsync("/login?ReturnUrl=" + Uri.EscapeDataString(returnUrl));

        using var callback = new HttpRequestMessage(HttpMethod.Get, returnUrl);
        callback.Headers.Add("Cookie", GetCookie(login));

        using var response = await client.SendAsync(callback);

        // Assert
        var (_, saml, _) = await ParseFormAsync(response);
        AssertSuccessfulResponse(LoadResponse(saml), "_force");
    }

    [Fact]
    public async Task SingleSignOn_RejectsTamperedState()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = CreateClient(host);

        // Act
        using var response = await client.GetAsync("/saml/sso?" + Parameters.State + "=tampered");

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(SR.GetResourceString(SR.ID2263), await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task SingleSignOn_IdentityProviderInitiatedRequiresOptIn()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = CreateClient(host);

        // Act
        using var response = await client.GetAsync("/saml/sso?sp=" + Uri.EscapeDataString(ServiceProviderEntityId));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(SR.GetResourceString(SR.ID2262), await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task SingleSignOn_IdentityProviderInitiatedReturnsUnsolicitedResponse()
    {
        // Arrange
        using var host = await CreateHostAsync(sp => sp.AllowIdentityProviderInitiatedSingleSignOn = true);
        using var client = CreateClient(host);

        var cookie = await LoginAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/saml/sso?sp=" + Uri.EscapeDataString(ServiceProviderEntityId) + "&RelayState=home");
        request.Headers.Add("Cookie", cookie);

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        var (_, saml, relayState) = await ParseFormAsync(response);
        Assert.Equal("home", relayState);

        var document = LoadResponse(saml);
        Assert.False(document.DocumentElement!.HasAttribute("InResponseTo"));
        AssertSuccessfulResponse(document, inResponseTo: null);
    }

    [Fact]
    public async Task SingleSignOn_DeniedAssertionReturnsRequestDenied()
    {
        // Arrange
        using var host = await CreateHostAsync(configuration: saml => saml.SetAssertionProvider<DenyingAssertionProvider>());
        using var client = CreateClient(host);

        var cookie = await LoginAsync(client);
        var query = CreateRedirectQueryString(CreateAuthenticationRequest(id: "_denied"), certificate: ServiceProviderCertificate);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/saml/sso" + query);
        request.Headers.Add("Cookie", cookie);

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        var (_, saml, _) = await ParseFormAsync(response);
        var document = LoadResponse(saml);

        Assert.Equal(SamlStatusCodes.RequestDenied, document.SelectSingleNode(
            "/samlp:Response/samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value", CreateNamespaceManager(document))!.Value);
    }

    private static XmlElement AssertSuccessfulResponse(XmlDocument document, string? inResponseTo)
    {
        var manager = CreateNamespaceManager(document);

        Assert.Equal(SamlStatusCodes.Success, document.SelectSingleNode("/samlp:Response/samlp:Status/samlp:StatusCode/@Value", manager)!.Value);

        var assertion = (XmlElement) document.SelectSingleNode("/samlp:Response/saml:Assertion", manager)!;
        Assert.True(VerifySignature(assertion, IdentityProviderCertificate));

        var data = (XmlElement) assertion.SelectSingleNode("saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", manager)!;
        Assert.Equal(inResponseTo ?? string.Empty, data.GetAttribute("InResponseTo"));
        Assert.Equal(AssertionConsumerServiceUrl.AbsoluteUri, data.GetAttribute("Recipient"));
        Assert.Equal(ServiceProviderEntityId, assertion.SelectSingleNode("saml:Conditions/saml:AudienceRestriction/saml:Audience", manager)!.InnerText);

        return assertion;
    }

    private static async Task<(string Action, string Response, string? RelayState)> ParseFormAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);

        var html = await response.Content.ReadAsStringAsync();

        var action = Extract(html, "<form id=\"saml\" method=\"post\" action=\"");
        var saml = Extract(html, "<input type=\"hidden\" name=\"" + Parameters.SamlResponse + "\" value=\"");
        var relay = Extract(html, "<input type=\"hidden\" name=\"" + Parameters.RelayState + "\" value=\"");

        return (action!, Encoding.UTF8.GetString(Convert.FromBase64String(saml!)), relay);

        static string? Extract(string html, string prefix)
        {
            var index = html.IndexOf(prefix, StringComparison.Ordinal);
            if (index is -1)
            {
                return null;
            }

            index += prefix.Length;
            return WebUtility.HtmlDecode(html[index..html.IndexOf('"', index)]);
        }
    }

    private static string QueryValue(Uri uri, string name)
        => Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query)[name].ToString();

    private static string GetCookie(HttpResponseMessage response)
        => string.Join("; ", response.Headers.GetValues("Set-Cookie").Select(static value => value.Split(';')[0]));

    private static async Task<string> LoginAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/login?ReturnUrl=%2F");
        return GetCookie(response);
    }

    private static HttpClient CreateClient(IHost host)
    {
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://idp.example.com/");
        return client;
    }

    private static async Task<IHost> CreateHostAsync(
        Action<OpenIddictServerSamlServiceProvider>? serviceProvider = null,
        Action<OpenIddictServerSamlBuilder>? configuration = null)
    {
        var builder = new HostBuilder();

        builder.ConfigureServices(services =>
        {
            services.AddRouting();

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options => options.LoginPath = "/login");

            services.AddOpenIddict()
                .AddServer(options =>
                {
                    options.UseSaml(saml =>
                    {
                        var sp = CreateServiceProvider();
                        serviceProvider?.Invoke(sp);

                        saml.SetEntityId(IdentityProviderEntityId)
                            .AddSigningCertificate(IdentityProviderCertificate)
                            .AddServiceProvider(sp)
                            .UseAspNetCore();

                        configuration?.Invoke(saml);
                    });
                });
        });

        builder.ConfigureWebHost(options =>
        {
            options.UseTestServer();
            options.Configure(app =>
            {
                app.UseRouting();
                app.UseAuthentication();

                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapOpenIddictSamlEndpoints();

                    endpoints.MapGet("/login", async (HttpContext context, string? returnUrl) =>
                    {
                        var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
                        identity.AddClaim(new Claim(Claims.Subject, "alice"));
                        identity.AddClaim(new Claim(Claims.Email, "alice@example.com"));

                        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

                        return Results.LocalRedirect(returnUrl ?? "/");
                    });
                });
            });
        });

        var host = builder.Build();
        await host.StartAsync();

        return host;
    }

    public sealed class DenyingAssertionProvider : IOpenIddictServerSamlAssertionProvider
    {
        public ValueTask<OpenIddictServerSamlModels.AssertionDescriptor?> CreateAssertionAsync(OpenIddictServerSamlModels.AssertionContext context)
            => new(result: null);
    }
}
