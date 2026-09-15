using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Moq;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Server.Saml.Tests;
using Xunit;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using static OpenIddict.Server.Saml.Tests.OpenIddictServerSamlLogoutTestHelpers;
using static OpenIddict.Server.Saml.Tests.OpenIddictServerSamlTestHelpers;
using Parameters = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.Parameters;
using SamlStatusCodes = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.StatusCodes;

namespace OpenIddict.Server.Saml.AspNetCore.Tests;

public class OpenIddictServerSamlAspNetCoreLogoutTests
{
    [Fact]
    public async Task SingleLogout_ReturnsNotFoundWhenSingleLogoutIsDisabled()
    {
        // Arrange
        using var host = await CreateHostAsync([], enable: false);
        using var client = CreateClient(host);

        // Act
        using var response = await client.GetAsync("/saml/slo" + CreateRedirectQueryString(CreateLogoutRequest(), certificate: ServiceProviderCertificate));

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Metadata_PublishesSingleLogoutService()
    {
        // Arrange
        using var host = await CreateHostAsync([]);
        using var client = CreateClient(host);

        // Act
        var document = LoadResponse(await client.GetStringAsync("/saml/metadata"));

        // Assert
        Assert.Equal(SingleLogoutEndpoint, document.SelectSingleNode("/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService[@Binding='" +
            Bindings.HttpRedirect + "']/@Location", CreateNamespaceManager(document))!.Value);
    }

    [Fact]
    public async Task SingleLogout_TerminatesSessionCreatedBySingleSignOnAndSignsOutUser()
    {
        // Arrange
        List<FakeSession> sessions = [];

        using var host = await CreateHostAsync(sessions);
        using var client = CreateClient(host);

        using var login = await client.GetAsync("/login?ReturnUrl=%2F");
        var cookie = GetCookie(login);

        using var sso = new HttpRequestMessage(HttpMethod.Get, "/saml/sso" +
            CreateRedirectQueryString(CreateAuthenticationRequest(), certificate: ServiceProviderCertificate));
        sso.Headers.Add("Cookie", cookie);

        using var assertion = await client.SendAsync(sso);
        var document = LoadResponse(await ParseSamlResponseAsync(assertion));

        var index = document.SelectSingleNode("//saml:AuthnStatement/@SessionIndex", CreateNamespaceManager(document))!.Value;
        var session = Assert.Single(sessions);
        Assert.Equal(session.Id, index);

        // Act
        using var request = new HttpRequestMessage(HttpMethod.Get, "/saml/slo" + CreateRedirectQueryString(
            CreateLogoutRequest(id: "_sp_logout", sessionIndexes: [index!]), relayState: "relay", certificate: ServiceProviderCertificate));
        request.Headers.Add("Cookie", cookie);

        using var response = await client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.Equal(Statuses.Revoked, session.Status);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), value =>
            value.StartsWith(".AspNetCore.Cookies=;", StringComparison.Ordinal));

        var (logout, relayState, valid) = DecodeRedirectUrl(response.Headers.Location!, Parameters.SamlResponse, IdentityProviderCertificate);

        Assert.True(valid);
        Assert.Equal("relay", relayState);
        Assert.StartsWith(ServiceProviderLogoutUrl + "?", response.Headers.Location!.AbsoluteUri, StringComparison.Ordinal);
        Assert.Equal("_sp_logout", logout.DocumentElement!.GetAttribute("InResponseTo"));
        Assert.Equal(SamlStatusCodes.Success, logout.SelectSingleNode(
            "/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value", CreateNamespaceManager(logout))!.Value);
    }

    [Fact]
    public async Task SingleLogout_RejectsUnsignedRequest()
    {
        // Arrange
        using var host = await CreateHostAsync([]);
        using var client = CreateClient(host);

        // Act
        using var response = await client.GetAsync("/saml/slo" + CreateRedirectQueryString(CreateLogoutRequest()));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(SR.GetResourceString(SR.ID2503), await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task SingleLogout_ReturnsErrorResponseForInvalidDestination()
    {
        // Arrange
        using var host = await CreateHostAsync([]);
        using var client = CreateClient(host);

        // Act
        using var response = await client.GetAsync("/saml/slo" + CreateRedirectQueryString(
            CreateLogoutRequest(id: "_invalid", destination: "https://idp.example.com/other"), certificate: ServiceProviderCertificate));

        // Assert
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var (document, _, valid) = DecodeRedirectUrl(response.Headers.Location!, Parameters.SamlResponse, IdentityProviderCertificate);
        Assert.True(valid);
        Assert.Equal("_invalid", document.DocumentElement!.GetAttribute("InResponseTo"));
        Assert.Equal(SamlStatusCodes.Requester, document.SelectSingleNode(
            "/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value", CreateNamespaceManager(document))!.Value);
    }

    [Fact]
    public async Task SingleLogout_PostBindingPropagatesLogoutToOtherServiceProviders()
    {
        // Arrange
        List<FakeSession> sessions =
        [
            CreateSamlSession("s1", ServiceProviderEntityId, "alice"),
            CreateSamlSession("s2", SecondServiceProviderEntityId, "alice-sp2")
        ];

        using var host = await CreateHostAsync(sessions, sp => sp.SingleLogoutServiceBinding = Bindings.HttpPost);
        using var client = CreateClient(host);

        // Act
        using var request = new HttpRequestMessage(HttpMethod.Post, "/saml/slo")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [Parameters.SamlRequest] = EncodePost(SignDocument(CreateLogoutRequest(id: "_post_logout", sessionIndexes: ["s1"]),
                    ServiceProviderCertificate).OuterXml),
                [Parameters.RelayState] = "post-relay"
            })
        };

        using var propagation = await client.SendAsync(request);

        // Assert: the second service provider receives a logout request.
        Assert.Equal(HttpStatusCode.SeeOther, propagation.StatusCode);
        Assert.All(sessions, session => Assert.Equal(Statuses.Revoked, session.Status));

        var (logout, _, valid) = DecodeRedirectUrl(propagation.Headers.Location!, Parameters.SamlRequest, IdentityProviderCertificate);
        Assert.True(valid);

        // Act: the second service provider returns its logout response.
        using var response = await client.GetAsync("/saml/slo" + CreateRedirectQueryString(
            CreateLogoutResponse(logout.DocumentElement!.GetAttribute("ID")), certificate: SecondServiceProviderCertificate,
            parameter: Parameters.SamlResponse));

        // Assert: the logout response is posted to the service provider that initiated the logout.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("action=\"" + ServiceProviderLogoutUrl + "\"", html, StringComparison.Ordinal);
        Assert.Contains("name=\"RelayState\" value=\"post-relay\"", html, StringComparison.Ordinal);
        Assert.Contains("form-action https://sp.example.com", response.Headers.GetValues("Content-Security-Policy").Single(), StringComparison.Ordinal);

        var document = LoadResponse(await ParseSamlResponseAsync(html));
        Assert.Equal("_post_logout", document.DocumentElement!.GetAttribute("InResponseTo"));
        Assert.True(VerifySignature(document.DocumentElement, IdentityProviderCertificate));
    }

    [Fact]
    public async Task StartOpenIddictSamlLogoutAsync_PropagatesLogoutAndRedirectsToReturnUrl()
    {
        // Arrange
        List<FakeSession> sessions = [CreateSamlSession("s1", ServiceProviderEntityId, "alice")];

        using var host = await CreateHostAsync(sessions);
        using var client = CreateClient(host);

        using var login = await client.GetAsync("/login?ReturnUrl=%2F");

        using var request = new HttpRequestMessage(HttpMethod.Get, "/logout");
        request.Headers.Add("Cookie", GetCookie(login));

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.Equal(Statuses.Revoked, sessions[0].Status);

        var (logout, _, _) = DecodeRedirectUrl(response.Headers.Location!, Parameters.SamlRequest, IdentityProviderCertificate);

        using var completion = await client.GetAsync("/saml/slo" + CreateRedirectQueryString(
            CreateLogoutResponse(logout.DocumentElement!.GetAttribute("ID"), issuer: ServiceProviderEntityId),
            certificate: ServiceProviderCertificate, parameter: Parameters.SamlResponse));

        Assert.Equal(HttpStatusCode.SeeOther, completion.StatusCode);
        Assert.Equal("/signed-out", completion.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task SingleLogout_ProcessesSoapLogoutRequest()
    {
        // Arrange
        List<FakeSession> sessions = [CreateSamlSession("s1", ServiceProviderEntityId, "alice")];

        using var host = await CreateHostAsync(sessions);
        using var client = CreateClient(host);

        var request = SignDocument(CreateLogoutRequest(id: "_soap", destination: null, sessionIndexes: ["s1"]), ServiceProviderCertificate);

        // Act
        using var response = await client.PostAsync("/saml/slo", new StringContent(
            CreateSoapEnvelope(request.DocumentElement!.OuterXml), Encoding.UTF8, "text/xml"));

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/xml", response.Content.Headers.ContentType!.MediaType);
        Assert.Equal(Statuses.Revoked, sessions[0].Status);

        var document = LoadResponse(await response.Content.ReadAsStringAsync());
        var manager = CreateNamespaceManager(document);

        Assert.Equal("_soap", document.SelectSingleNode("/soap:Envelope/soap:Body/samlp:LogoutResponse/@InResponseTo", manager)!.Value);
        Assert.Equal(SamlStatusCodes.Success, document.SelectSingleNode(
            "/soap:Envelope/soap:Body/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value", manager)!.Value);
    }

    [Fact]
    public async Task SingleLogout_ReturnsSoapFaultForMalformedSoapRequest()
    {
        // Arrange
        using var host = await CreateHostAsync([]);
        using var client = CreateClient(host);

        // Act
        using var response = await client.PostAsync("/saml/slo", new StringContent("<invalid", Encoding.UTF8, "text/xml"));

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Contains("soap:Fault", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task SingleLogout_ContinuesChainWhenParticipantResponseIsInvalid()
    {
        // Arrange
        List<FakeSession> sessions =
        [
            CreateSamlSession("s1", ServiceProviderEntityId, "alice"),
            CreateSamlSession("s2", SecondServiceProviderEntityId, "alice-sp2")
        ];

        using var host = await CreateHostAsync(sessions);
        using var client = CreateClient(host);

        using var propagation = await client.GetAsync("/saml/slo" + CreateRedirectQueryString(
            CreateLogoutRequest(id: "_chain", sessionIndexes: ["s1"]), certificate: ServiceProviderCertificate));

        Assert.Equal(HttpStatusCode.SeeOther, propagation.StatusCode);

        var (logout, _, _) = DecodeRedirectUrl(propagation.Headers.Location!, Parameters.SamlRequest, IdentityProviderCertificate);

        // Act: the second service provider returns an unsigned logout response.
        using var response = await client.GetAsync("/saml/slo" + CreateRedirectQueryString(
            CreateLogoutResponse(logout.DocumentElement!.GetAttribute("ID")), parameter: Parameters.SamlResponse));

        // Assert: the logout response is returned to the initiator with a PartialLogout status.
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.StartsWith(ServiceProviderLogoutUrl + "?", response.Headers.Location!.AbsoluteUri, StringComparison.Ordinal);

        var (document, _, valid) = DecodeRedirectUrl(response.Headers.Location!, Parameters.SamlResponse, IdentityProviderCertificate);
        Assert.True(valid);
        Assert.Equal("_chain", document.DocumentElement!.GetAttribute("InResponseTo"));
        Assert.Equal(SamlStatusCodes.PartialLogout, document.SelectSingleNode(
            "/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value", CreateNamespaceManager(document))!.Value);
    }

    [Fact]
    public async Task SingleLogout_InfersIssuerFromRequestWhenIssuerIsNotConfigured()
    {
        // Arrange
        List<FakeSession> sessions =
        [
            CreateSamlSession("s1", ServiceProviderEntityId, "alice"),
            new FakeSession { Id = "oidc", ApplicationId = "a1", LoginId = "login-1", Status = Statuses.Valid, Subject = "alice" }
        ];

        using var host = await CreateHostAsync(sessions, server: options => options.EnableFrontchannelLogout(),
            applications: CreateApplicationManager(), issuer: false);
        using var client = CreateClient(host);

        // Act
        using var response = await client.GetAsync("/saml/slo" + CreateRedirectQueryString(
            CreateLogoutRequest(sessionIndexes: ["s1"]), certificate: ServiceProviderCertificate));

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.All(sessions, session => Assert.Equal(Statuses.Revoked, session.Status));

        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("src=\"https://rp.example.com/frontchannel?", html, StringComparison.Ordinal);
        Assert.Contains("iss=" + Uri.EscapeDataString("https://idp.example.com/"), html, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("//evil.example.com")]
    [InlineData("/\\evil.example.com")]
    [InlineData("/\t/evil.example.com")]
    [InlineData("https://evil.example.com/")]
    public async Task StartOpenIddictSamlLogoutAsync_RejectsNonLocalReturnUrl(string url)
    {
        // Arrange
        List<FakeSession> sessions = [CreateSamlSession("s1", ServiceProviderEntityId, "alice")];

        using var host = await CreateHostAsync(sessions);
        using var client = CreateClient(host);

        using var login = await client.GetAsync("/login?ReturnUrl=%2F");

        using var request = new HttpRequestMessage(HttpMethod.Get, "/logout-to?returnUrl=" + Uri.EscapeDataString(url));
        request.Headers.Add("Cookie", GetCookie(login));

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.StartsWith(SR.GetResourceString(SR.ID01005), await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(Statuses.Valid, sessions[0].Status);
    }

    [Fact]
    public async Task EndSession_TerminatesSamlSessionsSharingTheLogin()
    {
        // Arrange
        List<FakeSession> sessions =
        [
            new FakeSession { Id = "oidc", LoginId = "login-1", Status = Statuses.Valid, Subject = "alice" },
            CreateSamlSession("s1", ServiceProviderEntityId, "alice"),
            CreateSamlSession("s2", SecondServiceProviderEntityId, "alice-sp2")
        ];

        using var host = await CreateHostAsync(sessions, server: options =>
        {
            options.SetEndSessionEndpointUris("connect/endsession")
                   .EnableSessionRevocationOnSignOut()
                   .EnableFrontchannelLogout();

            options.UseAspNetCore()
                   .EnableEndSessionEndpointPassthrough()
                   .DisableTransportSecurityRequirement();
        }, issuer: false);

        using var client = CreateClient(host);

        // Act
        using var response = await client.GetAsync("/connect/endsession");

        // Assert: the sessions sharing the login are revoked and the SAML service providers are notified in iframes.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.All(sessions, session => Assert.Equal(Statuses.Revoked, session.Status));

        var html = WebUtility.HtmlDecode(await response.Content.ReadAsStringAsync());

        foreach (var (url, certificate, nameId, index) in (IEnumerable<(string, System.Security.Cryptography.X509Certificates.X509Certificate2, string, string)>)
            [(ServiceProviderLogoutUrl, IdentityProviderCertificate, "alice", "s1"), (SecondServiceProviderLogoutUrl, IdentityProviderCertificate, "alice-sp2", "s2")])
        {
            var start = html.IndexOf("src=\"" + url + "?", StringComparison.Ordinal);
            Assert.True(start >= 0, html);

            start += "src=\"".Length;
            var uri = new Uri(html[start..html.IndexOf('"', start)], UriKind.Absolute);

            var (logout, _, valid) = DecodeRedirectUrl(uri, Parameters.SamlRequest, certificate);
            var namespaces = CreateNamespaceManager(logout);

            Assert.True(valid);
            Assert.Equal(nameId, logout.SelectSingleNode("/samlp:LogoutRequest/saml:NameID", namespaces)!.InnerText);
            Assert.Equal(index, logout.SelectSingleNode("/samlp:LogoutRequest/samlp:SessionIndex", namespaces)!.InnerText);
        }
    }

    private static async Task<string> ParseSamlResponseAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await ParseSamlResponseAsync(await response.Content.ReadAsStringAsync());
    }

    private static Task<string> ParseSamlResponseAsync(string html)
    {
        var prefix = "<input type=\"hidden\" name=\"" + Parameters.SamlResponse + "\" value=\"";
        var index = html.IndexOf(prefix, StringComparison.Ordinal) + prefix.Length;

        return Task.FromResult(Encoding.UTF8.GetString(Convert.FromBase64String(
            WebUtility.HtmlDecode(html[index..html.IndexOf('"', index)]))));
    }

    private static string GetCookie(HttpResponseMessage response)
        => string.Join("; ", response.Headers.GetValues("Set-Cookie").Select(static value => value.Split(';')[0]));

    private static HttpClient CreateClient(IHost host)
    {
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://idp.example.com/");
        return client;
    }

    private static async Task<IHost> CreateHostAsync(List<FakeSession> sessions,
        Action<OpenIddictServerSamlServiceProvider>? serviceProvider = null, bool enable = true,
        Action<OpenIddictServerBuilder>? server = null, Mock<IOpenIddictApplicationManager>? applications = null, bool issuer = true)
    {
        var builder = new HostBuilder();

        builder.ConfigureServices(services =>
        {
            services.AddRouting();

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options => options.LoginPath = "/login");

            AddServerServices(services, sessions, options =>
            {
                options.UseSaml(saml =>
                {
                    var sp = CreateServiceProvider();
                    sp.SingleLogoutServiceUrl = new Uri(ServiceProviderLogoutUrl, UriKind.Absolute);
                    serviceProvider?.Invoke(sp);

                    saml.SetEntityId(IdentityProviderEntityId)
                        .AddSigningCertificate(IdentityProviderCertificate)
                        .AddServiceProvider(sp)
                        .AddServiceProvider(CreateSecondServiceProvider())
                        .SetLoginIdClaimType(LoginIdClaimType)
                        .UseAspNetCore();

                    if (enable)
                    {
                        saml.EnableSingleLogout();
                    }
                });

                server?.Invoke(options);
            }, applications, issuer);
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
                        identity.AddClaim(new Claim(LoginIdClaimType, "login-1"));

                        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

                        return Results.LocalRedirect(returnUrl ?? "/");
                    });

                    endpoints.MapGet("/logout", (HttpContext context) => context.StartOpenIddictSamlLogoutAsync("/signed-out"));

                    endpoints.MapGet("/logout-to", async (HttpContext context, string returnUrl) =>
                    {
                        try
                        {
                            await context.StartOpenIddictSamlLogoutAsync(returnUrl);
                        }

                        catch (ArgumentException exception)
                        {
                            context.Response.StatusCode = 400;
                            await context.Response.WriteAsync(exception.Message);
                        }
                    });

                    endpoints.MapGet("/connect/endsession", (HttpContext context) => context.SignOutAsync(
                        OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        new AuthenticationProperties(new Dictionary<string, string?>(StringComparer.Ordinal) { [Properties.SessionId] = "oidc" })));
                });
            });
        });

        var host = builder.Build();
        await host.StartAsync();

        return host;
    }
}
