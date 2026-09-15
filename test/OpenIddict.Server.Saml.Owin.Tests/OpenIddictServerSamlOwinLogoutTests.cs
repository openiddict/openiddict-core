using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Testing;
using OpenIddict.Server.Saml.Tests;
using Owin;
using Xunit;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using static OpenIddict.Server.Saml.Tests.OpenIddictServerSamlLogoutTestHelpers;
using static OpenIddict.Server.Saml.Tests.OpenIddictServerSamlTestHelpers;
using Parameters = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.Parameters;
using SamlStatusCodes = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.StatusCodes;

namespace OpenIddict.Server.Saml.Owin.Tests;

public class OpenIddictServerSamlOwinLogoutTests
{
    private const string AuthenticationType = CookieAuthenticationDefaults.AuthenticationType;

    [Fact]
    public async Task SingleLogout_IsNotHandledWhenSingleLogoutIsDisabled()
    {
        // Arrange
        using var server = CreateServer([], enable: false);
        using var client = CreateClient(server);

        // Act
        using var response = await client.GetAsync("/saml/slo" + CreateRedirectQueryString(CreateLogoutRequest(), certificate: ServiceProviderCertificate));

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Metadata_PublishesSingleLogoutService()
    {
        // Arrange
        using var server = CreateServer([]);
        using var client = CreateClient(server);

        // Act
        var document = LoadResponse(await client.GetStringAsync("/saml/metadata"));

        // Assert
        Assert.Equal(SingleLogoutEndpoint, document.SelectSingleNode("/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService[@Binding='" +
            Bindings.HttpPost + "']/@Location", CreateNamespaceManager(document))!.Value);
    }

    [Fact]
    public async Task SingleLogout_TerminatesSessionCreatedBySingleSignOnAndSignsOutUser()
    {
        // Arrange
        List<FakeSession> sessions = [];

        using var server = CreateServer(sessions);
        using var client = CreateClient(server);

        var cookie = await LoginAsync(client);

        using var sso = new HttpRequestMessage(HttpMethod.Get, "/saml/sso" +
            CreateRedirectQueryString(CreateAuthenticationRequest(), certificate: ServiceProviderCertificate));
        sso.Headers.Add("Cookie", cookie);

        using var assertion = await client.SendAsync(sso);
        var document = LoadResponse(ParseSamlResponse(await assertion.Content.ReadAsStringAsync()));

        var index = document.SelectSingleNode("//saml:AuthnStatement/@SessionIndex", CreateNamespaceManager(document))!.Value;
        var session = Assert.Single(sessions);
        Assert.Equal(session.Id, index);

        // Act
        using var request = new HttpRequestMessage(HttpMethod.Get, "/saml/slo" + CreateRedirectQueryString(
            CreateLogoutRequest(id: "_sp_logout", sessionIndexes: [index!]), certificate: ServiceProviderCertificate));
        request.Headers.Add("Cookie", cookie);

        using var response = await client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.Equal(Statuses.Revoked, session.Status);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), value =>
            value.StartsWith(".AspNet.Cookies=;", StringComparison.Ordinal));

        var (logout, _, valid) = DecodeRedirectUrl(response.Headers.Location!, Parameters.SamlResponse, IdentityProviderCertificate);

        Assert.True(valid);
        Assert.Equal("_sp_logout", logout.DocumentElement!.GetAttribute("InResponseTo"));
        Assert.Equal(SamlStatusCodes.Success, logout.SelectSingleNode(
            "/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value", CreateNamespaceManager(logout))!.Value);
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

        using var server = CreateServer(sessions, sp => sp.SingleLogoutServiceBinding = Bindings.HttpPost);
        using var client = CreateClient(server);

        // Act
        using var request = new HttpRequestMessage(HttpMethod.Post, "/saml/slo")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [Parameters.SamlRequest] = EncodePost(SignDocument(CreateLogoutRequest(id: "_post_logout", sessionIndexes: ["s1"]),
                    ServiceProviderCertificate).OuterXml)
            })
        };

        using var propagation = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.SeeOther, propagation.StatusCode);
        Assert.All(sessions, session => Assert.Equal(Statuses.Revoked, session.Status));

        var (logout, _, _) = DecodeRedirectUrl(propagation.Headers.Location!, Parameters.SamlRequest, IdentityProviderCertificate);

        using var response = await client.GetAsync("/saml/slo" + CreateRedirectQueryString(
            CreateLogoutResponse(logout.DocumentElement!.GetAttribute("ID")), certificate: SecondServiceProviderCertificate,
            parameter: Parameters.SamlResponse));

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("action=\"" + ServiceProviderLogoutUrl + "\"", html, StringComparison.Ordinal);

        var document = LoadResponse(ParseSamlResponse(html));
        Assert.Equal("_post_logout", document.DocumentElement!.GetAttribute("InResponseTo"));
        Assert.True(VerifySignature(document.DocumentElement, IdentityProviderCertificate));
    }

    [Fact]
    public async Task StartOpenIddictSamlLogoutAsync_PropagatesLogoutAndRedirectsToReturnUrl()
    {
        // Arrange
        List<FakeSession> sessions = [CreateSamlSession("s1", ServiceProviderEntityId, "alice")];

        using var server = CreateServer(sessions);
        using var client = CreateClient(server);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/logout");
        request.Headers.Add("Cookie", await LoginAsync(client));

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

    private static string ParseSamlResponse(string html)
    {
        var prefix = "<input type=\"hidden\" name=\"" + Parameters.SamlResponse + "\" value=\"";
        var index = html.IndexOf(prefix, StringComparison.Ordinal) + prefix.Length;

        return Encoding.UTF8.GetString(Convert.FromBase64String(WebUtility.HtmlDecode(html.Substring(index, html.IndexOf('"', index) - index))));
    }

    private static async Task<string> LoginAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/login");
        return string.Join("; ", response.Headers.GetValues("Set-Cookie").Select(static value => value.Split(';')[0]));
    }

    private static HttpClient CreateClient(TestServer server)
    {
        var client = server.HttpClient;
        client.BaseAddress = new Uri("https://idp.example.com/");
        return client;
    }

    private static TestServer CreateServer(List<FakeSession> sessions,
        Action<OpenIddictServerSamlServiceProvider>? serviceProvider = null, bool enable = true)
    {
        var services = new ServiceCollection();

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
                    .UseOwin(owin => owin.SetAuthenticationType(AuthenticationType));

                if (enable)
                {
                    saml.EnableSingleLogout();
                }
            });
        });

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
                AuthenticationType = AuthenticationType,
                LoginPath = new PathString("/login")
            });

            app.UseOpenIddictSaml();

            app.Run(context =>
            {
                if (context.Request.Path == new PathString("/login"))
                {
                    var identity = new ClaimsIdentity(AuthenticationType);
                    identity.AddClaim(new Claim(Claims.Subject, "alice"));
                    identity.AddClaim(new Claim(LoginIdClaimType, "login-1"));

                    context.Authentication.SignIn(new AuthenticationProperties(), identity);
                    context.Response.StatusCode = 200;
                    return Task.CompletedTask;
                }

                if (context.Request.Path == new PathString("/logout"))
                {
                    return context.StartOpenIddictSamlLogoutAsync("/signed-out");
                }

                context.Response.StatusCode = 404;
                return Task.CompletedTask;
            });
        });
    }
}
