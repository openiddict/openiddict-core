using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Xml;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Testing;
using Owin;
using Xunit;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using static OpenIddict.Server.Saml.Tests.OpenIddictServerSamlTestHelpers;
using Parameters = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.Parameters;
using SamlStatusCodes = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.StatusCodes;

namespace OpenIddict.Server.Saml.Owin.Tests;

public class OpenIddictServerSamlOwinMiddlewareTests
{
    private const string AuthenticationType = CookieAuthenticationDefaults.AuthenticationType;

    [Fact]
    public async Task Metadata_ReturnsEntityDescriptor()
    {
        // Arrange
        using var server = CreateServer();
        using var client = CreateClient(server);

        // Act
        using var response = await client.GetAsync("/saml/metadata");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(MediaTypes.Metadata, response.Content.Headers.ContentType?.MediaType);

        var document = LoadResponse(await response.Content.ReadAsStringAsync());
        Assert.Equal(IdentityProviderEntityId, document.DocumentElement!.GetAttribute("entityID"));
        Assert.Equal(SingleSignOnEndpoint, document.SelectSingleNode(
            "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService[@Binding='" + Bindings.HttpRedirect + "']/@Location",
            CreateNamespaceManager(document))!.Value);
    }

    [Fact]
    public async Task Endpoints_RejectHttpRequests()
    {
        // Arrange
        using var server = CreateServer();
        using var client = server.HttpClient;
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
        using var server = CreateServer(configuration: saml => saml.SetAssertionProvider<RequestBoundAssertionProvider>());
        using var client = CreateClient(server);

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(id: "_restored"), relayState: "relay&state", certificate: ServiceProviderCertificate);

        // Act: the validated request is stored in a protected state and the user is redirected to the login page.
        using var redirect = await client.GetAsync("/saml/sso" + query);

        Assert.Equal(HttpStatusCode.Redirect, redirect.StatusCode);
        var stateUrl = redirect.Headers.Location!.OriginalString;
        Assert.StartsWith("/saml/sso?" + Parameters.State + "=", stateUrl, StringComparison.Ordinal);

        using var challenge = await client.GetAsync(stateUrl);

        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        Assert.Equal("/login", new Uri(client.BaseAddress, challenge.Headers.Location!).AbsolutePath);

        var returnUrl = QueryValue(new Uri(client.BaseAddress, challenge.Headers.Location!), "ReturnUrl");
        Assert.Equal(stateUrl, returnUrl);

        // Act: the user logs in and is redirected to the return URL.
        var cookie = await LoginAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Get, returnUrl);
        request.Headers.Add("Cookie", cookie);

        using var response = await client.SendAsync(request);

        // Assert
        var (action, saml, relayState) = await ParseFormAsync(response);
        Assert.Equal(AssertionConsumerServiceUrl.AbsoluteUri, action);
        Assert.Equal("relay&state", relayState);

        AssertSuccessfulResponse(LoadResponse(saml), "_restored");

        var policy = response.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("form-action https://sp.example.com", policy, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", policy, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SingleSignOn_PostBinding_ReturnsSignedResponseForAuthenticatedUser()
    {
        // Arrange
        using var server = CreateServer();
        using var client = CreateClient(server);

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
        Assert.Equal("alice", assertion.SelectSingleNode("saml:Subject/saml:NameID", CreateNamespaceManager(assertion.OwnerDocument))!.InnerText);
    }

    [Fact]
    public async Task SingleSignOn_RejectsUnknownAssertionConsumerService()
    {
        // Arrange
        using var server = CreateServer();
        using var client = CreateClient(server);

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(
            assertionConsumerServiceUrl: "https://attacker.example.com/acs"), certificate: ServiceProviderCertificate);

        // Act
        using var response = await client.GetAsync("/saml/sso" + query);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(SR.GetResourceString(SR.ID2256), await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task SingleSignOn_PassiveRequestWithoutSessionReturnsNoPassive()
    {
        // Arrange
        using var server = CreateServer();
        using var client = CreateClient(server);

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(id: "_passive", attributes: "IsPassive=\"true\""),
            certificate: ServiceProviderCertificate);

        // Act
        using var response = await client.GetAsync("/saml/sso" + query);

        // Assert
        var (_, saml, _) = await ParseFormAsync(response);
        var document = LoadResponse(saml);

        Assert.Equal("_passive", document.DocumentElement!.GetAttribute("InResponseTo"));
        Assert.Equal(SamlStatusCodes.NoPassive, document.SelectSingleNode(
            "/samlp:Response/samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value", CreateNamespaceManager(document))!.Value);
        Assert.True(VerifySignature(document.DocumentElement, IdentityProviderCertificate));
    }

    [Fact]
    public async Task SingleSignOn_ForceAuthnRequiresReauthentication()
    {
        // Arrange
        using var server = CreateServer();
        using var client = CreateClient(server);

        var cookie = await LoginAsync(client);

        // Note: authentication tickets store their issuance date with a precision of one second.
        await Task.Delay(TimeSpan.FromSeconds(1.1));

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(id: "_force", attributes: "ForceAuthn=\"true\""),
            certificate: ServiceProviderCertificate);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/saml/sso" + query);
        request.Headers.Add("Cookie", cookie);

        using var redirect = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Redirect, redirect.StatusCode);
        var stateUrl = redirect.Headers.Location!.OriginalString;

        // The previous session cannot be used with the state: the user must authenticate again.
        using var stale = new HttpRequestMessage(HttpMethod.Get, stateUrl);
        stale.Headers.Add("Cookie", cookie);

        using var challenge = await client.SendAsync(stale);
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        Assert.Equal("/login", new Uri(client.BaseAddress, challenge.Headers.Location!).AbsolutePath);

        // Act
        using var callback = new HttpRequestMessage(HttpMethod.Get, stateUrl);
        callback.Headers.Add("Cookie", await LoginAsync(client));

        using var response = await client.SendAsync(callback);

        // Assert
        var (_, saml, _) = await ParseFormAsync(response);
        AssertSuccessfulResponse(LoadResponse(saml), "_force");
    }

    [Fact]
    public async Task SingleSignOn_RejectsTamperedState()
    {
        // Arrange
        using var server = CreateServer();
        using var client = CreateClient(server);

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
        using var server = CreateServer();
        using var client = CreateClient(server);

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
        using var server = CreateServer(sp => sp.AllowIdentityProviderInitiatedSingleSignOn = true);
        using var client = CreateClient(server);

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
    public void Options_RequireAuthenticationType()
    {
        // Arrange
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddServer(options => options.UseSaml(saml => saml.UseOwin()));

        using var provider = services.BuildServiceProvider();

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<OpenIddictServerSamlOwinOptions>>().Value);
        Assert.Contains(SR.GetResourceString(SR.ID0579), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SingleSignOn_ArtifactBinding_RedirectsWithArtifactResolvedOnce()
    {
        // Arrange
        using var server = CreateServer(sp => sp.AssertionConsumerServiceBindings[0] = Bindings.HttpArtifact,
            saml => saml.EnableArtifactBinding());
        using var client = CreateClient(server);

        var cookie = await LoginAsync(client);
        var document = SignDocument(CreateAuthenticationRequest(id: "_artifact"), ServiceProviderCertificate);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/saml/sso")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [Parameters.SamlRequest] = EncodePost(document.OuterXml),
                [Parameters.RelayState] = "artifact-relay"
            })
        };

        request.Headers.Add("Cookie", cookie);

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var location = response.Headers.Location!;
        Assert.Equal(AssertionConsumerServiceUrl.AbsoluteUri, location.GetLeftPart(UriPartial.Path));
        Assert.Equal("artifact-relay", QueryValue(location, Parameters.RelayState));

        var artifact = QueryValue(location, Parameters.SamlArtifact);

        using var first = await ResolveAsync(client, CreateArtifactResolveEnvelope(artifact, certificate: ServiceProviderCertificate));
        using var second = await ResolveAsync(client, CreateArtifactResolveEnvelope(artifact, certificate: ServiceProviderCertificate));

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(MediaTypes.Soap, first.Content.Headers.ContentType?.MediaType);

        var resolved = GetArtifactResponse(await first.Content.ReadAsStringAsync());
        Assert.True(VerifySignature(resolved, IdentityProviderCertificate));

        var embedded = new XmlDocument { PreserveWhitespace = true };
        embedded.AppendChild(embedded.ImportNode(resolved.SelectSingleNode("samlp:Response", CreateNamespaceManager(resolved.OwnerDocument))!, deep: true));
        AssertSuccessfulResponse(embedded, "_artifact");

        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        var empty = GetArtifactResponse(await second.Content.ReadAsStringAsync());
        Assert.Null(empty.SelectSingleNode("samlp:Response", CreateNamespaceManager(empty.OwnerDocument)));
    }

    [Fact]
    public async Task ArtifactResolution_IsNotHandledWhenArtifactBindingIsDisabled()
    {
        // Arrange
        using var server = CreateServer();
        using var client = CreateClient(server);

        // Act
        using var response = await ResolveAsync(client, CreateArtifactResolveEnvelope("AAQ=", certificate: ServiceProviderCertificate));

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task ArtifactResolution_ReturnsSoapFaultForInvalidMessages()
    {
        // Arrange
        using var server = CreateServer(configuration: saml => saml.EnableArtifactBinding());
        using var client = CreateClient(server);

        // Act
        using var response = await ResolveAsync(client, "<invalid />");
        using var get = await client.GetAsync("/saml/artifact");

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Contains("soap:Client", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, get.StatusCode);
    }

    [Fact]
    public async Task Metadata_PublishesArtifactResolutionServiceWhenEnabled()
    {
        // Arrange
        using var server = CreateServer(configuration: saml => saml.EnableArtifactBinding());
        using var client = CreateClient(server);

        // Act
        using var response = await client.GetAsync("/saml/metadata");

        // Assert
        var document = LoadResponse(await response.Content.ReadAsStringAsync());
        Assert.Equal("https://idp.example.com/saml/artifact", document.SelectSingleNode(
            "/md:EntityDescriptor/md:IDPSSODescriptor/md:ArtifactResolutionService/@Location", CreateNamespaceManager(document))!.Value);
    }

    [Fact]
    public async Task SingleSignOn_ReplayProtection_RejectsReusedRequestAndStateByDefault()
    {
        // Arrange
        using var server = CreateServer();
        using var client = CreateClient(server);

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(id: "_single_use"), certificate: ServiceProviderCertificate);

        using var redirect = await client.GetAsync("/saml/sso" + query);
        Assert.Equal(HttpStatusCode.Redirect, redirect.StatusCode);
        var stateUrl = redirect.Headers.Location!.OriginalString;

        var cookie = await LoginAsync(client);

        // Act
        using var callback = new HttpRequestMessage(HttpMethod.Get, stateUrl);
        callback.Headers.Add("Cookie", cookie);
        using var response = await client.SendAsync(callback);

        using var reusedState = new HttpRequestMessage(HttpMethod.Get, stateUrl);
        reusedState.Headers.Add("Cookie", cookie);
        using var stateReplay = await client.SendAsync(reusedState);

        using var requestReplay = await client.GetAsync("/saml/sso" + query);

        // Assert
        var (_, saml, _) = await ParseFormAsync(response);
        AssertSuccessfulResponse(LoadResponse(saml), "_single_use");

        Assert.Equal(HttpStatusCode.BadRequest, stateReplay.StatusCode);
        Assert.Equal(SR.GetResourceString(SR.ID2263), await stateReplay.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.BadRequest, requestReplay.StatusCode);
        Assert.Equal(SR.GetResourceString(SR.ID2420), await requestReplay.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task SingleSignOn_ReplayProtection_CanBeDisabled()
    {
        // Arrange
        using var server = CreateServer(configuration: saml => saml.DisableRequestReplayProtection());
        using var client = CreateClient(server);

        var cookie = await LoginAsync(client);
        var query = CreateRedirectQueryString(CreateAuthenticationRequest(id: "_reusable"), certificate: ServiceProviderCertificate);

        // Act
        using var first = new HttpRequestMessage(HttpMethod.Get, "/saml/sso" + query);
        first.Headers.Add("Cookie", cookie);
        using var firstResponse = await client.SendAsync(first);

        using var second = new HttpRequestMessage(HttpMethod.Get, "/saml/sso" + query);
        second.Headers.Add("Cookie", cookie);
        using var secondResponse = await client.SendAsync(second);

        // Assert
        AssertSuccessfulResponse(LoadResponse((await ParseFormAsync(firstResponse)).Response), "_reusable");
        AssertSuccessfulResponse(LoadResponse((await ParseFormAsync(secondResponse)).Response), "_reusable");
    }

    [Fact]
    public async Task SingleSignOn_RequestStateIsNotConsumedWhenResponseCreationFails()
    {
        // Arrange
        using var server = CreateServer(configuration: saml => saml.SetAssertionProvider<FailingOnceAssertionProvider>(ServiceLifetime.Singleton));
        using var client = CreateClient(server);

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(id: "_transient"), certificate: ServiceProviderCertificate);

        using var redirect = await client.GetAsync("/saml/sso" + query);
        Assert.Equal(HttpStatusCode.Redirect, redirect.StatusCode);
        var stateUrl = redirect.Headers.Location!.OriginalString;

        var cookie = await LoginAsync(client);

        // Act
        using var failing = new HttpRequestMessage(HttpMethod.Get, stateUrl);
        failing.Headers.Add("Cookie", cookie);

        HttpResponseMessage? failed = null;
        try
        {
            failed = await client.SendAsync(failing);
        }

        catch (Exception exception) when (exception is InvalidOperationException or HttpRequestException or AggregateException)
        {
        }

        using var retry = new HttpRequestMessage(HttpMethod.Get, stateUrl);
        retry.Headers.Add("Cookie", cookie);
        using var response = await client.SendAsync(retry);

        // Assert
        Assert.True(failed is null || failed.StatusCode is HttpStatusCode.InternalServerError);
        failed?.Dispose();

        AssertSuccessfulResponse(LoadResponse((await ParseFormAsync(response)).Response), "_transient");
    }

    [Fact]
    public async Task SingleSignOn_ArtifactBinding_DeliversErrorResponses()
    {
        // Arrange
        using var server = CreateServer(sp => sp.AssertionConsumerServiceBindings[0] = Bindings.HttpArtifact,
            saml => saml.EnableArtifactBinding());
        using var client = CreateClient(server);

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(id: "_passive_artifact", attributes: "IsPassive=\"true\""),
            relayState: "passive-relay", certificate: ServiceProviderCertificate);

        // Act
        using var response = await client.GetAsync("/saml/sso" + query);

        // Assert
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.Equal("passive-relay", QueryValue(response.Headers.Location!, Parameters.RelayState));

        using var resolution = await ResolveAsync(client, CreateArtifactResolveEnvelope(
            QueryValue(response.Headers.Location!, Parameters.SamlArtifact), certificate: ServiceProviderCertificate));

        var resolved = GetArtifactResponse(await resolution.Content.ReadAsStringAsync());
        var manager = CreateNamespaceManager(resolved.OwnerDocument);

        var embedded = (XmlElement) resolved.SelectSingleNode("samlp:Response", manager)!;
        Assert.Equal("_passive_artifact", embedded.GetAttribute("InResponseTo"));
        Assert.Equal(SamlStatusCodes.NoPassive, embedded.SelectSingleNode("samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value", manager)!.Value);
        Assert.Null(embedded.SelectSingleNode("saml:Assertion", manager));
    }

    [Fact]
    public async Task SingleSignOn_ReturnsEncryptedAssertionWhenRequired()
    {
        // Arrange
        var encryption = CreateCertificate("CN=sp-encryption.example.com");

        using var server = CreateServer(sp =>
        {
            sp.EncryptAssertions = true;
            sp.EncryptionCertificate = encryption;
        });

        using var client = CreateClient(server);

        var cookie = await LoginAsync(client);
        var document = SignDocument(CreateAuthenticationRequest(id: "_encrypted"), ServiceProviderCertificate);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/saml/sso")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [Parameters.SamlRequest] = EncodePost(document.OuterXml)
            })
        };

        request.Headers.Add("Cookie", cookie);

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        var (_, saml, _) = await ParseFormAsync(response);
        var result = LoadResponse(saml);
        var manager = CreateNamespaceManager(result);

        Assert.Null(result.SelectSingleNode("/samlp:Response/saml:Assertion", manager));

        var assertion = DecryptAssertion((XmlElement) result.SelectSingleNode("/samlp:Response/saml:EncryptedAssertion", manager)!, encryption);
        Assert.True(VerifySignature(assertion, IdentityProviderCertificate));
    }

    private static async Task<HttpResponseMessage> ResolveAsync(HttpClient client, string envelope)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/saml/artifact")
        {
            Content = new StringContent(envelope, Encoding.UTF8, MediaTypes.Soap)
        };

        request.Headers.Add("SOAPAction", "http://www.oasis-open.org/committees/security");

        return await client.SendAsync(request);
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
            return WebUtility.HtmlDecode(html.Substring(index, html.IndexOf('"', index) - index));
        }
    }

    private static string QueryValue(Uri uri, string name)
    {
        foreach (var parameter in uri.Query.TrimStart('?').Split('&'))
        {
            var index = parameter.IndexOf('=');
            if (index is not -1 && string.Equals(parameter.Substring(0, index), name, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(parameter.Substring(index + 1));
            }
        }

        throw new InvalidOperationException("The parameter cannot be found.");
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

    private static TestServer CreateServer(
        Action<OpenIddictServerSamlServiceProvider>? serviceProvider = null,
        Action<OpenIddictServerSamlBuilder>? configuration = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();

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
                        .UseOwin(owin => owin.SetAuthenticationType(AuthenticationType));

                    configuration?.Invoke(saml);
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
                    identity.AddClaim(new Claim(Claims.Email, "alice@example.com"));

                    context.Authentication.SignIn(new AuthenticationProperties(), identity);
                    context.Response.StatusCode = 200;
                    return Task.CompletedTask;
                }

                context.Response.StatusCode = 404;
                return Task.CompletedTask;
            });
        });
    }

    public sealed class FailingOnceAssertionProvider : IOpenIddictServerSamlAssertionProvider
    {
        private int _calls;

        public ValueTask<OpenIddictServerSamlModels.AssertionDescriptor?> CreateAssertionAsync(OpenIddictServerSamlModels.AssertionContext context)
            => Interlocked.Increment(ref _calls) is 1
                ? throw new InvalidOperationException("Transient failure.")
                : new(new OpenIddictServerSamlModels.AssertionDescriptor { NameId = "alice" });
    }

    public sealed class RequestBoundAssertionProvider : IOpenIddictServerSamlAssertionProvider
    {
        public ValueTask<OpenIddictServerSamlModels.AssertionDescriptor?> CreateAssertionAsync(OpenIddictServerSamlModels.AssertionContext context)
            => new(context.Request is { Id: "_restored", IsSigned: true, Binding: Bindings.HttpRedirect }
                ? new OpenIddictServerSamlModels.AssertionDescriptor { NameId = "alice" }
                : null);
    }
}
