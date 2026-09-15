using System.Security.Claims;
using System.Xml;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using static OpenIddict.Server.Saml.OpenIddictServerSamlModels;
using static OpenIddict.Server.Saml.Tests.OpenIddictServerSamlLogoutTestHelpers;
using static OpenIddict.Server.Saml.Tests.OpenIddictServerSamlTestHelpers;
using Parameters = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.Parameters;

namespace OpenIddict.Server.Saml.Tests;

public class OpenIddictServerSamlLogoutTests
{
    private static readonly Uri Endpoint = new(SingleLogoutEndpoint, UriKind.Absolute);

    [Fact]
    public async Task AttachSessionAsync_ReturnsAssertionUnchangedWhenSingleLogoutIsDisabled()
    {
        // Arrange
        var (provider, sessions, _) = CreateProvider(enable: false);
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var assertion = new AssertionDescriptor { NameId = "alice", SessionIndex = "original" };

        // Act
        var result = await service.AttachSessionAsync(CreateAssertionContext(provider), assertion);

        // Assert
        Assert.Same(assertion, result);
        Assert.Empty(sessions);
    }

    [Fact]
    public async Task AttachSessionAsync_CreatesAndReusesServerSideSession()
    {
        // Arrange
        var (provider, sessions, _) = CreateProvider();
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var context = CreateAssertionContext(provider);

        // Act
        var first = await service.AttachSessionAsync(context, new AssertionDescriptor { NameId = "alice" });
        var second = await service.AttachSessionAsync(context, new AssertionDescriptor { NameId = "alice" });

        // Assert
        var session = Assert.Single(sessions);
        Assert.Equal(session.Id, first.SessionIndex);
        Assert.Equal(session.Id, second.SessionIndex);
        Assert.Equal("login-1", session.LoginId);
        Assert.Equal("alice", session.Subject);
        Assert.Null(session.ApplicationId);
        Assert.Equal(ServiceProviderEntityId, session.Properties[SessionProperties.ServiceProvider].GetString());
        Assert.Equal("alice", session.Properties[SessionProperties.NameId].GetString());
    }

    [Fact]
    public async Task Options_RequireLoginIdClaimTypeWhenSingleLogoutIsEnabled()
    {
        // Arrange
        var (provider, _, _) = CreateProvider(configuration: saml => saml.Configure(options => options.LoginIdClaimType = null));
        await using var _ = provider;

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(() =>
            provider.GetRequiredService<IOptionsMonitor<OpenIddictServerSamlOptions>>().CurrentValue);

        Assert.Contains(SR.GetResourceString(SR.ID01004), exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://sp.example.com/slo", "urn:invalid")]
    [InlineData("urn:sp:slo", null)]
    [InlineData("https://sp.example.com/slo#fragment", null)]
    public void ValidateServiceProvider_RejectsInvalidSingleLogoutService(string url, string? binding)
    {
        // Arrange
        var sp = CreateServiceProvider();
        sp.SingleLogoutServiceUrl = new Uri(url, UriKind.Absolute);
        sp.SingleLogoutServiceBinding = binding;

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => OpenIddictServerSamlConfiguration.ValidateServiceProvider(sp));
        Assert.Equal(SR.FormatID01000(ServiceProviderEntityId), exception.Message);
    }

    [Fact]
    public async Task CreateMetadata_PublishesSingleLogoutServiceWhenEnabled()
    {
        // Arrange
        var (provider, _, _) = CreateProvider();
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Act
        var document = LoadResponse(service.CreateMetadata(new Uri(SingleSignOnEndpoint), null, Endpoint));

        // Assert
        var services = document.SelectNodes("/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService", CreateNamespaceManager(document))!;
        Assert.Equal(2, services.Count);
        Assert.Equal(SingleLogoutEndpoint, ((XmlElement) services[0]!).GetAttribute("Location"));
    }

    [Fact]
    public async Task CreateMetadata_DoesNotPublishSingleLogoutServiceWhenDisabled()
    {
        // Arrange
        var (provider, _, _) = CreateProvider(enable: false);
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Act
        var document = LoadResponse(service.CreateMetadata(new Uri(SingleSignOnEndpoint), null, Endpoint));

        // Assert
        Assert.Empty(document.SelectNodes("//md:SingleLogoutService", CreateNamespaceManager(document))!.Cast<XmlNode>());
    }

    [Fact]
    public async Task ValidateRedirectLogoutRequestAsync_AcceptsSignedRequest()
    {
        // Arrange
        var (provider, _, _) = CreateProvider();
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var query = CreateRedirectQueryString(CreateLogoutRequest(id: "_slo", sessionIndexes: ["s1", "s2"],
            attributes: "Reason=\"" + LogoutReasons.User + "\""), relayState: "relay", certificate: ServiceProviderCertificate);

        // Act
        var result = await service.ValidateRedirectLogoutRequestAsync(query, Endpoint);

        // Assert
        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.Equal("_slo", result.Request!.Id);
        Assert.Equal("alice", result.Request.NameId);
        Assert.Equal(["s1", "s2"], result.Request.SessionIndexes);
        Assert.Equal(Bindings.HttpRedirect, result.Request.Binding);
        Assert.Equal(LogoutReasons.User, result.Request.Reason);
        Assert.Equal("relay", result.RelayState);
    }

    [Fact]
    public async Task ValidateRedirectLogoutRequestAsync_RejectsUnsignedRequest()
    {
        // Arrange
        var (provider, _, _) = CreateProvider();
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();

        // Act
        var result = await service.ValidateRedirectLogoutRequestAsync(CreateRedirectQueryString(CreateLogoutRequest()), Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.False(result.CanReturnErrorToServiceProvider);
        Assert.Equal(SR.GetResourceString(SR.ID2503), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRedirectLogoutRequestAsync_RejectsRequestSignedWithUnknownKey()
    {
        // Arrange
        var (provider, _, _) = CreateProvider();
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var query = CreateRedirectQueryString(CreateLogoutRequest(), certificate: SecondServiceProviderCertificate);

        // Act
        var result = await service.ValidateRedirectLogoutRequestAsync(query, Endpoint);

        // Assert
        Assert.False(result.CanReturnErrorToServiceProvider);
        Assert.Equal(SR.GetResourceString(SR.ID2504), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRedirectLogoutRequestAsync_RejectsUnknownIssuer()
    {
        // Arrange
        var (provider, _, _) = CreateProvider();
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var query = CreateRedirectQueryString(CreateLogoutRequest(issuer: "https://unknown.example.com/"), certificate: ServiceProviderCertificate);

        // Act
        var result = await service.ValidateRedirectLogoutRequestAsync(query, Endpoint);

        // Assert
        Assert.Null(result.ServiceProvider);
        Assert.Equal(SR.GetResourceString(SR.ID2502), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRedirectLogoutRequestAsync_RejectsInvalidDestination()
    {
        // Arrange
        var (provider, _, _) = CreateProvider();
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var query = CreateRedirectQueryString(CreateLogoutRequest(id: "_dest", destination: "https://attacker.example.com/slo"),
            certificate: ServiceProviderCertificate);

        // Act
        var result = await service.ValidateRedirectLogoutRequestAsync(query, Endpoint);

        // Assert
        Assert.True(result.CanReturnErrorToServiceProvider);
        Assert.Equal("_dest", result.RequestId);
        Assert.Equal(SR.GetResourceString(SR.ID2507), result.ErrorDescription);

        var action = service.CreateErrorResponseAction(result);
        var (document, _, valid) = DecodeRedirectUrl(action.RedirectUrl!, Parameters.SamlResponse, IdentityProviderCertificate);

        Assert.True(valid);
        Assert.StartsWith(ServiceProviderLogoutUrl + "?", action.RedirectUrl!.AbsoluteUri, StringComparison.Ordinal);
        Assert.Equal("_dest", document.DocumentElement!.GetAttribute("InResponseTo"));
        Assert.Equal(StatusCodes.Requester, document.SelectSingleNode(
            "/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value", CreateNamespaceManager(document))!.Value);
    }

    [Fact]
    public async Task ValidateRedirectLogoutRequestAsync_RejectsExpiredRequest()
    {
        // Arrange
        var (provider, _, _) = CreateProvider();
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var query = CreateRedirectQueryString(CreateLogoutRequest(attributes: "NotOnOrAfter=\"" +
            FormatInstant(DateTimeOffset.UtcNow.AddMinutes(-10)) + "\""), certificate: ServiceProviderCertificate);

        // Act
        var result = await service.ValidateRedirectLogoutRequestAsync(query, Endpoint);

        // Assert
        Assert.Equal(SR.GetResourceString(SR.ID2506), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRedirectLogoutRequestAsync_RejectsReplayedRequest()
    {
        // Arrange
        var (provider, _, _) = CreateProvider();
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var query = CreateRedirectQueryString(CreateLogoutRequest(id: "_replayed"), certificate: ServiceProviderCertificate);

        // Act
        var first = await service.ValidateRedirectLogoutRequestAsync(query, Endpoint);
        var second = await service.ValidateRedirectLogoutRequestAsync(query, Endpoint);

        // Assert
        Assert.True(first.Succeeded, first.ErrorDescription);
        Assert.False(second.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2509), second.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRedirectLogoutRequestAsync_RejectsServiceProviderWithoutSingleLogoutService()
    {
        // Arrange
        var (provider, _, _) = CreateProvider(serviceProvider: sp => sp.SingleLogoutServiceUrl = null);
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var query = CreateRedirectQueryString(CreateLogoutRequest(), certificate: ServiceProviderCertificate);

        // Act
        var result = await service.ValidateRedirectLogoutRequestAsync(query, Endpoint);

        // Assert
        Assert.False(result.CanReturnErrorToServiceProvider);
        Assert.Equal(SR.GetResourceString(SR.ID2510), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidatePostLogoutRequestAsync_AcceptsSignedRequest()
    {
        // Arrange
        var (provider, _, _) = CreateProvider();
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var document = SignDocument(CreateLogoutRequest(id: "_post"), ServiceProviderCertificate);

        // Act
        var result = await service.ValidatePostLogoutRequestAsync(EncodePost(document.OuterXml), "relay", Endpoint);

        // Assert
        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.Equal(Bindings.HttpPost, result.Request!.Binding);
        Assert.Empty(result.Request.SessionIndexes);
    }

    [Fact]
    public async Task ValidatePostLogoutRequestAsync_RejectsMissingNameId()
    {
        // Arrange
        var (provider, _, _) = CreateProvider();
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var document = SignDocument(CreateLogoutRequest(nameId: null), ServiceProviderCertificate);

        // Act
        var result = await service.ValidatePostLogoutRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        // Assert
        Assert.True(result.CanReturnErrorToServiceProvider);
        Assert.Equal(StatusCodes.UnknownPrincipal, result.SecondLevelStatus);
        Assert.Equal(SR.GetResourceString(SR.ID2508), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRedirectLogoutResponseAsync_RejectsUnsignedResponse()
    {
        // Arrange
        var (provider, _, _) = CreateProvider();
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var query = CreateRedirectQueryString(CreateLogoutResponse("_request"), parameter: Parameters.SamlResponse);

        // Act
        var result = await service.ValidateRedirectLogoutResponseAsync(query, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2503), result.ErrorDescription);
    }

    [Fact]
    public async Task ProcessLogoutRequestAsync_PropagatesLogoutAndReturnsResponseToInitiator()
    {
        // Arrange
        var (provider, sessions, _) = CreateProvider();
        await using var _ = provider;

        sessions.Add(CreateSamlSession("s1", ServiceProviderEntityId, "alice"));
        sessions.Add(CreateSamlSession("s2", SecondServiceProviderEntityId, "alice-sp2"));
        sessions.Add(new FakeSession { Id = "oidc", ApplicationId = "a1", LoginId = "login-1", Status = Statuses.Valid, Subject = "alice" });
        sessions.Add(CreateSamlSession("other", SecondServiceProviderEntityId, "alice-sp2", login: "login-2"));

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var query = CreateRedirectQueryString(CreateLogoutRequest(id: "_initiator", sessionIndexes: ["s1"]),
            relayState: "initiator-relay", certificate: ServiceProviderCertificate);

        var result = await service.ValidateRedirectLogoutRequestAsync(query, Endpoint);

        // Act
        var action = await service.ProcessLogoutRequestAsync(result, CreatePrincipal());

        // Assert: the sessions sharing the login identifier are revoked and the second service provider is notified.
        Assert.True(action.SignOut);
        Assert.False(action.PartialLogout);
        Assert.True(new HashSet<string>(["s1", "s2", "oidc"], StringComparer.Ordinal).SetEquals(action.TerminatedSessionIds));
        Assert.Equal(Statuses.Revoked, sessions.Single(session => session.Id is "oidc").Status);
        Assert.Equal(Statuses.Valid, sessions.Single(session => session.Id is "other").Status);

        Assert.StartsWith(SecondServiceProviderLogoutUrl + "?", action.RedirectUrl!.AbsoluteUri, StringComparison.Ordinal);

        var (request, relayState, valid) = DecodeRedirectUrl(action.RedirectUrl, Parameters.SamlRequest, IdentityProviderCertificate);
        var manager = CreateNamespaceManager(request);

        Assert.True(valid);
        Assert.Null(relayState);
        Assert.Equal(SecondServiceProviderLogoutUrl, request.DocumentElement!.GetAttribute("Destination"));
        Assert.Equal(IdentityProviderEntityId, request.SelectSingleNode("/samlp:LogoutRequest/saml:Issuer", manager)!.InnerText);
        Assert.Equal("alice-sp2", request.SelectSingleNode("/samlp:LogoutRequest/saml:NameID", manager)!.InnerText);
        Assert.Equal("s2", request.SelectSingleNode("/samlp:LogoutRequest/samlp:SessionIndex", manager)!.InnerText);

        // Act: the second service provider returns its logout response.
        var response = await service.ValidateRedirectLogoutResponseAsync(CreateRedirectQueryString(
            CreateLogoutResponse(request.DocumentElement.GetAttribute("ID")), certificate: SecondServiceProviderCertificate,
            parameter: Parameters.SamlResponse), Endpoint);

        Assert.True(response.Succeeded, response.ErrorDescription);

        var final = await service.ProcessLogoutResponseAsync(response);

        // Assert: the logout response is returned to the service provider that initiated the logout.
        Assert.False(final.SignOut);
        Assert.StartsWith(ServiceProviderLogoutUrl + "?", final.RedirectUrl!.AbsoluteUri, StringComparison.Ordinal);

        var (document, state, signed) = DecodeRedirectUrl(final.RedirectUrl, Parameters.SamlResponse, IdentityProviderCertificate);
        var namespaces = CreateNamespaceManager(document);

        Assert.True(signed);
        Assert.Equal("initiator-relay", state);
        Assert.Equal("_initiator", document.DocumentElement!.GetAttribute("InResponseTo"));
        Assert.Equal(StatusCodes.Success, document.SelectSingleNode("/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value", namespaces)!.Value);
        Assert.Null(document.SelectSingleNode("/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/samlp:StatusCode", namespaces));

        // The logout state can only be used once.
        var replayed = await service.ProcessLogoutResponseAsync(response);
        Assert.True(replayed.IsCompleted);
    }

    [Fact]
    public async Task ProcessLogoutRequestAsync_ReturnsPartialLogoutWhenParticipantFails()
    {
        // Arrange
        var (provider, sessions, _) = CreateProvider();
        await using var _ = provider;

        sessions.Add(CreateSamlSession("s1", ServiceProviderEntityId, "alice"));
        sessions.Add(CreateSamlSession("s2", SecondServiceProviderEntityId, "alice-sp2"));

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var result = await service.ValidateRedirectLogoutRequestAsync(CreateRedirectQueryString(
            CreateLogoutRequest(sessionIndexes: ["s1"]), certificate: ServiceProviderCertificate), Endpoint);

        var action = await service.ProcessLogoutRequestAsync(result, CreatePrincipal());
        var (request, _, _) = DecodeRedirectUrl(action.RedirectUrl!, Parameters.SamlRequest, IdentityProviderCertificate);

        var response = await service.ValidateRedirectLogoutResponseAsync(CreateRedirectQueryString(
            CreateLogoutResponse(request.DocumentElement!.GetAttribute("ID"), status: StatusCodes.Responder),
            certificate: SecondServiceProviderCertificate, parameter: Parameters.SamlResponse), Endpoint);

        // Act
        var final = await service.ProcessLogoutResponseAsync(response);

        // Assert
        Assert.True(final.PartialLogout);

        var (document, _, _) = DecodeRedirectUrl(final.RedirectUrl!, Parameters.SamlResponse, IdentityProviderCertificate);
        Assert.Equal(StatusCodes.PartialLogout, document.SelectSingleNode(
            "/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value", CreateNamespaceManager(document))!.Value);
    }

    [Fact]
    public async Task ProcessLogoutRequestAsync_DoesNotTerminateSessionWhenNameIdDoesNotMatch()
    {
        // Arrange
        var (provider, sessions, _) = CreateProvider();
        await using var _ = provider;

        sessions.Add(CreateSamlSession("s1", ServiceProviderEntityId, "bob", subject: "bob", login: "login-bob"));

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var result = await service.ValidateRedirectLogoutRequestAsync(CreateRedirectQueryString(
            CreateLogoutRequest(nameId: "alice", sessionIndexes: ["s1"]), certificate: ServiceProviderCertificate), Endpoint);

        // Act
        var action = await service.ProcessLogoutRequestAsync(result, CreatePrincipal());

        // Assert
        Assert.False(action.SignOut);
        Assert.Empty(action.TerminatedSessionIds);
        Assert.Equal(Statuses.Valid, sessions[0].Status);
        Assert.StartsWith(ServiceProviderLogoutUrl + "?", action.RedirectUrl!.AbsoluteUri, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProcessLogoutRequestAsync_ResolvesSessionsFromLoginWhenNoSessionIndexIsSpecified()
    {
        // Arrange
        var (provider, sessions, _) = CreateProvider(serviceProvider: sp => sp.SingleLogoutServiceBinding = Bindings.HttpPost);
        await using var _ = provider;

        sessions.Add(CreateSamlSession("s1", ServiceProviderEntityId, "alice"));

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var result = await service.ValidatePostLogoutRequestAsync(EncodePost(
            SignDocument(CreateLogoutRequest(id: "_nosession"), ServiceProviderCertificate).OuterXml), "relay", Endpoint);

        // Act
        var action = await service.ProcessLogoutRequestAsync(result, CreatePrincipal());

        // Assert
        Assert.True(action.SignOut);
        Assert.Equal("s1", Assert.Single(action.TerminatedSessionIds));
        Assert.Equal(new Uri(ServiceProviderLogoutUrl), action.FormPostUrl);
        Assert.Contains(action.FormFields, field => field is { Key: Parameters.RelayState, Value: "relay" });

        var document = LoadResponse(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(
            action.FormFields.Single(field => field.Key is Parameters.SamlResponse).Value)));

        Assert.Equal("_nosession", document.DocumentElement!.GetAttribute("InResponseTo"));
        Assert.True(VerifySignature(document.DocumentElement, IdentityProviderCertificate));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ProcessLogoutRequestAsync_SendsSoapLogoutRequests(bool succeeds)
    {
        // Arrange
        var (provider, sessions, soap) = CreateProvider(secondBinding: Bindings.Soap);
        await using var _ = provider;

        soap.Callback = (url, envelope) =>
        {
            if (!succeeds)
            {
                return null;
            }

            var request = LoadResponse(envelope);
            var manager = CreateNamespaceManager(request);
            var element = (XmlElement) request.SelectSingleNode("/soap:Envelope/soap:Body/samlp:LogoutRequest", manager)!;

            Assert.True(VerifySignature(element, IdentityProviderCertificate));
            Assert.Equal("s2", element.SelectSingleNode("samlp:SessionIndex", manager)!.InnerText);

            var response = SignDocument(CreateLogoutResponse(element.GetAttribute("ID"), destination: null), SecondServiceProviderCertificate);

            return "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>" +
                response.DocumentElement!.OuterXml + "</soap:Body></soap:Envelope>";
        };

        sessions.Add(CreateSamlSession("s1", ServiceProviderEntityId, "alice"));
        sessions.Add(CreateSamlSession("s2", SecondServiceProviderEntityId, "alice-sp2"));

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var result = await service.ValidateRedirectLogoutRequestAsync(CreateRedirectQueryString(
            CreateLogoutRequest(sessionIndexes: ["s1"]), certificate: ServiceProviderCertificate), Endpoint);

        // Act
        var action = await service.ProcessLogoutRequestAsync(result, CreatePrincipal());

        // Assert
        Assert.Equal(new Uri(SecondServiceProviderLogoutUrl), Assert.Single(soap.Requests).Url);
        Assert.Equal(!succeeds, action.PartialLogout);
        Assert.StartsWith(ServiceProviderLogoutUrl + "?", action.RedirectUrl!.AbsoluteUri, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TerminateSessionAsync_NotifiesServiceProvidersOfOpenIdConnectSessions()
    {
        // Arrange
        var (provider, sessions, soap) = CreateProvider(server: options => options.EnableFrontchannelLogout());
        await using var _ = provider;

        sessions.Add(new FakeSession { Id = "oidc", LoginId = "login-1", Status = Statuses.Valid, Subject = "alice" });
        sessions.Add(CreateSamlSession("s1", ServiceProviderEntityId, "alice"));
        sessions.Add(CreateSamlSession("s2", SecondServiceProviderEntityId, "alice-sp2"));

        var service = provider.GetRequiredService<OpenIddictServerService>();

        // Act
        var result = await service.TerminateSessionAsync("oidc");

        // Assert
        Assert.NotNull(result);
        Assert.Equal(3, result.SessionIds.Length);
        Assert.All(sessions, session => Assert.Equal(Statuses.Revoked, session.Status));
        Assert.Equal(2, result.FrontchannelLogoutUris.Length);

        var uri = Assert.Single(result.FrontchannelLogoutUris, uri => uri.Host is "sp2.example.com");
        var (request, _, valid) = DecodeRedirectUrl(uri, Parameters.SamlRequest, IdentityProviderCertificate);

        Assert.True(valid);
        Assert.Equal("alice-sp2", request.SelectSingleNode("/samlp:LogoutRequest/saml:NameID", CreateNamespaceManager(request))!.InnerText);
        Assert.Empty(soap.Requests);
    }

    [Fact]
    public async Task StartLogoutAsync_PropagatesLogoutAndRedirectsToReturnUrl()
    {
        // Arrange
        var (provider, sessions, _) = CreateProvider();
        await using var _ = provider;

        sessions.Add(CreateSamlSession("s1", ServiceProviderEntityId, "alice"));

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();

        // Act
        var action = await service.StartLogoutAsync(CreatePrincipal(), new Uri("/signed-out", UriKind.Relative));

        // Assert
        Assert.True(action.SignOut);
        Assert.Equal(Statuses.Revoked, sessions[0].Status);

        var (request, _, _) = DecodeRedirectUrl(action.RedirectUrl!, Parameters.SamlRequest, IdentityProviderCertificate);

        var response = await service.ValidatePostLogoutResponseAsync(EncodePost(SignDocument(CreateLogoutResponse(
            request.DocumentElement!.GetAttribute("ID"), issuer: ServiceProviderEntityId), ServiceProviderCertificate).OuterXml), null, Endpoint);

        var final = await service.ProcessLogoutResponseAsync(response);

        Assert.Equal("/signed-out", final.RedirectUrl!.OriginalString);
        Assert.Null(final.FormPostUrl);
    }

    [Fact]
    public async Task ProcessLogoutResponseAsync_CompletesUnknownResponses()
    {
        // Arrange
        var (provider, _, _) = CreateProvider();
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var response = await service.ValidateRedirectLogoutResponseAsync(CreateRedirectQueryString(
            CreateLogoutResponse("_unknown"), certificate: SecondServiceProviderCertificate, parameter: Parameters.SamlResponse), Endpoint);

        // Act
        var action = await service.ProcessLogoutResponseAsync(response);

        // Assert
        Assert.True(action.IsCompleted);
    }

    [Fact]
    public async Task ProcessLogoutRequestAsync_ThrowsWhenSingleLogoutIsDisabled()
    {
        // Arrange
        var (provider, _, _) = CreateProvider(enable: false);
        await using var _ = provider;

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var result = new LogoutRequestResult
        {
            Request = new LogoutRequest { Binding = Bindings.HttpRedirect, Id = "_id", IssueInstant = DateTimeOffset.UtcNow, Issuer = "issuer", NameId = "alice" },
            ServiceProvider = CreateServiceProvider()
        };

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () => await service.ProcessLogoutRequestAsync(result, null));
        Assert.Equal(SR.GetResourceString(SR.ID01002), exception.Message);
    }

    [Fact]
    public void CreateLogoutPage_RendersFramesAndForm()
    {
        // Arrange
        var action = new LogoutAction
        {
            FormFields = [new(Parameters.SamlResponse, "<value>")],
            FormPostUrl = new Uri("https://sp.example.com/slo"),
            FrontchannelLogoutUris = [new Uri("https://rp.example.com/logout?sid=1")]
        };

        // Act
        var page = OpenIddictServerSamlLogoutService.CreateLogoutPage(action, "nonce");
        var policy = OpenIddictServerSamlLogoutService.CreateLogoutContentSecurityPolicy(action, "nonce");

        // Assert
        Assert.Contains("<iframe hidden width=\"0\" height=\"0\" src=\"https://rp.example.com/logout?sid=1\"></iframe>", page, StringComparison.Ordinal);
        Assert.Contains("value=\"&lt;value&gt;\"", page, StringComparison.Ordinal);
        Assert.Contains("<script nonce=\"nonce\">", page, StringComparison.Ordinal);
        Assert.Contains("frame-src https://rp.example.com;", policy, StringComparison.Ordinal);
        Assert.Contains("form-action https://sp.example.com;", policy, StringComparison.Ordinal);
    }

    private static ClaimsPrincipal CreatePrincipal(string login = "login-1") => new(new ClaimsIdentity(
    [
        new Claim(Claims.Subject, "alice"),
        new Claim(LoginIdClaimType, login)
    ], "test"));

    private static AssertionContext CreateAssertionContext(IServiceProvider provider) => new()
    {
        Principal = CreatePrincipal(),
        ServiceProvider = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerSamlOptions>>().CurrentValue.ServiceProviders[0]
    };

    private static (ServiceProvider Provider, List<FakeSession> Sessions, FakeSoapClient Soap) CreateProvider(
        Action<OpenIddictServerSamlBuilder>? configuration = null,
        Action<OpenIddictServerSamlServiceProvider>? serviceProvider = null,
        Action<OpenIddictServerBuilder>? server = null,
        string secondBinding = Bindings.HttpRedirect,
        bool enable = true)
    {
        var sessions = new List<FakeSession>();
        var soap = new FakeSoapClient();

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
                    .AddServiceProvider(CreateSecondServiceProvider(secondBinding))
                    .SetLoginIdClaimType(LoginIdClaimType);

                if (enable)
                {
                    saml.EnableSingleLogout();
                }

                configuration?.Invoke(saml);
            });

            server?.Invoke(options);
        });

        services.AddSingleton<IOpenIddictServerSamlSoapClient>(soap);

        return (services.BuildServiceProvider(), sessions, soap);
    }
}
