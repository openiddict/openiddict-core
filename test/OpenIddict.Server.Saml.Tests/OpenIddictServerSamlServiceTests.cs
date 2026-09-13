using System.Security.Claims;
using System.Text;
using System.Xml;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using Parameters = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.Parameters;
using static OpenIddict.Server.Saml.OpenIddictServerSamlModels;
using static OpenIddict.Server.Saml.Tests.OpenIddictServerSamlTestHelpers;

namespace OpenIddict.Server.Saml.Tests;

public class OpenIddictServerSamlServiceTests
{
    private static readonly Uri Endpoint = new(SingleSignOnEndpoint, UriKind.Absolute);

    [Fact]
    public async Task ValidateRedirectAuthenticationRequestAsync_AcceptsSignedRequest()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var request = CreateAuthenticationRequest(id: "_abc", assertionConsumerServiceUrl: SecondaryAssertionConsumerServiceUrl.AbsoluteUri);
        var query = CreateRedirectQueryString(request, relayState: "state +/=&", certificate: ServiceProviderCertificate);

        // Act
        var result = await service.ValidateRedirectAuthenticationRequestAsync(query, Endpoint);

        // Assert
        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.Equal("_abc", result.Request!.Id);
        Assert.Equal("_abc", result.RequestId);
        Assert.Equal(Bindings.HttpRedirect, result.Request.Binding);
        Assert.True(result.Request.IsSigned);
        Assert.Equal(ServiceProviderEntityId, result.Request.Issuer);
        Assert.Equal(SecondaryAssertionConsumerServiceUrl, result.AssertionConsumerServiceUrl);
        Assert.Equal("state +/=&", result.RelayState);
    }

    [Fact]
    public async Task ValidateRedirectAuthenticationRequestAsync_UsesFirstRegisteredUrlByDefault()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(), certificate: ServiceProviderCertificate);

        // Act
        var result = await service.ValidateRedirectAuthenticationRequestAsync(query, Endpoint);

        // Assert
        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.Equal(AssertionConsumerServiceUrl, result.AssertionConsumerServiceUrl);
        Assert.Null(result.RelayState);
    }

    [Fact]
    public async Task ValidateRedirectAuthenticationRequestAsync_RejectsUnsignedRequestWhenSignatureIsRequired()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var query = CreateRedirectQueryString(CreateAuthenticationRequest());

        // Act
        var result = await service.ValidateRedirectAuthenticationRequestAsync(query, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.False(result.CanReturnErrorToServiceProvider);
        Assert.Equal(SR.GetResourceString(SR.ID2253), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRedirectAuthenticationRequestAsync_AcceptsUnsignedRequestWhenSignatureIsNotRequired()
    {
        // Arrange
        using var provider = CreateProvider(serviceProvider: sp => sp.RequireSignedAuthenticationRequests = false);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(destination: null), relayState: "xyz");

        // Act
        var result = await service.ValidateRedirectAuthenticationRequestAsync(query, Endpoint);

        // Assert
        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.False(result.Request!.IsSigned);
        Assert.Equal("xyz", result.RelayState);
    }

    [Fact]
    public async Task ValidateRedirectAuthenticationRequestAsync_RejectsTamperedRelayState()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(), relayState: "original", certificate: ServiceProviderCertificate)
            .Replace("RelayState=original", "RelayState=tampered");

        // Act
        var result = await service.ValidateRedirectAuthenticationRequestAsync(query, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2254), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRedirectAuthenticationRequestAsync_RejectsSignatureFromUnknownCertificate()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(), certificate: CreateCertificate("CN=attacker"));

        // Act
        var result = await service.ValidateRedirectAuthenticationRequestAsync(query, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2254), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRedirectAuthenticationRequestAsync_RejectsSha1Signatures()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(),
            certificate: ServiceProviderCertificate, algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1");

        // Act
        var result = await service.ValidateRedirectAuthenticationRequestAsync(query, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2255), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRedirectAuthenticationRequestAsync_RejectsDuplicateParameters()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var query = CreateRedirectQueryString(CreateAuthenticationRequest(), relayState: "original", certificate: ServiceProviderCertificate) + "&RelayState=injected";

        // Act
        var result = await service.ValidateRedirectAuthenticationRequestAsync(query, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2259), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRedirectAuthenticationRequestAsync_RejectsMalformedPayload()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Act
        var result = await service.ValidateRedirectAuthenticationRequestAsync("?SAMLRequest=not-deflated", Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2246), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateRedirectAuthenticationRequestAsync_RejectsOversizedPayload()
    {
        // Arrange
        using var provider = CreateProvider(options => options.MaximumMessageSize = 1024);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Note: highly compressible payloads must be rejected after inflating (decompression bombs).
        var query = CreateRedirectQueryString(CreateAuthenticationRequest(extra: "<!--" + new string('a', 100_000) + "-->"));

        // Act
        var result = await service.ValidateRedirectAuthenticationRequestAsync(query, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2247), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidatePostAuthenticationRequestAsync_AcceptsSignedRequest()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var document = SignDocument(CreateAuthenticationRequest(id: "_post", attributes: "ForceAuthn=\"true\""), ServiceProviderCertificate);

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), "relay", Endpoint);

        // Assert
        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.Equal("_post", result.Request!.Id);
        Assert.Equal(Bindings.HttpPost, result.Request.Binding);
        Assert.True(result.Request.IsSigned);
        Assert.True(result.Request.ForceAuthentication);
        Assert.False(result.Request.IsPassive);
        Assert.Equal("relay", result.RelayState);
    }

    [Fact]
    public async Task ValidatePostAuthenticationRequestAsync_RejectsModifiedSignedContent()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var document = SignDocument(CreateAuthenticationRequest(), ServiceProviderCertificate);
        document.DocumentElement!.SetAttribute("AssertionConsumerServiceURL", SecondaryAssertionConsumerServiceUrl.AbsoluteUri);

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2254), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidatePostAuthenticationRequestAsync_RejectsWrappedSignedRequest()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // The legitimate signed request is moved inside an attacker-controlled request (classic XSW).
        var legitimate = SignDocument(CreateAuthenticationRequest(id: "_legitimate"), ServiceProviderCertificate);

        var document = new XmlDocument { PreserveWhitespace = true };
        document.LoadXml(CreateAuthenticationRequest(id: "_evil", assertionConsumerServiceUrl: "https://attacker.example.com/acs",
            extra: "<samlp:Extensions></samlp:Extensions>"));

        var extensions = document.GetElementsByTagName("Extensions", Namespaces.Protocol)[0]!;
        extensions.AppendChild(document.ImportNode(legitimate.DocumentElement!, deep: true));

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2254), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidatePostAuthenticationRequestAsync_RejectsWrappedRequestWithDuplicateIdentifier()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var legitimate = SignDocument(CreateAuthenticationRequest(id: "_shared"), ServiceProviderCertificate);
        var signature = legitimate.GetElementsByTagName(Elements.Signature, Namespaces.XmlDsig)[0]!;

        // The attacker root reuses the identifier and the signature of the legitimate request,
        // which is hidden in an extension so that the reference resolves to the original content.
        var document = new XmlDocument { PreserveWhitespace = true };
        document.LoadXml(CreateAuthenticationRequest(id: "_shared", assertionConsumerServiceUrl: "https://attacker.example.com/acs",
            extra: "<samlp:Extensions></samlp:Extensions>"));

        var root = document.DocumentElement!;
        root.InsertAfter(document.ImportNode(signature, deep: true), root.GetElementsByTagName(Elements.Issuer, Namespaces.Assertion)[0]!);

        signature.ParentNode!.RemoveChild(signature);
        document.GetElementsByTagName("Extensions", Namespaces.Protocol)[0]!.AppendChild(document.ImportNode(legitimate.DocumentElement!, deep: true));

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2254), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidatePostAuthenticationRequestAsync_RejectsMultipleSignatures()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var document = SignDocument(CreateAuthenticationRequest(extra: "<samlp:Extensions></samlp:Extensions>"), ServiceProviderCertificate);
        var signature = document.GetElementsByTagName(Elements.Signature, Namespaces.XmlDsig)[0]!;
        document.GetElementsByTagName("Extensions", Namespaces.Protocol)[0]!.AppendChild(signature.CloneNode(deep: true));

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2254), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidatePostAuthenticationRequestAsync_RejectsSignatureReferencingAnotherElement()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // The signature covers a signed child element instead of the root element.
        var document = new XmlDocument { PreserveWhitespace = true };
        document.LoadXml(CreateAuthenticationRequest(id: "_root"));

        var signed = SignDocument(CreateAuthenticationRequest(id: "_other"), ServiceProviderCertificate);
        var signature = document.ImportNode(signed.GetElementsByTagName(Elements.Signature, Namespaces.XmlDsig)[0]!, deep: true);

        var root = document.DocumentElement!;
        root.InsertAfter(signature, root.GetElementsByTagName(Elements.Issuer, Namespaces.Assertion)[0]!);

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2254), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidatePostAuthenticationRequestAsync_RejectsDocumentTypeDefinitions()
    {
        // Arrange
        using var provider = CreateProvider(serviceProvider: sp => sp.RequireSignedAuthenticationRequests = false);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var xml = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]>" +
            CreateAuthenticationRequest(issuer: "&xxe;");

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(xml), null, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2248), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidatePostAuthenticationRequestAsync_RejectsUnknownAssertionConsumerService()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var document = SignDocument(CreateAuthenticationRequest(assertionConsumerServiceUrl: "https://sp.example.com/acs/evil"), ServiceProviderCertificate);

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.False(result.CanReturnErrorToServiceProvider);
        Assert.Null(result.AssertionConsumerServiceUrl);
        Assert.Equal(SR.GetResourceString(SR.ID2256), result.ErrorDescription);
    }

    [Theory]
    [InlineData("AssertionConsumerServiceIndex=\"1\"", true)]
    [InlineData("AssertionConsumerServiceIndex=\"2\"", false)]
    [InlineData("AssertionConsumerServiceIndex=\"-1\"", false)]
    public async Task ValidatePostAuthenticationRequestAsync_ResolvesAssertionConsumerServiceIndex(string attribute, bool valid)
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var document = SignDocument(CreateAuthenticationRequest(attributes: attribute), ServiceProviderCertificate);

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        // Assert
        Assert.Equal(valid, result.Succeeded);
        Assert.Equal(valid ? SecondaryAssertionConsumerServiceUrl : null, result.AssertionConsumerServiceUrl);
    }

    [Fact]
    public async Task ValidatePostAuthenticationRequestAsync_RejectsUnknownIssuer()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var document = SignDocument(CreateAuthenticationRequest(issuer: "https://unknown.example.com/"), ServiceProviderCertificate);

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Null(result.ServiceProvider);
        Assert.Equal(SR.GetResourceString(SR.ID2251), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidatePostAuthenticationRequestAsync_RejectsExpiredRequest()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var document = SignDocument(CreateAuthenticationRequest(issueInstant: DateTimeOffset.UtcNow.AddHours(-1)), ServiceProviderCertificate);

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2250), result.ErrorDescription);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("https://other.example.com/saml/sso")]
    public async Task ValidatePostAuthenticationRequestAsync_RejectsInvalidDestination(string? destination)
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var document = SignDocument(CreateAuthenticationRequest(destination: destination), ServiceProviderCertificate);

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2252), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidatePostAuthenticationRequestAsync_ReturnsInvalidNameIdPolicyToServiceProvider()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var xml = CreateAuthenticationRequest(id: "_policy").Replace(
            "<samlp:NameIDPolicy AllowCreate=\"true\" />",
            $"<samlp:NameIDPolicy Format=\"{NameIdFormats.EmailAddress}\" />");

        var document = SignDocument(xml, ServiceProviderCertificate);

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.True(result.CanReturnErrorToServiceProvider);
        Assert.Equal("_policy", result.RequestId);
        Assert.Equal(StatusCodes.Requester, result.Status);
        Assert.Equal(StatusCodes.InvalidNameIdPolicy, result.SecondLevelStatus);
    }

    [Fact]
    public async Task ValidateIdentityProviderInitiatedRequestAsync_RequiresOptIn()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Act
        var result = await service.ValidateIdentityProviderInitiatedRequestAsync(ServiceProviderEntityId, "relay");

        // Assert
        Assert.False(result.Succeeded);
        Assert.False(result.CanReturnErrorToServiceProvider);
        Assert.Equal(SR.GetResourceString(SR.ID2262), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateIdentityProviderInitiatedRequestAsync_AcceptsAllowedServiceProvider()
    {
        // Arrange
        using var provider = CreateProvider(serviceProvider: sp => sp.AllowIdentityProviderInitiatedSingleSignOn = true);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Act
        var result = await service.ValidateIdentityProviderInitiatedRequestAsync(ServiceProviderEntityId, "relay");

        // Assert
        Assert.True(result.Succeeded);
        Assert.Null(result.Request);
        Assert.Null(result.RequestId);
        Assert.Equal(AssertionConsumerServiceUrl, result.AssertionConsumerServiceUrl);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CreateResponse_ReturnsSignedAssertion(bool signResponse)
    {
        // Arrange
        using var provider = CreateProvider(options => options.SignResponses = signResponse);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Act
        var xml = service.CreateResponse(new ResponseDescriptor
        {
            Assertion = new AssertionDescriptor
            {
                Attributes = [new AssertionAttribute { Name = "mail", Values = ["alice@example.com"] }],
                NameId = "alice",
                SessionIndex = "session"
            },
            AssertionConsumerServiceUrl = AssertionConsumerServiceUrl,
            InResponseTo = "_request",
            ServiceProvider = CreateServiceProvider()
        });

        // Assert
        var document = LoadResponse(xml);
        var manager = CreateNamespaceManager(document);

        var response = document.DocumentElement!;
        Assert.Equal("Response", response.LocalName);
        Assert.Equal("_request", response.GetAttribute("InResponseTo"));
        Assert.Equal(AssertionConsumerServiceUrl.AbsoluteUri, response.GetAttribute("Destination"));
        Assert.Equal(StatusCodes.Success, response.SelectSingleNode("samlp:Status/samlp:StatusCode/@Value", manager)!.Value);
        Assert.Equal(signResponse, VerifySignature(response, IdentityProviderCertificate));

        var assertions = response.SelectNodes("saml:Assertion", manager)!;
        Assert.Equal(1, assertions.Count);

        var assertion = (XmlElement) assertions[0]!;
        Assert.True(VerifySignature(assertion, IdentityProviderCertificate));
        Assert.False(VerifySignature(assertion, ServiceProviderCertificate));

        Assert.Equal(IdentityProviderEntityId, assertion.SelectSingleNode("saml:Issuer", manager)!.InnerText);
        Assert.Equal("alice", assertion.SelectSingleNode("saml:Subject/saml:NameID", manager)!.InnerText);
        Assert.Equal(ConfirmationMethods.Bearer, assertion.SelectSingleNode("saml:Subject/saml:SubjectConfirmation/@Method", manager)!.Value);

        var data = (XmlElement) assertion.SelectSingleNode("saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", manager)!;
        Assert.Equal("_request", data.GetAttribute("InResponseTo"));
        Assert.Equal(AssertionConsumerServiceUrl.AbsoluteUri, data.GetAttribute("Recipient"));

        var conditions = (XmlElement) assertion.SelectSingleNode("saml:Conditions", manager)!;
        var notBefore = XmlConvert.ToDateTimeOffset(conditions.GetAttribute("NotBefore"));
        var notOnOrAfter = XmlConvert.ToDateTimeOffset(conditions.GetAttribute("NotOnOrAfter"));
        Assert.Equal(TimeSpan.FromMinutes(5), notOnOrAfter - notBefore);
        Assert.Equal(conditions.GetAttribute("NotOnOrAfter"), data.GetAttribute("NotOnOrAfter"));
        Assert.Equal(ServiceProviderEntityId, conditions.SelectSingleNode("saml:AudienceRestriction/saml:Audience", manager)!.InnerText);

        Assert.Equal("session", assertion.SelectSingleNode("saml:AuthnStatement/@SessionIndex", manager)!.Value);
        Assert.Equal("alice@example.com", assertion.SelectSingleNode(
            "saml:AttributeStatement/saml:Attribute[@Name='mail']/saml:AttributeValue", manager)!.InnerText);
    }

    [Fact]
    public void CreateResponse_TamperedAssertionFailsSignatureValidation()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var xml = service.CreateResponse(new ResponseDescriptor
        {
            Assertion = new AssertionDescriptor { NameId = "alice" },
            AssertionConsumerServiceUrl = AssertionConsumerServiceUrl,
            ServiceProvider = CreateServiceProvider()
        });

        // Act
        var document = LoadResponse(xml.Replace(">alice<", ">admin<"));
        var assertion = (XmlElement) document.GetElementsByTagName(Elements.Assertion, Namespaces.Assertion)[0]!;

        // Assert
        Assert.False(VerifySignature(assertion, IdentityProviderCertificate));
    }

    [Fact]
    public void CreateResponse_ReturnsSignedErrorResponse()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Act
        var xml = service.CreateResponse(new ResponseDescriptor
        {
            AssertionConsumerServiceUrl = AssertionConsumerServiceUrl,
            InResponseTo = "_request",
            SecondLevelStatus = StatusCodes.NoPassive,
            ServiceProvider = CreateServiceProvider(),
            Status = StatusCodes.Responder,
            StatusMessage = "passive"
        });

        // Assert
        var document = LoadResponse(xml);
        var manager = CreateNamespaceManager(document);

        Assert.True(VerifySignature(document.DocumentElement!, IdentityProviderCertificate));
        Assert.Null(document.DocumentElement!.SelectSingleNode("saml:Assertion", manager));
        Assert.Equal(StatusCodes.Responder, document.DocumentElement.SelectSingleNode("samlp:Status/samlp:StatusCode/@Value", manager)!.Value);
        Assert.Equal(StatusCodes.NoPassive, document.DocumentElement.SelectSingleNode("samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value", manager)!.Value);
    }

    [Fact]
    public void CreateMetadata_ReturnsEntityDescriptor()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Act
        var document = LoadResponse(service.CreateMetadata(Endpoint));

        // Assert
        var manager = CreateNamespaceManager(document);
        var root = document.DocumentElement!;

        Assert.Equal(Elements.EntityDescriptor, root.LocalName);
        Assert.Equal(Namespaces.Metadata, root.NamespaceURI);
        Assert.Equal(IdentityProviderEntityId, root.GetAttribute("entityID"));

        var descriptor = (XmlElement) root.SelectSingleNode("md:IDPSSODescriptor", manager)!;
        Assert.Equal("true", descriptor.GetAttribute("WantAuthnRequestsSigned"));
        Assert.Equal(Namespaces.Protocol, descriptor.GetAttribute("protocolSupportEnumeration"));

        Assert.Equal(Convert.ToBase64String(IdentityProviderCertificate.RawData), descriptor.SelectSingleNode(
            "md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate", manager)!.InnerText);

        var services = descriptor.SelectNodes("md:SingleSignOnService", manager)!;
        Assert.Equal(2, services.Count);
        Assert.Equal(Bindings.HttpRedirect, ((XmlElement) services[0]!).GetAttribute("Binding"));
        Assert.Equal(Bindings.HttpPost, ((XmlElement) services[1]!).GetAttribute("Binding"));
        Assert.Equal(SingleSignOnEndpoint, ((XmlElement) services[0]!).GetAttribute("Location"));
        Assert.Null(descriptor.SelectSingleNode("md:SingleLogoutService", manager));
    }

    [Fact]
    public async Task AssertionProvider_MapsNameIdAndAttributes()
    {
        // Arrange
        using var provider = CreateProvider();
        var assertions = provider.GetRequiredService<IOpenIddictServerSamlAssertionProvider>();

        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(Claims.Subject, "alice"), new Claim(Claims.Email, "alice@example.com"), new Claim("role", "admin")], "test"));

        // Act
        var assertion = await assertions.CreateAssertionAsync(new AssertionContext
        {
            Principal = principal,
            ServiceProvider = CreateServiceProvider()
        });

        // Assert
        Assert.NotNull(assertion);
        Assert.Equal("alice", assertion.NameId);
        var attribute = Assert.Single(assertion.Attributes);
        Assert.Equal("mail", attribute.Name);
        Assert.Equal(["alice@example.com"], attribute.Values);
    }

    [Fact]
    public async Task AssertionProvider_ReturnsNullWhenNameIdCannotBeResolved()
    {
        // Arrange
        using var provider = CreateProvider();
        var assertions = provider.GetRequiredService<IOpenIddictServerSamlAssertionProvider>();

        var sp = CreateServiceProvider();
        sp.NameIdFormat = NameIdFormats.EmailAddress;

        // Act
        var assertion = await assertions.CreateAssertionAsync(new AssertionContext
        {
            Principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(Claims.Subject, "alice")], "test")),
            ServiceProvider = sp
        });

        // Assert
        Assert.Null(assertion);
    }

    [Fact]
    public void Options_RejectServiceProviderRequiringSignaturesWithoutCertificate()
    {
        // Arrange
        using var provider = CreateProvider(serviceProvider: sp => sp.SigningCertificates.Clear());

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<OpenIddictServerSamlOptions>>().Value);
        Assert.Contains(SR.FormatID0569(ServiceProviderEntityId), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Options_RejectDuplicateServiceProviders()
    {
        // Arrange
        using var provider = CreateProvider(options => options.ServiceProviders.Add(CreateServiceProvider()));

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<OpenIddictServerSamlOptions>>().Value);
        Assert.Contains(SR.FormatID0570(ServiceProviderEntityId), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Options_RequireX509SigningCertificate()
    {
        // Arrange
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddServer(options =>
            {
                ConfigureServer(options).AddEphemeralSigningKey();
                options.UseSaml().SetEntityId(IdentityProviderEntityId);
            });

        using var provider = services.BuildServiceProvider();

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<OpenIddictServerSamlOptions>>().Value);
        Assert.Contains(SR.GetResourceString(SR.ID0566), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Options_UseServerIssuerAndSigningCertificatesByDefault()
    {
        // Arrange
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddServer(options =>
            {
                ConfigureServer(options)
                    .AddSigningCertificate(IdentityProviderCertificate)
                    .SetIssuer(new Uri(IdentityProviderEntityId, UriKind.Absolute));

                options.UseSaml();
            });

        using var provider = services.BuildServiceProvider();

        // Act
        var options = provider.GetRequiredService<IOptions<OpenIddictServerSamlOptions>>().Value;

        // Assert
        Assert.Equal(IdentityProviderEntityId, options.EntityId);
        Assert.Equal(IdentityProviderCertificate, Assert.Single(options.SigningCertificates));
    }

    private static OpenIddictServerBuilder ConfigureServer(OpenIddictServerBuilder options)
        => options.AllowClientCredentialsFlow()
                  .SetTokenEndpointUris("connect/token")
                  .AddEphemeralEncryptionKey()
                  .EnableDegradedMode()
                  .AddEventHandler<OpenIddictServerEvents.ValidateTokenRequestContext>(
                      handler => handler.UseInlineHandler(static context => default));

    private static ServiceProvider CreateProvider(
        Action<OpenIddictServerSamlOptions>? configuration = null,
        Action<OpenIddictServerSamlServiceProvider>? serviceProvider = null)
    {
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.UseSaml(saml =>
                {
                    var sp = CreateServiceProvider();
                    serviceProvider?.Invoke(sp);

                    saml.SetEntityId(IdentityProviderEntityId)
                        .AddSigningCertificate(IdentityProviderCertificate)
                        .AddServiceProvider(sp);

                    if (configuration is not null)
                    {
                        saml.Configure(configuration);
                    }
                });
            });

        return services.BuildServiceProvider();
    }
}
