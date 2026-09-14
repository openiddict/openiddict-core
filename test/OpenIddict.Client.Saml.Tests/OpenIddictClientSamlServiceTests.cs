/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.IO.Compression;
using System.Security.Claims;
using System.Text;
using System.Xml;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Server.Saml;
using Xunit;
using static OpenIddict.Client.Saml.OpenIddictClientSamlConstants;
using static OpenIddict.Client.Saml.OpenIddictClientSamlModels;
using static OpenIddict.Client.Saml.Tests.OpenIddictClientSamlTestHelpers;
using Claims = OpenIddict.Abstractions.OpenIddictConstants.Claims;
using Parameters = OpenIddict.Client.Saml.OpenIddictClientSamlConstants.Parameters;
using ServerModels = OpenIddict.Server.Saml.OpenIddictServerSamlModels;

namespace OpenIddict.Client.Saml.Tests;

public class OpenIddictClientSamlServiceTests
{
    [Fact]
    public async Task CreateAuthenticationRequestAsync_RedirectBinding_IsAcceptedByIdentityProvider()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();
        var registration = await service.GetRegistrationByProviderNameAsync(ProviderName);

        // Act
        var request = await service.CreateAuthenticationRequestAsync(registration, AssertionConsumerServiceUrl, "relay");

        // Assert
        Assert.Equal(Bindings.HttpRedirect, request.Binding);
        Assert.True(request.IsSigned);
        Assert.StartsWith(SingleSignOnServiceUrl.AbsoluteUri + "?SAMLRequest=", request.RedirectUrl!.AbsoluteUri, StringComparison.Ordinal);
        Assert.Contains("SigAlg=", request.RedirectUrl.Query, StringComparison.Ordinal);

        var result = await idp.GetRequiredService<OpenIddictServerSamlService>()
            .ValidateRedirectAuthenticationRequestAsync(request.RedirectUrl.Query, SingleSignOnServiceUrl);

        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.Equal(request.RequestId, result.RequestId);
        Assert.True(result.Request!.IsSigned);
        Assert.Equal(ServiceProviderEntityId, result.Request.Issuer);
        Assert.Equal(AssertionConsumerServiceUrl, result.AssertionConsumerServiceUrl);
        Assert.Equal("relay", result.RelayState);
    }

    [Fact]
    public async Task CreateAuthenticationRequestAsync_PostBinding_IsAcceptedByIdentityProvider()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.AuthenticationRequestBinding = Bindings.HttpPost;
        registration.ForceAuthentication = true;

        using var sp = CreateServiceProvider(registration: registration);
        using var idp = CreateIdentityProvider();
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act
        var request = await service.CreateAuthenticationRequestAsync(registration, AssertionConsumerServiceUrl, "relay");

        // Assert
        Assert.Null(request.RedirectUrl);
        Assert.True(request.IsSigned);
        Assert.True(request.ForceAuthentication);
        Assert.Equal("relay", request.FormParameters[Parameters.RelayState]);

        var result = await idp.GetRequiredService<OpenIddictServerSamlService>().ValidatePostAuthenticationRequestAsync(
            request.FormParameters[Parameters.SamlRequest], "relay", SingleSignOnServiceUrl);

        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.True(result.Request!.IsSigned);
        Assert.True(result.Request.ForceAuthentication);

        var page = OpenIddictClientSamlService.CreateFormPostPage(request, "nonce");
        Assert.Contains("action=\"" + SingleSignOnServiceUrl.AbsoluteUri + "\"", page, StringComparison.Ordinal);
        Assert.Contains("nonce=\"nonce\"", page, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateAuthenticationRequestAsync_UnsignedRequestWhenSigningIsDisabled()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.SignAuthenticationRequests = false;
        registration.NameIdFormat = NameIdFormats.Persistent;
        registration.AuthenticationContextClasses.Add("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

        using var sp = CreateServiceProvider(saml => saml.Configure(options => options.SigningCertificates.Clear()), registration);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act
        var request = await service.CreateAuthenticationRequestAsync(registration, AssertionConsumerServiceUrl, relayState: null);

        // Assert
        Assert.False(request.IsSigned);
        Assert.DoesNotContain("Signature=", request.RedirectUrl!.Query, StringComparison.Ordinal);

        var document = Load(request.Xml);
        var manager = CreateNamespaceManager(document);
        Assert.Equal(NameIdFormats.Persistent, document.SelectSingleNode("/samlp:AuthnRequest/samlp:NameIDPolicy/@Format", manager)!.Value);
        Assert.NotNull(document.SelectSingleNode("/samlp:AuthnRequest/samlp:RequestedAuthnContext/saml:AuthnContextClassRef", manager));
        Assert.Equal(Bindings.HttpPost, document.DocumentElement!.GetAttribute("ProtocolBinding"));

        // The deflated request can be decoded from the redirect URL.
        var value = Uri.UnescapeDataString(request.RedirectUrl.Query.Substring("?SAMLRequest=".Length));
        using var input = new MemoryStream(Convert.FromBase64String(value));
        using var stream = new DeflateStream(input, CompressionMode.Decompress);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        Assert.Equal(request.Xml, await reader.ReadToEndAsync());
    }

    [Fact]
    public async Task CreateAuthenticationRequestAsync_RejectsLongRelayState()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();
        var registration = await service.GetRegistrationByProviderNameAsync(ProviderName);

        // Act and assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.CreateAuthenticationRequestAsync(registration, AssertionConsumerServiceUrl, new string('a', 81)));

        Assert.StartsWith(SR.GetResourceString(SR.ID0908), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ValidateResponseAsync_AcceptsResponseIssuedByIdentityProvider()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, registration, request, state) = await StartAsync(sp);

        var response = CreateResponse(idp, request.RequestId);

        // Act
        var result = await service.ValidateResponseAsync(Encode(response), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.Equal(StatusCodes.Success, result.Status);
        Assert.Same(registration, result.Registration);
        Assert.Equal("alice", result.Assertion!.NameId);
        Assert.Equal(IdentityProviderEntityId, result.Assertion.Issuer);
        Assert.Equal("session-1", result.Assertion.SessionIndex);
        Assert.True(result.Assertion.IsSigned);
        Assert.False(result.Assertion.IsEncrypted);

        var principal = result.Principal!;
        Assert.Equal(AuthenticationType, principal.Identity!.AuthenticationType);
        Assert.Equal("alice", principal.FindFirst(Claims.Subject)!.Value);
        Assert.Equal("alice", principal.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        Assert.Equal("alice@example.com", principal.FindFirst(Claims.Email)!.Value);
        Assert.True(principal.FindAll("role").Select(static claim => claim.Value).SequenceEqual(["admin", "user"], StringComparer.Ordinal));
        Assert.Equal(registration.RegistrationId, principal.FindFirst(Claims.Private.RegistrationId)!.Value);
        Assert.Equal(ProviderName, principal.FindFirst(Claims.Private.ProviderName)!.Value);
        Assert.Equal("session-1", principal.FindFirst(OpenIddictClientSamlConstants.Claims.SessionIndex)!.Value);
        Assert.All(principal.Claims, static claim => Assert.Equal(IdentityProviderEntityId, claim.Issuer));
    }

    [Fact]
    public async Task ValidateResponseAsync_AcceptsSignedResponse()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider(options => options.SignResponses = true);
        var (service, _, request, state) = await StartAsync(sp);

        // Act
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, request.RequestId)), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.True(result.Succeeded, result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_AcceptsUnsignedAssertionInSignedResponse()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var document = Load(CreateResponse(idp, request.RequestId));
        var manager = CreateNamespaceManager(document);
        var signature = document.SelectSingleNode("/samlp:Response/saml:Assertion/ds:Signature", manager)!;
        signature.ParentNode!.RemoveChild(signature);

        var response = SignRoot(document.OuterXml, IdentityProviderCertificate);

        // Act
        var result = await service.ValidateResponseAsync(Encode(response), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.False(result.Assertion!.IsSigned);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsUnsignedAssertionInSignedResponseWhenSignedAssertionsAreRequired()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.RequireSignedAssertions = true;

        using var sp = CreateServiceProvider(registration: registration);
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var document = Load(CreateResponse(idp, request.RequestId));
        var signature = document.SelectSingleNode("/samlp:Response/saml:Assertion/ds:Signature", CreateNamespaceManager(document))!;
        signature.ParentNode!.RemoveChild(signature);

        // Act
        var result = await service.ValidateResponseAsync(Encode(SignRoot(document.OuterXml, IdentityProviderCertificate)),
            "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2452), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsUnsignedResponse()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var document = Load(CreateResponse(idp, request.RequestId));
        var signature = document.SelectSingleNode("/samlp:Response/saml:Assertion/ds:Signature", CreateNamespaceManager(document))!;
        signature.ParentNode!.RemoveChild(signature);

        // Act
        var result = await service.ValidateResponseAsync(Encode(document.OuterXml), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2452), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsTamperedAssertion()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var response = CreateResponse(idp, request.RequestId).Replace(">alice<", ">mallory<");

        // Act
        var result = await service.ValidateResponseAsync(Encode(response), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2445), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsAssertionSignedByUnrelatedCertificate()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider(options =>
        {
            options.SigningCertificates.Clear();
            options.SigningCertificates.Add(UnrelatedCertificate);
        });

        var (service, _, request, state) = await StartAsync(sp);

        // Act
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, request.RequestId)), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2445), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsSignatureWrappingWithAdditionalAssertion()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var document = Load(CreateResponse(idp, request.RequestId));
        var manager = CreateNamespaceManager(document);
        var assertion = (XmlElement) document.SelectSingleNode("/samlp:Response/saml:Assertion", manager)!;

        // Insert an unsigned forged assertion before the legitimate signed assertion.
        var forged = (XmlElement) assertion.CloneNode(deep: true);
        forged.SetAttribute("ID", "_forged");
        forged.RemoveChild(forged.SelectSingleNode("ds:Signature", manager)!);
        forged.SelectSingleNode("saml:Subject/saml:NameID", manager)!.InnerText = "mallory";
        assertion.ParentNode!.InsertBefore(forged, assertion);

        // Act
        var result = await service.ValidateResponseAsync(Encode(document.OuterXml), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2450), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsSignatureWrappingWithSignedAssertionMovedToExtensions()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var document = Load(CreateResponse(idp, request.RequestId));
        var manager = CreateNamespaceManager(document);
        var assertion = (XmlElement) document.SelectSingleNode("/samlp:Response/saml:Assertion", manager)!;

        // Move the signed assertion to an extensions element and replace it by a forged assertion
        // referencing the identifier of the signed assertion in its signature.
        var forged = (XmlElement) assertion.CloneNode(deep: true);
        forged.SetAttribute("ID", "_forged");
        forged.SelectSingleNode("saml:Subject/saml:NameID", manager)!.InnerText = "mallory";

        var extensions = document.CreateElement("samlp", "Extensions", ProtocolNamespace);
        assertion.ParentNode!.ReplaceChild(forged, assertion);
        extensions.AppendChild(assertion);
        document.DocumentElement!.InsertAfter(extensions, document.DocumentElement.FirstChild);

        // Act
        var result = await service.ValidateResponseAsync(Encode(document.OuterXml), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2445), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsDocumentTypeDefinition()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var response = "<!DOCTYPE r [<!ENTITY x \"x\">]>" + CreateResponse(idp, request.RequestId);

        // Act
        var result = await service.ValidateResponseAsync(Encode(response), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2442), result.ErrorDescription);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("%%%")]
    public async Task ValidateResponseAsync_RejectsMissingOrMalformedResponse(string? response)
    {
        // Arrange
        using var sp = CreateServiceProvider();
        var (service, _, _, state) = await StartAsync(sp);

        // Act
        var result = await service.ValidateResponseAsync(response, "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(string.IsNullOrEmpty(response) ? SR.ID2440 : SR.ID2441), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsInResponseToMismatch()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, _, state) = await StartAsync(sp);

        // Act
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, "_other")), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2447), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsSolicitedResponseWithoutState()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, _) = await StartAsync(sp);

        // Act
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, request.RequestId)), "relay", null, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2447), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsRelayStateMismatch()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        // Act
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, request.RequestId)), "other", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2447), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsExpiredState()
    {
        // Arrange
        var time = new TestTimeProvider();
        using var sp = CreateServiceProvider(saml => saml.Configure(options => options.TimeProvider = time));
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        time.UtcNow += TimeSpan.FromHours(1);

        // Act
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, request.RequestId)), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2447), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsExpiredAssertion()
    {
        // Arrange
        var time = new TestTimeProvider();
        using var sp = CreateServiceProvider(saml => saml.Configure(options => options.TimeProvider = time));
        using var idp = CreateIdentityProvider(options =>
        {
            options.TimeProvider = new TestTimeProvider { UtcNow = time.UtcNow - TimeSpan.FromMinutes(10) };
        });

        var (service, _, request, state) = await StartAsync(sp);

        // Act
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, request.RequestId)), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2453), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_AcceptsAssertionWithinClockSkew()
    {
        // Arrange
        var time = new TestTimeProvider();
        using var sp = CreateServiceProvider(saml => saml.Configure(options => options.TimeProvider = time));

        // Note: the identity provider clock is 1 minute ahead (NotBefore is in the future for the service provider).
        using var idp = CreateIdentityProvider(options => options.TimeProvider = new TestTimeProvider { UtcNow = time.UtcNow + TimeSpan.FromMinutes(1) });

        var (service, _, request, state) = await StartAsync(sp);

        // Act
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, request.RequestId)), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.True(result.Succeeded, result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsAssertionNotYetValid()
    {
        // Arrange
        var time = new TestTimeProvider();
        using var sp = CreateServiceProvider(saml => saml.Configure(options => options.TimeProvider = time));
        using var idp = CreateIdentityProvider(options => options.TimeProvider = new TestTimeProvider { UtcNow = time.UtcNow + TimeSpan.FromMinutes(3) });

        var (service, _, request, state) = await StartAsync(sp);

        // Act
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, request.RequestId)), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2454), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsWrongAudience()
    {
        // Arrange
        using var sp = CreateServiceProvider(saml => saml.SetEntityId("https://other.example.com/"));
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        // Act
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, request.RequestId)), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2454), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsWrongDestination()
    {
        // Arrange
        var other = new Uri("https://sp.example.com/other", UriKind.Absolute);

        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider(options => options.SignResponses = true, assertionConsumerServiceUrl: other);
        var (service, _, request, state) = await StartAsync(sp);

        // Act
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, request.RequestId, other)), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2446), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsWrongRecipient()
    {
        // Arrange
        var other = new Uri("https://sp.example.com/other", UriKind.Absolute);

        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider(assertionConsumerServiceUrl: other);
        var (service, _, request, state) = await StartAsync(sp);

        // Note: the Destination attribute of the (unsigned) response is removed so that only the recipient is checked.
        var document = Load(CreateResponse(idp, request.RequestId, other));
        document.DocumentElement!.RemoveAttribute("Destination");

        // Act
        var result = await service.ValidateResponseAsync(Encode(document.OuterXml), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2453), result.ErrorDescription);
    }
    [Fact]
    public async Task ValidateResponseAsync_RejectsReplayedAssertion()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var response = Encode(CreateResponse(idp, request.RequestId));

        // Act
        var first = await service.ValidateResponseAsync(response, "relay", state, AssertionConsumerServiceUrl);
        var second = await service.ValidateResponseAsync(response, "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.True(first.Succeeded, first.ErrorDescription);
        Assert.False(second.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2456), second.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_ReturnsIdentityProviderErrorStatus()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var provider = idp.GetRequiredService<IOptionsMonitor<OpenIddictServerSamlOptions>>().CurrentValue.ServiceProviders[0];
        var response = idp.GetRequiredService<OpenIddictServerSamlService>().CreateResponse(new ServerModels.ResponseDescriptor
        {
            AssertionConsumerServiceUrl = AssertionConsumerServiceUrl,
            InResponseTo = request.RequestId,
            SecondLevelStatus = StatusCodes.RequestDenied,
            ServiceProvider = provider,
            Status = StatusCodes.Responder,
            StatusMessage = "denied"
        });

        // Act
        var result = await service.ValidateResponseAsync(Encode(response), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(StatusCodes.Responder, result.Status);
        Assert.Equal(StatusCodes.RequestDenied, result.SecondLevelStatus);
        Assert.Equal("denied", result.StatusMessage);
        Assert.Null(result.Principal);

        // The values controlled by the sender of the response are never included in the error description.
        Assert.Equal(SR.GetResourceString(SR.ID2449), result.ErrorDescription);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ValidateResponseAsync_DecryptsEncryptedAssertion(bool keyInsideEncryptedData)
    {
        // Arrange
        var registration = CreateRegistration();
        registration.RequireEncryptedAssertions = true;

        using var sp = CreateServiceProvider(registration: registration);
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var response = EncryptAssertion(CreateResponse(idp, request.RequestId), GetPublicCertificate(EncryptionCertificate), keyInsideEncryptedData);

        // Act
        var result = await service.ValidateResponseAsync(Encode(response), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.True(result.Assertion!.IsEncrypted);
        Assert.True(result.Assertion.IsSigned);
        Assert.Equal("alice", result.Assertion.NameId);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsAssertionEncryptedForUnknownCertificate()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var response = EncryptAssertion(CreateResponse(idp, request.RequestId), GetPublicCertificate(UnrelatedCertificate));

        // Act
        var result = await service.ValidateResponseAsync(Encode(response), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2451), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsPlainAssertionWhenEncryptionIsRequired()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.RequireEncryptedAssertions = true;

        using var sp = CreateServiceProvider(registration: registration);
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        // Act
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, request.RequestId)), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2457), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsUnsolicitedResponseByDefault()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, inResponseTo: null)), null, null, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2448), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_AcceptsUnsolicitedResponseWhenAllowed()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.AllowUnsolicitedResponses = true;

        using var sp = CreateServiceProvider(registration: registration);
        using var idp = CreateIdentityProvider();
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, inResponseTo: null)), "/home", null, AssertionConsumerServiceUrl);

        // Assert
        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.Null(result.State);
        Assert.Equal("/home", result.RelayState);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsForcedAuthenticationWithOldAuthenticationInstant()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.ForceAuthentication = true;

        using var sp = CreateServiceProvider(registration: registration);
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var provider = idp.GetRequiredService<IOptionsMonitor<OpenIddictServerSamlOptions>>().CurrentValue.ServiceProviders[0];
        var response = idp.GetRequiredService<OpenIddictServerSamlService>().CreateResponse(new ServerModels.ResponseDescriptor
        {
            Assertion = new ServerModels.AssertionDescriptor
            {
                AuthenticationInstant = DateTimeOffset.UtcNow - TimeSpan.FromHours(1),
                NameId = "alice"
            },
            AssertionConsumerServiceUrl = AssertionConsumerServiceUrl,
            InResponseTo = request.RequestId,
            ServiceProvider = provider
        });

        // Act
        var result = await service.ValidateResponseAsync(Encode(response), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2459), result.ErrorDescription);
    }

    [Fact]
    public async Task RequestState_RoundTrips()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        var (service, _, request, state) = await StartAsync(sp);
        state = state with { Properties = ImmutableDictionary.CreateRange(StringComparer.Ordinal, [new KeyValuePair<string, string?>(".redirect", "/home"), new KeyValuePair<string, string?>("null", null)]) };

        // Act
        var result = OpenIddictClientSamlService.DeserializeRequestState(OpenIddictClientSamlService.SerializeRequestState(state));

        // Assert
        Assert.NotNull(result);
        Assert.Equal(state.RequestId, result.RequestId);
        Assert.Equal(state.RegistrationId, result.RegistrationId);
        Assert.Equal(state.RelayState, result.RelayState);
        Assert.Equal(state.AssertionConsumerServiceUrl, result.AssertionConsumerServiceUrl);
        Assert.Equal(state.ExpirationDate, result.ExpirationDate);
        Assert.Equal("/home", result.Properties[".redirect"]);
        Assert.Null(result.Properties["null"]);
        Assert.Null(OpenIddictClientSamlService.DeserializeRequestState([1, 2, 3]));
    }

    [Fact]
    public async Task GetIdentityProviderConfigurationAsync_ImportsMetadata()
    {
        // Arrange
        using var idp = CreateIdentityProvider();
        var metadata = idp.GetRequiredService<OpenIddictServerSamlService>().CreateMetadata(SingleSignOnServiceUrl);
        var retriever = new TestMetadataRetriever(metadata);

        var registration = new OpenIddictClientSamlRegistration
        {
            MetadataAddress = new Uri("https://idp.example.com/saml/metadata", UriKind.Absolute),
            ProviderName = ProviderName
        };

        using var sp = CreateServiceProvider(saml => saml.Services.AddSingleton<IOpenIddictClientSamlMetadataRetriever>(retriever), registration);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act
        var configuration = await service.GetIdentityProviderConfigurationAsync(registration);
        await service.GetIdentityProviderConfigurationAsync(registration);

        // Assert
        Assert.Equal(IdentityProviderEntityId, configuration.EntityId);
        Assert.Equal(SingleSignOnServiceUrl, configuration.SingleSignOnServices[Bindings.HttpRedirect]);
        Assert.Equal(SingleSignOnServiceUrl, configuration.SingleSignOnServices[Bindings.HttpPost]);
        Assert.True(configuration.WantAuthenticationRequestsSigned);
        Assert.Equal(IdentityProviderCertificate.RawData, Assert.Single(configuration.SigningCertificates).RawData);
        Assert.Equal(1, retriever.Count);

        // The imported configuration is used to validate the responses.
        var request = await service.CreateAuthenticationRequestAsync(registration, AssertionConsumerServiceUrl, "relay");
        var state = service.CreateRequestState(registration, request, AssertionConsumerServiceUrl);
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, request.RequestId)), "relay", state, AssertionConsumerServiceUrl);
        Assert.True(result.Succeeded, result.ErrorDescription);
    }

    [Fact]
    public async Task GetIdentityProviderConfigurationAsync_RejectsUnsignedMetadataWhenSigningCertificatesAreConfigured()
    {
        // Arrange
        using var idp = CreateIdentityProvider();
        var metadata = idp.GetRequiredService<OpenIddictServerSamlService>().CreateMetadata(SingleSignOnServiceUrl);

        var registration = new OpenIddictClientSamlRegistration
        {
            MetadataAddress = new Uri("https://idp.example.com/saml/metadata", UriKind.Absolute),
            MetadataSigningCertificates = { GetPublicCertificate(IdentityProviderCertificate) },
            ProviderName = ProviderName
        };

        using var sp = CreateServiceProvider(saml => saml.Services.AddSingleton<IOpenIddictClientSamlMetadataRetriever>(
            new TestMetadataRetriever(metadata)), registration);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () => await service.GetIdentityProviderConfigurationAsync(registration));
        Assert.Contains(SR.GetResourceString(SR.ID0904), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetIdentityProviderConfigurationAsync_AcceptsSignedMetadata()
    {
        // Arrange
        using var idp = CreateIdentityProvider();
        var metadata = Load(idp.GetRequiredService<OpenIddictServerSamlService>().CreateMetadata(SingleSignOnServiceUrl));
        metadata.DocumentElement!.SetAttribute("ID", "_metadata");

        var registration = new OpenIddictClientSamlRegistration
        {
            IdentityProviderEntityId = IdentityProviderEntityId,
            MetadataAddress = new Uri("https://idp.example.com/saml/metadata", UriKind.Absolute),
            MetadataSigningCertificates = { GetPublicCertificate(IdentityProviderCertificate) },
            ProviderName = ProviderName
        };

        using var sp = CreateServiceProvider(saml => saml.Services.AddSingleton<IOpenIddictClientSamlMetadataRetriever>(
            new TestMetadataRetriever(SignRoot(metadata.OuterXml, IdentityProviderCertificate))), registration);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act
        var configuration = await service.GetIdentityProviderConfigurationAsync(registration);

        // Assert
        Assert.Equal(IdentityProviderEntityId, configuration.EntityId);
    }

    [Fact]
    public async Task GetIdentityProviderConfigurationAsync_RejectsMetadataForAnotherEntity()
    {
        // Arrange
        using var idp = CreateIdentityProvider();
        var metadata = idp.GetRequiredService<OpenIddictServerSamlService>().CreateMetadata(SingleSignOnServiceUrl);

        var registration = new OpenIddictClientSamlRegistration
        {
            IdentityProviderEntityId = "https://other.example.com/",
            MetadataAddress = new Uri("https://idp.example.com/saml/metadata", UriKind.Absolute)
        };

        using var sp = CreateServiceProvider(saml => saml.Services.AddSingleton<IOpenIddictClientSamlMetadataRetriever>(
            new TestMetadataRetriever(metadata)), registration);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act and assert
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await service.GetIdentityProviderConfigurationAsync(registration));
    }

    [Fact]
    public async Task GetIdentityProviderConfigurationAsync_ImportsMetadataFromFile()
    {
        // Arrange
        using var idp = CreateIdentityProvider();
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".xml");
        File.WriteAllText(path, idp.GetRequiredService<OpenIddictServerSamlService>().CreateMetadata(SingleSignOnServiceUrl));

        try
        {
            var registration = new OpenIddictClientSamlRegistration { MetadataAddress = new Uri(path, UriKind.Absolute) };

            using var sp = CreateServiceProvider(registration: registration);
            var service = sp.GetRequiredService<OpenIddictClientSamlService>();

            // Act
            var configuration = await service.GetIdentityProviderConfigurationAsync(registration);

            // Assert
            Assert.Equal(IdentityProviderEntityId, configuration.EntityId);
            Assert.NotEmpty(configuration.SigningCertificates);
        }

        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task GetRegistrationByIdAsync_ResolvesAndCachesDynamicRegistrations()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.RegistrationId = "dynamic";

        var source = new TestRegistrationProvider(registration);

        using var sp = CreateServiceProvider(saml => saml.AddRegistrationProvider(source), addRegistration: false);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act
        var first = await service.GetRegistrationByIdAsync("dynamic");
        var second = await service.GetRegistrationByIdAsync("dynamic");
        var byName = await service.GetRegistrationByProviderNameAsync(ProviderName);

        // Assert
        Assert.Same(registration, first);
        Assert.Same(registration, second);
        Assert.Same(registration, byName);
        Assert.Equal(1, source.FindByIdCount);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await service.GetRegistrationByIdAsync("unknown"));
    }

    [Fact]
    public async Task GetRegistrationByIdAsync_DoesNotCacheWhenCachingIsDisabled()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.RegistrationId = "dynamic";

        var source = new TestRegistrationProvider(registration);

        using var sp = CreateServiceProvider(saml => saml.AddRegistrationProvider(source).SetDynamicRegistrationCacheLifetime(null), addRegistration: false);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act
        await service.GetRegistrationByIdAsync("dynamic");
        await service.GetRegistrationByIdAsync("dynamic");

        // Assert
        Assert.Equal(2, source.FindByIdCount);
    }

    [Fact]
    public async Task GetRegistrationByIdAsync_RejectsInvalidDynamicRegistration()
    {
        // Arrange
        var source = new TestRegistrationProvider(new OpenIddictClientSamlRegistration
        {
            IdentityProviderEntityId = IdentityProviderEntityId,
            RegistrationId = "dynamic"
        });

        using var sp = CreateServiceProvider(saml => saml.AddRegistrationProvider(source), addRegistration: false);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () => await service.GetRegistrationByIdAsync("dynamic"));
        Assert.Equal(SR.FormatID0886("dynamic"), exception.Message);
    }

    [Fact]
    public async Task ValidateResponseAsync_UsesDynamicRegistration()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.RegistrationId = "dynamic";

        using var sp = CreateServiceProvider(saml => saml.AddRegistrationProvider(new TestRegistrationProvider(registration)), addRegistration: false);
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        // Act
        var result = await service.ValidateResponseAsync(Encode(CreateResponse(idp, request.RequestId)), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.Equal("dynamic", result.Principal!.FindFirst(Claims.Private.RegistrationId)!.Value);
    }

    [Fact]
    public void CreateMetadata_ReturnsServiceProviderMetadata()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act
        var document = Load(service.CreateMetadata(AssertionConsumerServiceUrl));

        // Assert
        var manager = CreateNamespaceManager(document);
        Assert.Equal(ServiceProviderEntityId, document.DocumentElement!.GetAttribute("entityID"));
        Assert.Equal("true", document.SelectSingleNode("/md:EntityDescriptor/md:SPSSODescriptor/@AuthnRequestsSigned", manager)!.Value);
        Assert.Equal(AssertionConsumerServiceUrl.AbsoluteUri, document.SelectSingleNode(
            "/md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService[@Binding='" + Bindings.HttpPost + "']/@Location", manager)!.Value);
        Assert.NotNull(document.SelectSingleNode("/md:EntityDescriptor/md:SPSSODescriptor/md:KeyDescriptor[@use='signing']", manager));
        Assert.NotNull(document.SelectSingleNode("/md:EntityDescriptor/md:SPSSODescriptor/md:KeyDescriptor[@use='encryption']", manager));
    }

    [Fact]
    public void Options_RejectMissingEntityId()
    {
        // Arrange
        using var sp = CreateServiceProvider(saml => saml.Configure(options => options.EntityId = null));

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(() => sp.GetRequiredService<IOptionsMonitor<OpenIddictClientSamlOptions>>().CurrentValue);
        Assert.Contains(SR.GetResourceString(SR.ID0880), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Options_RejectRegistrationWithoutCertificates()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.SigningCertificates.Clear();

        using var sp = CreateServiceProvider(registration: registration);

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(() => sp.GetRequiredService<IOptionsMonitor<OpenIddictClientSamlOptions>>().CurrentValue);
        Assert.Contains(SR.FormatID0886(registration.RegistrationId), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Options_RejectDisabledRequestSigningWhenSigningCertificatesAreConfigured()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.SignAuthenticationRequests = false;

        using var sp = CreateServiceProvider(registration: registration);

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(() => sp.GetRequiredService<IOptionsMonitor<OpenIddictClientSamlOptions>>().CurrentValue);
        Assert.Contains(SR.FormatID0913(registration.RegistrationId), exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Options_RejectHttpSingleSignOnServiceUrlUnlessAllowed(bool allowed)
    {
        // Arrange
        var registration = CreateRegistration();
        registration.SingleSignOnServiceUrl = new Uri("http://idp.example.com/saml/sso", UriKind.Absolute);

        using var sp = CreateServiceProvider(saml =>
        {
            if (allowed)
            {
                saml.AllowInsecureIdentityProviderEndpoints();
            }
        }, registration);

        // Act and assert
        if (allowed)
        {
            Assert.NotNull(sp.GetRequiredService<IOptionsMonitor<OpenIddictClientSamlOptions>>().CurrentValue);
        }

        else
        {
            var exception = Assert.Throws<OptionsValidationException>(() => sp.GetRequiredService<IOptionsMonitor<OpenIddictClientSamlOptions>>().CurrentValue);
            Assert.Contains(SR.FormatID0887(registration.RegistrationId), exception.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Options_RejectUncMetadataAddress()
    {
        // Arrange
        var registration = new OpenIddictClientSamlRegistration
        {
            MetadataAddress = new Uri("file://server/share/metadata.xml", UriKind.Absolute),
            RegistrationId = "unc"
        };

        using var sp = CreateServiceProvider(registration: registration);

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(() => sp.GetRequiredService<IOptionsMonitor<OpenIddictClientSamlOptions>>().CurrentValue);
        Assert.Contains(SR.FormatID0888("unc"), exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("file")]
    [InlineData("https://internal.example.com/metadata")]
    public async Task GetRegistrationByIdAsync_RejectsDisallowedDynamicMetadataAddress(string address)
    {
        // Arrange
        var registration = new OpenIddictClientSamlRegistration
        {
            MetadataAddress = address is "file"
                ? new Uri(Path.Combine(Path.GetTempPath(), "metadata.xml"), UriKind.Absolute)
                : new Uri(address, UriKind.Absolute),
            RegistrationId = "dynamic"
        };

        using var sp = CreateServiceProvider(saml => saml.AddRegistrationProvider(new TestRegistrationProvider(registration))
            .AddAllowedDynamicMetadataHosts("idp.example.com"), addRegistration: false);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () => await service.GetRegistrationByIdAsync("dynamic"));
        Assert.Equal(SR.FormatID0912("dynamic"), exception.Message);
    }

    [Fact]
    public async Task GetRegistrationByIdAsync_AcceptsDynamicMetadataAddressWithAllowedHost()
    {
        // Arrange
        var registration = new OpenIddictClientSamlRegistration
        {
            MetadataAddress = new Uri("https://IDP.example.com/saml/metadata", UriKind.Absolute),
            RegistrationId = "dynamic"
        };

        using var sp = CreateServiceProvider(saml => saml.AddRegistrationProvider(new TestRegistrationProvider(registration))
            .AddAllowedDynamicMetadataHosts("idp.example.com"), addRegistration: false);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act and assert
        Assert.Same(registration, await service.GetRegistrationByIdAsync("dynamic"));
    }

    [Fact]
    public async Task GetRegistrationByIdAsync_UsesUpdatedDynamicRegistrationReturnedByAnotherLookup()
    {
        // Arrange
        var original = CreateRegistration();
        original.RegistrationId = "dynamic";
        original.AllowUnsolicitedResponses = true;

        var updated = CreateRegistration();
        updated.RegistrationId = "dynamic";
        updated.SigningCertificates.Clear();
        updated.SigningCertificates.Add(GetPublicCertificate(UnrelatedCertificate));

        var source = new TestRegistrationProvider(original);

        using var sp = CreateServiceProvider(saml => saml.AddRegistrationProvider(source), addRegistration: false);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        Assert.Same(original, await service.GetRegistrationByIdAsync("dynamic"));

        // Act
        source.Registrations = [updated];
        var resolved = await service.GetRegistrationsByProviderNameAsync(ProviderName);

        // Assert
        Assert.Same(updated, Assert.Single(resolved));
        Assert.Same(updated, await service.GetRegistrationByIdAsync("dynamic"));
        Assert.Equal(1, source.FindByIdCount);
    }

    [Fact]
    public async Task GetRegistrationByIdAsync_UsesUpdatedDynamicRegistrationOnceTheCacheEntryExpires()
    {
        // Arrange
        var time = new TestTimeProvider();

        var original = CreateRegistration();
        original.RegistrationId = "dynamic";

        var updated = CreateRegistration();
        updated.RegistrationId = "dynamic";
        updated.RequireEncryptedAssertions = true;

        var source = new TestRegistrationProvider(original);

        using var sp = CreateServiceProvider(saml => saml.AddRegistrationProvider(source)
            .SetDynamicRegistrationCacheLifetime(TimeSpan.FromMinutes(5))
            .Configure(options => options.TimeProvider = time), addRegistration: false);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        Assert.Same(original, await service.GetRegistrationByIdAsync("dynamic"));
        source.Registrations = [updated];

        // Act and assert
        time.UtcNow += TimeSpan.FromMinutes(1);
        Assert.Same(original, await service.GetRegistrationByIdAsync("dynamic"));

        time.UtcNow += TimeSpan.FromMinutes(5);
        Assert.Same(updated, await service.GetRegistrationByIdAsync("dynamic"));
        Assert.Equal(2, source.FindByIdCount);
    }

    [Fact]
    public async Task ClearCache_RemovesDeletedDynamicRegistrations()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.RegistrationId = "dynamic";

        var source = new TestRegistrationProvider(registration);

        using var sp = CreateServiceProvider(saml => saml.AddRegistrationProvider(source), addRegistration: false);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        Assert.Same(registration, await service.GetRegistrationByIdAsync("dynamic"));
        Assert.Single(await service.GetRegistrationsAsync());
        source.Registrations = [];

        // Act
        service.ClearCache();

        // Assert
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await service.GetRegistrationByIdAsync("dynamic"));
        Assert.Empty(await service.GetRegistrationsAsync());
    }

    [Fact]
    public async Task GetRegistrationsByProviderNameAsync_CachesLookupsIncludingEmptyResults()
    {
        // Arrange
        var registration = CreateRegistration();
        registration.RegistrationId = "dynamic";

        var source = new TestRegistrationProvider(registration);

        using var sp = CreateServiceProvider(saml => saml.AddRegistrationProvider(source), addRegistration: false);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act
        for (var index = 0; index < 3; index++)
        {
            Assert.Single(await service.GetRegistrationsByProviderNameAsync(ProviderName));
            Assert.Empty(await service.GetRegistrationsByProviderNameAsync("Unknown"));
            Assert.Single(await service.GetRegistrationsAsync());
        }

        // Assert
        Assert.Equal(2, source.FindByProviderNameCount);
        Assert.Equal(1, source.ListCount);
    }

    [Fact]
    public async Task GetRegistrationsAsync_IgnoresInvalidDynamicRegistrations()
    {
        // Arrange
        var valid = CreateRegistration();
        valid.RegistrationId = "valid";

        var invalid = new OpenIddictClientSamlRegistration { IdentityProviderEntityId = "https://invalid.example.com/", RegistrationId = "invalid" };

        using var sp = CreateServiceProvider(saml => saml.AddRegistrationProvider(new TestRegistrationProvider(invalid, valid)), addRegistration: false);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act
        var registrations = await service.GetRegistrationsAsync();

        // Assert
        Assert.Same(valid, Assert.Single(registrations));
    }

    [Theory]
    [InlineData(AssertionNamespace, "Unknown")]
    [InlineData("urn:example:conditions", "Custom")]
    public async Task ValidateResponseAsync_RejectsUnknownCondition(string ns, string name)
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var response = ModifyAssertion(CreateResponse(idp, request.RequestId), (assertion, manager) =>
        {
            var conditions = (XmlElement) assertion.SelectSingleNode("saml:Conditions", manager)!;
            conditions.AppendChild(assertion.OwnerDocument.CreateElement("x", name, ns));
        });

        // Act
        var result = await service.ValidateResponseAsync(Encode(response), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2454), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_AcceptsModifiedAndResignedAssertion()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var response = ModifyAssertion(CreateResponse(idp, request.RequestId), static (_, _) => { });

        // Act
        var result = await service.ValidateResponseAsync(Encode(response), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.True(result.Succeeded, result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsSubjectConfirmationInResponseToMismatch()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var response = ModifyAssertion(CreateResponse(idp, request.RequestId), static (assertion, manager) =>
            ((XmlElement) assertion.SelectSingleNode("saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", manager)!)
                .SetAttribute("InResponseTo", "_other"));

        // Act
        var result = await service.ValidateResponseAsync(Encode(response), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2453), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsBearerSubjectConfirmationWithNotBefore()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var response = ModifyAssertion(CreateResponse(idp, request.RequestId), static (assertion, manager) =>
            ((XmlElement) assertion.SelectSingleNode("saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", manager)!)
                .SetAttribute("NotBefore", XmlConvert.ToString(DateTime.UtcNow.AddMinutes(-1), XmlDateTimeSerializationMode.Utc)));

        // Act
        var result = await service.ValidateResponseAsync(Encode(response), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2453), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsEncryptedAssertionWithAdditionalPlainAssertion()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var plain = CreateResponse(idp, request.RequestId);
        var document = Load(EncryptAssertion(plain, GetPublicCertificate(EncryptionCertificate)));
        var manager = CreateNamespaceManager(document);

        // Add a (forged) plain assertion next to the encrypted assertion.
        var assertion = Load(plain).SelectSingleNode("/samlp:Response/saml:Assertion", manager)!;
        document.DocumentElement!.AppendChild(document.ImportNode(assertion, deep: true));

        // Act
        var result = await service.ValidateResponseAsync(Encode(document.OuterXml), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2450), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsUnsignedEncryptedAssertionInUnsignedResponse()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        var unsigned = ModifyAssertion(CreateResponse(idp, request.RequestId), static (_, _) => { }, sign: false);
        var response = EncryptAssertion(unsigned, GetPublicCertificate(EncryptionCertificate));

        // Act
        var result = await service.ValidateResponseAsync(Encode(response), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2452), result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateResponseAsync_RejectsSignedResponseWithReplacedUnsignedAssertion()
    {
        // Arrange
        using var sp = CreateServiceProvider();
        using var idp = CreateIdentityProvider();
        var (service, _, request, state) = await StartAsync(sp);

        // Create a signed response containing an unsigned assertion, then replace the assertion by a forged one.
        var response = Load(SignRoot(ModifyAssertion(CreateResponse(idp, request.RequestId), static (_, _) => { }, sign: false),
            IdentityProviderCertificate));
        var manager = CreateNamespaceManager(response);
        response.SelectSingleNode("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID", manager)!.InnerText = "mallory";

        // Act
        var result = await service.ValidateResponseAsync(Encode(response.OuterXml), "relay", state, AssertionConsumerServiceUrl);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal(SR.GetResourceString(SR.ID2445), result.ErrorDescription);
    }

    [Fact]
    public async Task GetIdentityProviderConfigurationAsync_NeverUsesMetadataAfterValidUntil()
    {
        // Arrange
        var time = new TestTimeProvider();

        using var idp = CreateIdentityProvider();
        var document = Load(idp.GetRequiredService<OpenIddictServerSamlService>().CreateMetadata(SingleSignOnServiceUrl));
        document.DocumentElement!.SetAttribute("validUntil", XmlConvert.ToString((time.UtcNow + TimeSpan.FromHours(1)).UtcDateTime,
            XmlDateTimeSerializationMode.Utc));

        var retriever = new TestMetadataRetriever(document.OuterXml);
        var registration = new OpenIddictClientSamlRegistration
        {
            MetadataAddress = new Uri("https://idp.example.com/saml/metadata", UriKind.Absolute),
            ProviderName = ProviderName
        };

        using var sp = CreateServiceProvider(saml => saml.SetMetadataRefreshInterval(TimeSpan.FromMinutes(10))
            .Configure(options => options.TimeProvider = time)
            .Services.AddSingleton<IOpenIddictClientSamlMetadataRetriever>(retriever), registration);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act and assert
        var configuration = await service.GetIdentityProviderConfigurationAsync(registration);
        Assert.NotNull(configuration.ExpirationDate);

        // Before validUntil, the previous metadata is used when the refresh fails.
        retriever.Fail = true;
        time.UtcNow += TimeSpan.FromMinutes(20);
        Assert.Equal(IdentityProviderEntityId, (await service.GetIdentityProviderConfigurationAsync(registration)).EntityId);
        Assert.Equal(2, retriever.Count);

        // After validUntil, the stale metadata is never used again.
        time.UtcNow += TimeSpan.FromHours(1);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await service.GetIdentityProviderConfigurationAsync(registration));
        Assert.Equal(3, retriever.Count);
    }

    [Fact]
    public async Task GetIdentityProviderConfigurationAsync_HonorsCacheDuration()
    {
        // Arrange
        var time = new TestTimeProvider();

        using var idp = CreateIdentityProvider();
        var document = Load(idp.GetRequiredService<OpenIddictServerSamlService>().CreateMetadata(SingleSignOnServiceUrl));
        document.DocumentElement!.SetAttribute("cacheDuration", "PT10M");

        var retriever = new TestMetadataRetriever(document.OuterXml);
        var registration = new OpenIddictClientSamlRegistration
        {
            MetadataAddress = new Uri("https://idp.example.com/saml/metadata", UriKind.Absolute),
            ProviderName = ProviderName
        };

        using var sp = CreateServiceProvider(saml => saml.Configure(options => options.TimeProvider = time)
            .Services.AddSingleton<IOpenIddictClientSamlMetadataRetriever>(retriever), registration);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act
        await service.GetIdentityProviderConfigurationAsync(registration);
        time.UtcNow += TimeSpan.FromMinutes(5);
        await service.GetIdentityProviderConfigurationAsync(registration);
        time.UtcNow += TimeSpan.FromMinutes(10);
        await service.GetIdentityProviderConfigurationAsync(registration);

        // Assert
        Assert.Equal(2, retriever.Count);
    }

    [Fact]
    public async Task GetIdentityProviderConfigurationAsync_IgnoresInsecureSingleSignOnServiceUrls()
    {
        // Arrange
        using var idp = CreateIdentityProvider();
        var metadata = idp.GetRequiredService<OpenIddictServerSamlService>().CreateMetadata(new Uri("http://idp.example.com/saml/sso", UriKind.Absolute));

        var registration = new OpenIddictClientSamlRegistration
        {
            MetadataAddress = new Uri("https://idp.example.com/saml/metadata", UriKind.Absolute),
            ProviderName = ProviderName
        };

        using var sp = CreateServiceProvider(saml => saml.Services.AddSingleton<IOpenIddictClientSamlMetadataRetriever>(
            new TestMetadataRetriever(metadata)), registration);
        var service = sp.GetRequiredService<OpenIddictClientSamlService>();

        // Act
        var configuration = await service.GetIdentityProviderConfigurationAsync(registration);

        // Assert
        Assert.Empty(configuration.SingleSignOnServices);
    }

    private static async Task<(OpenIddictClientSamlService Service, OpenIddictClientSamlRegistration Registration,
        AuthenticationRequestMessage Request, RequestState State)> StartAsync(IServiceProvider provider)
    {
        var service = provider.GetRequiredService<OpenIddictClientSamlService>();
        var registration = await service.GetRegistrationByProviderNameAsync(ProviderName);
        var request = await service.CreateAuthenticationRequestAsync(registration, AssertionConsumerServiceUrl, "relay");

        return (service, registration, request, service.CreateRequestState(registration, request, AssertionConsumerServiceUrl));
    }

    private sealed class TestMetadataRetriever(string metadata) : IOpenIddictClientSamlMetadataRetriever
    {
        public int Count { get; private set; }

        public string Metadata { get; set; } = metadata;

        public bool Fail { get; set; }

        public ValueTask<byte[]> RetrieveAsync(Uri address, int maximumSize, CancellationToken cancellationToken)
        {
            Count++;

            if (Fail)
            {
                throw new InvalidOperationException("unavailable");
            }

            return new(Encoding.UTF8.GetBytes(Metadata));
        }
    }

    private sealed class TestRegistrationProvider(params OpenIddictClientSamlRegistration[] registrations) : IOpenIddictClientSamlRegistrationProvider
    {
        public OpenIddictClientSamlRegistration[] Registrations { get; set; } = registrations;

        public int FindByIdCount { get; private set; }

        public int FindByProviderNameCount { get; private set; }

        public int ListCount { get; private set; }

        public ValueTask<OpenIddictClientSamlRegistration?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        {
            FindByIdCount++;
            return new(Array.Find(Registrations, registration => string.Equals(identifier, registration.RegistrationId, StringComparison.Ordinal)));
        }

        public ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> FindByEntityIdAsync(string entityId, CancellationToken cancellationToken)
            => new([.. Registrations.Where(registration => string.Equals(entityId, registration.IdentityProviderEntityId, StringComparison.Ordinal))]);

        public ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> FindByProviderNameAsync(string name, CancellationToken cancellationToken)
        {
            FindByProviderNameCount++;
            return new([.. Registrations.Where(registration => string.Equals(name, registration.ProviderName, StringComparison.Ordinal))]);
        }

        public ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> ListAsync(CancellationToken cancellationToken)
        {
            ListCount++;
            return new([.. Registrations]);
        }
    }
}
