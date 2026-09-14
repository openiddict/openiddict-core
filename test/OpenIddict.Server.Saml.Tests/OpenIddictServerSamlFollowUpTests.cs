using System.Collections.Concurrent;
using System.Globalization;
using System.Reflection;
using System.Text;
using System.Xml;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using static OpenIddict.Server.Saml.OpenIddictServerSamlModels;
using static OpenIddict.Server.Saml.Tests.OpenIddictServerSamlTestHelpers;

namespace OpenIddict.Server.Saml.Tests;

/// <summary>
/// Covers encrypted assertions, the HTTP-Artifact binding, the replay cache and the metadata signature requirement.
/// </summary>
public class OpenIddictServerSamlFollowUpTests
{
    private static readonly Uri Endpoint = new(SingleSignOnEndpoint, UriKind.Absolute);
    private static readonly Uri ArtifactEndpoint = new("https://idp.example.com/saml/artifact", UriKind.Absolute);

    private static readonly System.Security.Cryptography.X509Certificates.X509Certificate2 EncryptionCertificate =
        CreateCertificate("CN=sp-encryption.example.com");

    // Encrypted assertions

    [Theory]
    [InlineData(DataEncryptionAlgorithms.Aes256Gcm, KeyTransportAlgorithms.RsaOaepMgf1P)]
    [InlineData(DataEncryptionAlgorithms.Aes256Cbc, KeyTransportAlgorithms.RsaOaepMgf1P)]
    [InlineData(DataEncryptionAlgorithms.Aes256Gcm, KeyTransportAlgorithms.RsaOaep)]
    [InlineData(DataEncryptionAlgorithms.Aes256Cbc, KeyTransportAlgorithms.RsaOaep)]
    public void CreateResponse_ReturnsSignedEncryptedAssertion(string dataAlgorithm, string keyAlgorithm)
    {
        // Arrange
        using var provider = CreateProvider(options => options.SignResponses = true);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var sp = CreateEncryptingServiceProvider();
        sp.DataEncryptionAlgorithm = dataAlgorithm;
        sp.KeyTransportAlgorithm = keyAlgorithm;

        // Act
        var xml = service.CreateResponse(new ResponseDescriptor
        {
            Assertion = new AssertionDescriptor { NameId = "alice" },
            AssertionConsumerServiceUrl = AssertionConsumerServiceUrl,
            InResponseTo = "_request",
            ServiceProvider = sp
        });

        // Assert
        Assert.DoesNotContain("alice", xml, StringComparison.Ordinal);

        var document = LoadResponse(xml);
        var manager = CreateNamespaceManager(document);
        var response = document.DocumentElement!;

        Assert.True(VerifySignature(response, IdentityProviderCertificate));
        Assert.Null(response.SelectSingleNode("saml:Assertion", manager));

        var encrypted = (XmlElement) response.SelectSingleNode("saml:EncryptedAssertion", manager)!;
        Assert.Equal(dataAlgorithm, encrypted.SelectSingleNode("xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm", manager)!.Value);
        Assert.Equal(EncryptedTypes.Element, encrypted.SelectSingleNode("xenc:EncryptedData/@Type", manager)!.Value);
        Assert.Equal(keyAlgorithm, encrypted.SelectSingleNode(
            "xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm", manager)!.Value);

        var assertion = DecryptAssertion(encrypted, EncryptionCertificate);
        Assert.Equal(Elements.Assertion, assertion.LocalName);
        Assert.True(VerifySignature(assertion, IdentityProviderCertificate));
        Assert.Equal("alice", assertion.SelectSingleNode("saml:Subject/saml:NameID", CreateNamespaceManager(assertion.OwnerDocument))!.InnerText);
    }

    [Fact]
    public void CreateResponse_UsesGlobalEncryptionAlgorithmsByDefault()
    {
        // Arrange
        using var provider = CreateProvider(options => options.DataEncryptionAlgorithm = DataEncryptionAlgorithms.Aes256Cbc);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Act
        var document = LoadResponse(service.CreateResponse(new ResponseDescriptor
        {
            Assertion = new AssertionDescriptor { NameId = "alice" },
            AssertionConsumerServiceUrl = AssertionConsumerServiceUrl,
            ServiceProvider = CreateEncryptingServiceProvider()
        }));

        // Assert
        var manager = CreateNamespaceManager(document);
        Assert.Equal(DataEncryptionAlgorithms.Aes256Cbc, document.DocumentElement!.SelectSingleNode(
            "saml:EncryptedAssertion/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm", manager)!.Value);
    }

    [Fact]
    public void CreateResponse_DoesNotEncryptErrorResponsesOrAssertionsByDefault()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Act
        var plain = LoadResponse(service.CreateResponse(new ResponseDescriptor
        {
            Assertion = new AssertionDescriptor { NameId = "alice" },
            AssertionConsumerServiceUrl = AssertionConsumerServiceUrl,
            ServiceProvider = CreateServiceProvider()
        }));

        var error = LoadResponse(service.CreateResponse(new ResponseDescriptor
        {
            AssertionConsumerServiceUrl = AssertionConsumerServiceUrl,
            ServiceProvider = CreateEncryptingServiceProvider(),
            Status = StatusCodes.Responder
        }));

        // Assert
        Assert.NotNull(plain.DocumentElement!.SelectSingleNode("saml:Assertion", CreateNamespaceManager(plain)));
        Assert.Null(error.DocumentElement!.SelectSingleNode("saml:EncryptedAssertion", CreateNamespaceManager(error)));
    }

    [Fact]
    public void Options_RejectEncryptionWithoutCertificate()
    {
        // Arrange
        using var provider = CreateProvider(serviceProvider: sp => sp.EncryptAssertions = true);

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<OpenIddictServerSamlOptions>>().Value);
        Assert.Contains(SR.FormatID0844(ServiceProviderEntityId), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Options_RejectUnsupportedEncryptionAlgorithms()
    {
        // Arrange
        using var provider = CreateProvider(options => options.DataEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc");

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<OpenIddictServerSamlOptions>>().Value);
        Assert.Contains(SR.FormatID0842("http://www.w3.org/2001/04/xmlenc#tripledes-cbc", KeyTransportAlgorithms.RsaOaepMgf1P),
            exception.Message, StringComparison.Ordinal);
    }

    // Assertion consumer service bindings

    [Theory]
    [InlineData("AssertionConsumerServiceIndex=\"1\"", Bindings.HttpArtifact)]
    [InlineData("AssertionConsumerServiceIndex=\"0\"", Bindings.HttpPost)]
    [InlineData("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\"", Bindings.HttpArtifact)]
    [InlineData("AssertionConsumerServiceURL=\"https://sp.example.com/acs2\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\"", Bindings.HttpArtifact)]
    public async Task ValidatePostAuthenticationRequestAsync_SelectsAssertionConsumerServiceBinding(string attributes, string binding)
    {
        // Arrange
        using var provider = CreateProvider(options => options.EnableArtifactBinding = true,
            sp => sp.AssertionConsumerServiceBindings[1] = Bindings.HttpArtifact);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var document = SignDocument(CreateAuthenticationRequest(attributes: attributes), ServiceProviderCertificate);

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        // Assert
        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.Equal(binding, result.ResponseBinding);
        Assert.Equal(Bindings.HttpPost, result.Request!.Binding);
        Assert.Equal(binding is Bindings.HttpArtifact ? SecondaryAssertionConsumerServiceUrl : AssertionConsumerServiceUrl,
            result.AssertionConsumerServiceUrl);
    }

    [Theory]
    [InlineData(Bindings.HttpArtifact, true)]
    [InlineData(Bindings.HttpPost, false)]
    public async Task ValidatePostAuthenticationRequestAsync_AcceptsIndexCombinedWithMatchingProtocolBinding(string binding, bool succeeded)
    {
        // Arrange
        using var provider = CreateProvider(options => options.EnableArtifactBinding = true,
            sp => sp.AssertionConsumerServiceBindings[1] = Bindings.HttpArtifact);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Note: AssertionConsumerServiceIndex is mutually exclusive with ProtocolBinding (SAML core, 3.4.1),
        // but the combination is tolerated when the binding matches the binding of the indexed endpoint.
        var document = SignDocument(CreateAuthenticationRequest(
            attributes: "AssertionConsumerServiceIndex=\"1\" ProtocolBinding=\"" + binding + "\""), ServiceProviderCertificate);

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        // Assert
        Assert.Equal(succeeded, result.Succeeded);
        Assert.Equal(Bindings.HttpArtifact, result.ResponseBinding);

        if (!succeeded)
        {
            Assert.True(result.CanReturnErrorToServiceProvider);
            Assert.Equal(StatusCodes.UnsupportedBinding, result.SecondLevelStatus);
        }
    }

    [Fact]
    public async Task ValidatePostAuthenticationRequestAsync_RejectsProtocolBindingNotMatchingEndpoint()
    {
        // Arrange
        using var provider = CreateProvider(options => options.EnableArtifactBinding = true,
            sp => sp.AssertionConsumerServiceBindings[1] = Bindings.HttpArtifact);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var document = SignDocument(CreateAuthenticationRequest(
            assertionConsumerServiceUrl: SecondaryAssertionConsumerServiceUrl.AbsoluteUri,
            attributes: "ProtocolBinding=\"" + Bindings.HttpPost + "\""), ServiceProviderCertificate);

        // Act
        var result = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        // Assert
        Assert.False(result.Succeeded);
        Assert.True(result.CanReturnErrorToServiceProvider);
        Assert.Equal(StatusCodes.UnsupportedBinding, result.SecondLevelStatus);
        Assert.Equal(Bindings.HttpArtifact, result.ResponseBinding);
    }

    [Fact]
    public async Task ValidateRequestStateAsync_RestoresResponseBindingAndRejectsDisabledArtifactBinding()
    {
        // Arrange
        using var provider = CreateProvider(options => options.EnableArtifactBinding = true,
            sp => sp.AssertionConsumerServiceBindings[1] = Bindings.HttpArtifact);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var document = SignDocument(CreateAuthenticationRequest(attributes: "AssertionConsumerServiceIndex=\"1\""), ServiceProviderCertificate);
        var validation = await service.ValidatePostAuthenticationRequestAsync(EncodePost(document.OuterXml), null, Endpoint);

        var state = OpenIddictServerSamlService.DeserializeRequestState(OpenIddictServerSamlService.SerializeRequestState(
            service.CreateRequestState(validation, TimeSpan.FromMinutes(10))))!;

        // Act and assert
        var result = await service.ValidateRequestStateAsync(state);
        Assert.True(result.Succeeded, result.ErrorDescription);
        Assert.Equal(Bindings.HttpArtifact, result.ResponseBinding);
        Assert.False(string.IsNullOrEmpty(state.Id));

        // The binding stored in the state must still be the binding of the endpoint.
        Assert.False((await service.ValidateRequestStateAsync(state with { ResponseBinding = Bindings.HttpPost })).Succeeded);
    }

    [Theory]
    [InlineData(2, Bindings.HttpPost)]
    [InlineData(0, Bindings.HttpRedirect)]
    public void Options_RejectInvalidAssertionConsumerServiceBindings(int index, string binding)
    {
        // Arrange
        using var provider = CreateProvider(serviceProvider: sp => sp.AssertionConsumerServiceBindings[index] = binding);

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<OpenIddictServerSamlOptions>>().Value);
        Assert.Contains(SR.FormatID0840(ServiceProviderEntityId), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Options_RejectArtifactBindingWhenDisabled()
    {
        // Arrange
        using var provider = CreateProvider(serviceProvider: sp => sp.AssertionConsumerServiceBindings[0] = Bindings.HttpArtifact);

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<OpenIddictServerSamlOptions>>().Value);
        Assert.Contains(SR.FormatID0843(ServiceProviderEntityId), exception.Message, StringComparison.Ordinal);
    }

    // Artifact binding

    [Fact]
    public async Task CreateArtifactAsync_ReturnsType4Artifact()
    {
        // Arrange
        using var provider = CreateProvider(options => options.EnableArtifactBinding = true);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Act
        var artifact = Convert.FromBase64String(await service.CreateArtifactAsync(CreateServiceProvider(), "<response />"));

        // Assert
        Assert.Equal(44, artifact.Length);
        Assert.Equal([0x00, 0x04, 0x00, 0x00], artifact.Take(4).ToArray());

#pragma warning disable CA5350
        using var sha1 = System.Security.Cryptography.SHA1.Create();
        Assert.Equal(sha1.ComputeHash(Encoding.UTF8.GetBytes(IdentityProviderEntityId)), artifact.Skip(4).Take(20).ToArray());
#pragma warning restore CA5350
    }

    [Fact]
    public void CreateArtifactRedirectUrl_AppendsArtifactAndRelayState()
    {
        // Act
        var url = OpenIddictServerSamlService.CreateArtifactRedirectUrl(new Uri("https://sp.example.com/acs?x=1"), "AAQ+/=", "a b&c");

        // Assert
        Assert.Equal("https://sp.example.com/acs?x=1&SAMLart=AAQ%2B%2F%3D&RelayState=a%20b%26c", url.AbsoluteUri);
    }

    [Fact]
    public async Task ArtifactMethods_ThrowWhenArtifactBindingIsDisabled()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Act and assert
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await service.CreateArtifactAsync(CreateServiceProvider(), "<x />"));
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await service.ResolveArtifactAsync(new MemoryStream(), ArtifactEndpoint));
    }

    [Fact]
    public async Task ResolveArtifactAsync_ReturnsSignedResponseOnlyOnce()
    {
        // Arrange
        using var provider = CreateProvider(options => options.EnableArtifactBinding = true);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var response = service.CreateResponse(new ResponseDescriptor
        {
            Assertion = new AssertionDescriptor { NameId = "alice" },
            AssertionConsumerServiceUrl = AssertionConsumerServiceUrl,
            InResponseTo = "_request",
            ServiceProvider = CreateServiceProvider()
        });

        var artifact = await service.CreateArtifactAsync(CreateServiceProvider(), response);

        // Act
        var first = await service.ResolveArtifactAsync(CreateBody(CreateArtifactResolveEnvelope(artifact, certificate: ServiceProviderCertificate)), ArtifactEndpoint);
        var second = await service.ResolveArtifactAsync(CreateBody(CreateArtifactResolveEnvelope(artifact, certificate: ServiceProviderCertificate)), ArtifactEndpoint);

        // Assert
        Assert.True(first.Resolved);
        Assert.False(first.IsFault);

        var element = GetArtifactResponse(first.Content);
        var manager = CreateNamespaceManager(element.OwnerDocument);
        Assert.True(VerifySignature(element, IdentityProviderCertificate));
        Assert.StartsWith("_resolve_", element.GetAttribute("InResponseTo"), StringComparison.Ordinal);
        Assert.Equal(StatusCodes.Success, element.SelectSingleNode("samlp:Status/samlp:StatusCode/@Value", manager)!.Value);

        var embedded = (XmlElement) element.SelectSingleNode("samlp:Response", manager)!;
        Assert.Equal("_request", embedded.GetAttribute("InResponseTo"));
        Assert.True(VerifySignature((XmlElement) embedded.SelectSingleNode("saml:Assertion", manager)!, IdentityProviderCertificate));

        Assert.False(second.Resolved);
        Assert.False(second.IsFault);
        Assert.Equal(SR.GetResourceString(SR.ID2425), second.ErrorDescription);
        Assert.Null(first.ErrorDescription);
        var empty = GetArtifactResponse(second.Content);
        Assert.True(VerifySignature(empty, IdentityProviderCertificate));
        var emptyManager = CreateNamespaceManager(empty.OwnerDocument);
        Assert.Equal(StatusCodes.Success, empty.SelectSingleNode("samlp:Status/samlp:StatusCode/@Value", emptyManager)!.Value);
        Assert.Null(empty.SelectSingleNode("samlp:Response", emptyManager));
    }

    [Fact]
    public async Task ResolveArtifactAsync_RequiresValidRequesterSignature()
    {
        // Arrange
        using var provider = CreateProvider(options => options.EnableArtifactBinding = true);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var artifact = await service.CreateArtifactAsync(CreateServiceProvider(), "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" />");

        // Act
        var unsigned = await service.ResolveArtifactAsync(CreateBody(CreateArtifactResolveEnvelope(artifact)), ArtifactEndpoint);
        var forged = await service.ResolveArtifactAsync(CreateBody(CreateArtifactResolveEnvelope(artifact, certificate: CreateCertificate("CN=attacker"))), ArtifactEndpoint);
        var legitimate = await service.ResolveArtifactAsync(CreateBody(CreateArtifactResolveEnvelope(artifact, certificate: ServiceProviderCertificate)), ArtifactEndpoint);

        // Assert
        Assert.False(unsigned.Resolved);
        Assert.Equal(SR.GetResourceString(SR.ID2423), unsigned.ErrorDescription);
        Assert.False(forged.Resolved);
        Assert.Equal(SR.GetResourceString(SR.ID2423), forged.ErrorDescription);

        // Note: unauthenticated resolution attempts must not consume the artifact.
        Assert.True(legitimate.Resolved);
    }

    [Fact]
    public async Task ResolveArtifactAsync_RejectsArtifactIssuedToAnotherServiceProvider()
    {
        // Arrange
        var other = CreateServiceProvider();
        other.EntityId = "https://other.example.com/metadata";

        using var provider = CreateProvider(options =>
        {
            options.EnableArtifactBinding = true;
            options.ServiceProviders.Add(other);
        });

        var service = provider.GetRequiredService<OpenIddictServerSamlService>();
        var artifact = await service.CreateArtifactAsync(CreateServiceProvider(), "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" />");

        // Act
        var stolen = await service.ResolveArtifactAsync(CreateBody(CreateArtifactResolveEnvelope(
            artifact, issuer: other.EntityId, certificate: ServiceProviderCertificate)), ArtifactEndpoint);
        var legitimate = await service.ResolveArtifactAsync(CreateBody(CreateArtifactResolveEnvelope(
            artifact, certificate: ServiceProviderCertificate)), ArtifactEndpoint);

        // Assert
        Assert.False(stolen.Resolved);
        Assert.Equal(SR.GetResourceString(SR.ID2426), stolen.ErrorDescription);
        Assert.False(legitimate.Resolved);
        Assert.Equal(SR.GetResourceString(SR.ID2425), legitimate.ErrorDescription);
    }

    [Fact]
    public async Task ResolveArtifactAsync_RejectsExpiredArtifacts()
    {
        // Arrange
        var clock = new MutableTimeProvider();

        using var provider = CreateProvider(options =>
        {
            options.EnableArtifactBinding = true;
            options.TimeProvider = clock;
        });

        var service = provider.GetRequiredService<OpenIddictServerSamlService>();
        var artifact = await service.CreateArtifactAsync(CreateServiceProvider(), "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" />");

        clock.Now += TimeSpan.FromMinutes(2);

        // Act
        var result = await service.ResolveArtifactAsync(CreateBody(CreateArtifactResolveEnvelope(
            artifact, certificate: ServiceProviderCertificate, issueInstant: clock.Now)), ArtifactEndpoint);

        // Assert
        Assert.False(result.Resolved);
        Assert.Equal(SR.GetResourceString(SR.ID2425), result.ErrorDescription);
    }

    [Theory]
    [InlineData(-10, null)]
    [InlineData(5, null)]
    [InlineData(0, "https://idp.example.com/other")]
    public async Task ResolveArtifactAsync_RejectsStaleOrMisdirectedRequestsWithoutConsumingArtifact(int minutes, string? destination)
    {
        // Arrange
        using var provider = CreateProvider(options => options.EnableArtifactBinding = true);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var artifact = await service.CreateArtifactAsync(CreateServiceProvider(), "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" />");

        // Act
        var rejected = await service.ResolveArtifactAsync(CreateBody(CreateArtifactResolveEnvelope(artifact,
            certificate: ServiceProviderCertificate, issueInstant: DateTimeOffset.UtcNow.AddMinutes(minutes), destination: destination)), ArtifactEndpoint);
        var legitimate = await service.ResolveArtifactAsync(CreateBody(CreateArtifactResolveEnvelope(artifact,
            certificate: ServiceProviderCertificate, destination: ArtifactEndpoint.AbsoluteUri)), ArtifactEndpoint);

        // Assert
        Assert.False(rejected.Resolved);
        Assert.False(rejected.IsFault);
        Assert.Equal(SR.GetResourceString(SR.ID2424), rejected.ErrorDescription);
        Assert.True(legitimate.Resolved, legitimate.ErrorDescription);
    }

    [Fact]
    public async Task ArtifactStore_StoresEncryptedMessages()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddOpenIddict()
            .AddServer(options => options.UseSaml(saml => saml
                .SetEntityId(IdentityProviderEntityId)
                .AddSigningCertificate(IdentityProviderCertificate)
                .AddServiceProvider(CreateServiceProvider())
                .EnableArtifactBinding()));

        using var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<IOpenIddictServerSamlArtifactStore>();
        var cache = provider.GetRequiredService<Microsoft.Extensions.Caching.Distributed.IDistributedCache>();

        var handle = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(20));
        var key = "openiddict-saml-artifact:" + Convert.ToBase64String(System.Security.Cryptography.SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(handle))).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        // Act
        await store.AddAsync(handle, new ArtifactMessage
        {
            ExpirationDate = DateTimeOffset.UtcNow.AddMinutes(1),
            Message = "<secret>alice@example.com</secret>",
            ServiceProvider = ServiceProviderEntityId
        }, CancellationToken.None);

        var stored = await cache.GetAsync(key);

        // Assert
        Assert.NotNull(stored);
        var text = Encoding.UTF8.GetString(stored);
        Assert.DoesNotContain("alice@example.com", text, StringComparison.Ordinal);
        Assert.DoesNotContain(ServiceProviderEntityId, text, StringComparison.Ordinal);

        // The payload cannot be decrypted without the handle: tampered payloads are ignored.
        stored[stored.Length - 1] ^= 0xFF;
        await cache.SetAsync(key, stored, new Microsoft.Extensions.Caching.Distributed.DistributedCacheEntryOptions());
        Assert.Null(await store.RemoveAsync(handle, CancellationToken.None));
    }

    [Fact]
    public async Task ArtifactStore_RoundTripsMessagesUsingPrivateMemoryCache()
    {
        // Arrange
        using var provider = CreateProvider(options => options.EnableArtifactBinding = true);
        var store = provider.GetRequiredService<IOpenIddictServerSamlArtifactStore>();

        var handle = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(20));
        var expiration = DateTimeOffset.UtcNow.AddMinutes(1);

        // Act
        await store.AddAsync(handle, new ArtifactMessage
        {
            ExpirationDate = expiration,
            Message = "<message />",
            ServiceProvider = ServiceProviderEntityId
        }, CancellationToken.None);

        var message = await store.RemoveAsync(handle, CancellationToken.None);

        // Assert
        Assert.NotNull(message);
        Assert.Equal("<message />", message.Message);
        Assert.Equal(ServiceProviderEntityId, message.ServiceProvider);
        Assert.Equal(expiration.UtcTicks, message.ExpirationDate.UtcTicks);
        Assert.Null(await store.RemoveAsync(handle, CancellationToken.None));
    }

    [Fact]
    public async Task ResolveArtifactAsync_RejectsArtifactsIssuedByAnotherEntity()
    {
        // Arrange
        using var provider = CreateProvider(options => options.EnableArtifactBinding = true);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var artifact = Convert.FromBase64String(await service.CreateArtifactAsync(CreateServiceProvider(), "<x />"));
        artifact[10] ^= 0xFF;

        // Act
        var result = await service.ResolveArtifactAsync(CreateBody(CreateArtifactResolveEnvelope(
            Convert.ToBase64String(artifact), certificate: ServiceProviderCertificate)), ArtifactEndpoint);

        // Assert
        Assert.False(result.Resolved);
    }

    [Theory]
    [InlineData("not xml")]
    [InlineData("<samlp:ArtifactResolve xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" />")]
    [InlineData("<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body /></soap:Envelope>")]
    [InlineData("<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" /></soap:Body></soap:Envelope>")]
    [InlineData("")]
    public async Task ResolveArtifactAsync_ReturnsSoapFaultForInvalidMessages(string body)
    {
        // Arrange
        using var provider = CreateProvider(options => options.EnableArtifactBinding = true);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Act
        var result = await service.ResolveArtifactAsync(CreateBody(body), ArtifactEndpoint);

        // Assert
        Assert.True(result.IsFault);
        Assert.False(result.Resolved);
        Assert.Contains("soap:Client", result.Content, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ResolveArtifactAsync_ReturnsSoapFaultForMandatoryHeaders()
    {
        // Arrange
        using var provider = CreateProvider(options => options.EnableArtifactBinding = true);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var envelope = CreateArtifactResolveEnvelope("AAQ=", certificate: ServiceProviderCertificate,
            header: "<x:Custom xmlns:x=\"urn:x\" soap:mustUnderstand=\"1\" />");

        // Act
        var result = await service.ResolveArtifactAsync(CreateBody(envelope), ArtifactEndpoint);

        // Assert
        Assert.True(result.IsFault);
        Assert.Contains("soap:MustUnderstand", result.Content, StringComparison.Ordinal);
    }

    [Fact]
    public void CreateMetadata_PublishesArtifactResolutionServiceWhenEnabled()
    {
        // Arrange
        using var disabled = CreateProvider();
        using var enabled = CreateProvider(options => options.EnableArtifactBinding = true);

        // Act
        var without = LoadResponse(disabled.GetRequiredService<OpenIddictServerSamlService>().CreateMetadata(Endpoint, ArtifactEndpoint));
        var with = LoadResponse(enabled.GetRequiredService<OpenIddictServerSamlService>().CreateMetadata(Endpoint, ArtifactEndpoint));

        // Assert
        Assert.Null(without.DocumentElement!.SelectSingleNode("md:IDPSSODescriptor/md:ArtifactResolutionService", CreateNamespaceManager(without)));

        var service = (XmlElement) with.DocumentElement!.SelectSingleNode("md:IDPSSODescriptor/md:ArtifactResolutionService", CreateNamespaceManager(with))!;
        Assert.Equal(Bindings.Soap, service.GetAttribute("Binding"));
        Assert.Equal(ArtifactEndpoint.AbsoluteUri, service.GetAttribute("Location"));
        Assert.Equal("0", service.GetAttribute("index"));

        // Note: the schema requires ArtifactResolutionService elements to precede the NameIDFormat elements.
        Assert.Equal(Elements.NameIdFormat, service.NextSibling!.LocalName);
    }

    // Replay protection

    [Fact]
    public async Task ValidatePostAuthenticationRequestAsync_RejectsReplayedRequestByDefault()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var payload = EncodePost(SignDocument(CreateAuthenticationRequest(id: "_replayed"), ServiceProviderCertificate).OuterXml);

        // Act
        var first = await service.ValidatePostAuthenticationRequestAsync(payload, null, Endpoint);
        var second = await service.ValidatePostAuthenticationRequestAsync(payload, null, Endpoint);

        // Assert
        Assert.True(first.Succeeded, first.ErrorDescription);
        Assert.False(second.Succeeded);
        Assert.False(second.CanReturnErrorToServiceProvider);
        Assert.Equal(SR.GetResourceString(SR.ID2420), second.ErrorDescription);
    }

    [Fact]
    public async Task ValidatePostAuthenticationRequestAsync_AcceptsReplayedRequestWhenDisabled()
    {
        // Arrange
        using var provider = CreateProvider(options => options.EnableRequestReplayProtection = false);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var payload = EncodePost(SignDocument(CreateAuthenticationRequest(id: "_replayed"), ServiceProviderCertificate).OuterXml);

        // Act and assert
        Assert.True((await service.ValidatePostAuthenticationRequestAsync(payload, null, Endpoint)).Succeeded);
        Assert.True((await service.ValidatePostAuthenticationRequestAsync(payload, null, Endpoint)).Succeeded);
    }

    [Fact]
    public async Task ValidateRedirectAuthenticationRequestAsync_DoesNotConsumeIdentifierOfRejectedRequests()
    {
        // Arrange
        using var provider = CreateProvider(options => options.EnableRequestReplayProtection = true);
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        var request = CreateAuthenticationRequest(id: "_forged");

        // Act
        var forged = await service.ValidateRedirectAuthenticationRequestAsync(
            CreateRedirectQueryString(request, certificate: CreateCertificate("CN=attacker")), Endpoint);
        var legitimate = await service.ValidateRedirectAuthenticationRequestAsync(
            CreateRedirectQueryString(request, certificate: ServiceProviderCertificate), Endpoint);

        // Assert
        Assert.False(forged.Succeeded);
        Assert.True(legitimate.Succeeded, legitimate.ErrorDescription);
    }

    [Fact]
    public async Task ConsumeRequestStateAsync_AllowsSingleUseByDefault()
    {
        // Arrange
        using var enabled = CreateProvider();
        using var disabled = CreateProvider(options => options.EnableRequestReplayProtection = false);

        var service = enabled.GetRequiredService<OpenIddictServerSamlService>();
        var state = new RequestState
        {
            AssertionConsumerServiceUrl = AssertionConsumerServiceUrl,
            CreationDate = DateTimeOffset.UtcNow,
            ExpirationDate = DateTimeOffset.UtcNow.AddMinutes(5),
            Id = "state",
            ServiceProvider = ServiceProviderEntityId
        };

        // Act and assert
        Assert.True(await service.ConsumeRequestStateAsync(state));
        Assert.False(await service.ConsumeRequestStateAsync(state));
        Assert.True(await service.ConsumeRequestStateAsync(state with { Id = "other" }));

        // States without identifier (created by a previous version) are also bound to a single use.
        Assert.True(await service.ConsumeRequestStateAsync(state with { Id = null }));
        Assert.False(await service.ConsumeRequestStateAsync(state with { Id = null }));

        var other = disabled.GetRequiredService<OpenIddictServerSamlService>();
        Assert.True(await other.ConsumeRequestStateAsync(state));
        Assert.True(await other.ConsumeRequestStateAsync(state));
    }

    [Fact]
    public async Task DeserializeRequestState_ReadsLegacyStatesThatCanBeConsumedOnce()
    {
        // Arrange: payload serialized using the previous format (version 2, without identifier and response binding).
        var expiration = DateTimeOffset.UtcNow.AddMinutes(5);

        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write((byte) 2);
            writer.Write(ServiceProviderEntityId);
            writer.Write(AssertionConsumerServiceUrl.AbsoluteUri);
            writer.Write(false);
            writer.Write(DateTimeOffset.UtcNow.UtcTicks);
            writer.Write(expiration.UtcTicks);
            writer.Write(true);
            writer.Write("_legacy");
            writer.Write(ServiceProviderEntityId);
            writer.Write(DateTimeOffset.UtcNow.UtcTicks);
            writer.Write(Bindings.HttpPost);
            writer.Write(false);
            writer.Write(false);
            writer.Write(false);
            writer.Write(false);
            writer.Write(true);
        }

        using var enabled = CreateProvider();
        using var disabled = CreateProvider(options => options.EnableRequestReplayProtection = false);

        // Act
        var state = OpenIddictServerSamlService.DeserializeRequestState(stream.ToArray());

        // Assert
        Assert.NotNull(state);
        Assert.Null(state.Id);
        Assert.Null(state.ResponseBinding);
        Assert.Equal("_legacy", state.Request!.Id);
        Assert.True(state.Request.IsSigned);
        Assert.Equal(expiration.UtcTicks, state.ExpirationDate.UtcTicks);

        Assert.True((await enabled.GetRequiredService<OpenIddictServerSamlService>().ValidateRequestStateAsync(state)).Succeeded);
        Assert.True(await enabled.GetRequiredService<OpenIddictServerSamlService>().ConsumeRequestStateAsync(state));
        Assert.False(await enabled.GetRequiredService<OpenIddictServerSamlService>().ConsumeRequestStateAsync(state));
        Assert.True(await disabled.GetRequiredService<OpenIddictServerSamlService>().ConsumeRequestStateAsync(state));

        // Unknown versions are rejected.
        var unknown = stream.ToArray();
        unknown[0] = 1;
        Assert.Null(OpenIddictServerSamlService.DeserializeRequestState(unknown));
    }

    [Fact]
    public async Task ReplayCache_UsesRelativeExpirationWithCustomTimeProvider()
    {
        // Arrange
        var clock = new MutableTimeProvider { Now = DateTimeOffset.UtcNow.AddYears(-1) };
        using var provider = CreateProvider(options => options.TimeProvider = clock);

        var cache = provider.GetRequiredService<IOpenIddictServerSamlReplayCache>();

        // Act and assert
        Assert.True(await cache.TryAddAsync("identifier", clock.Now.AddMinutes(5), CancellationToken.None));
        Assert.False(await cache.TryAddAsync("identifier", clock.Now.AddMinutes(5), CancellationToken.None));
    }

    [Fact]
    public async Task ReplayCache_FailsClosedWhenPrivateMemoryCacheIsFull()
    {
        // Arrange
        using var provider = CreateProvider();
        var cache = (OpenIddictServerSamlReplayCache) Activator.CreateInstance(typeof(OpenIddictServerSamlReplayCache),
            BindingFlags.Instance | BindingFlags.NonPublic, binder: null,
            args: [provider, provider.GetRequiredService<IOptionsMonitor<OpenIddictServerSamlOptions>>(), 2L], culture: null)!;

        var expiration = DateTimeOffset.UtcNow.AddMinutes(5);

        // Act and assert
        Assert.True(await cache.TryAddAsync("first", expiration, CancellationToken.None));
        Assert.True(await cache.TryAddAsync("second", expiration, CancellationToken.None));

        // New identifiers can no longer be remembered: they are rejected and existing entries are not evicted.
        Assert.False(await cache.TryAddAsync("third", expiration, CancellationToken.None));
        await Task.Delay(100);
        Assert.False(await cache.TryAddAsync("first", expiration, CancellationToken.None));
        Assert.False(await cache.TryAddAsync("second", expiration, CancellationToken.None));
        Assert.False(await cache.TryAddAsync("fourth", expiration, CancellationToken.None));
    }

    [Fact]
    public async Task ReplayCache_FailsClosedWhenDistributedCacheDiscardsEntries()
    {
        // Arrange
        using var provider = CreateProviderWithDistributedCache(new DiscardingDistributedCache());
        var cache = provider.GetRequiredService<IOpenIddictServerSamlReplayCache>();

        // Act and assert
        Assert.False(await cache.TryAddAsync("identifier", DateTimeOffset.UtcNow.AddMinutes(5), CancellationToken.None));
    }

    [Fact]
    public async Task ReplayCache_DoesNotSerializeUnrelatedIdentifiers()
    {
        // Arrange
        var distributed = new BlockingDistributedCache();
        using var provider = CreateProviderWithDistributedCache(distributed);
        var cache = provider.GetRequiredService<IOpenIddictServerSamlReplayCache>();

        var expiration = DateTimeOffset.UtcNow.AddMinutes(5);
        var blocked = cache.TryAddAsync("blocked", expiration, CancellationToken.None).AsTask();
        await distributed.Entered.Task;

        // Act: at least one of these identifiers uses a different lock stripe than the blocked one.
        var others = Enumerable.Range(0, 8)
            .Select(index => cache.TryAddAsync("other-" + index.ToString(CultureInfo.InvariantCulture), expiration, CancellationToken.None).AsTask())
            .ToList();

        await Task.WhenAny(Task.WhenAny(others), Task.Delay(10_000));
        var completed = others.Any(task => task.IsCompleted);
        distributed.Release.SetResult(true);

        // Assert
        Assert.True(completed);
        Assert.True(await blocked);
    }

    [Fact]
    public async Task Service_UsesCustomReplayCacheAndArtifactStore()
    {
        // Arrange
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddServer(options => options.UseSaml(saml => saml
                .SetEntityId(IdentityProviderEntityId)
                .AddSigningCertificate(IdentityProviderCertificate)
                .AddServiceProvider(CreateServiceProvider())
                .EnableArtifactBinding()
                .SetReplayCache<RejectingReplayCache>()
                .SetArtifactStore<RecordingArtifactStore>()));

        using var provider = services.BuildServiceProvider();
        var service = provider.GetRequiredService<OpenIddictServerSamlService>();

        // Act
        await service.CreateArtifactAsync(CreateServiceProvider(), "<x />");
        var result = await service.ValidatePostAuthenticationRequestAsync(
            EncodePost(SignDocument(CreateAuthenticationRequest(), ServiceProviderCertificate).OuterXml), null, Endpoint);

        // Assert
        Assert.Single(((RecordingArtifactStore) provider.GetRequiredService<IOpenIddictServerSamlArtifactStore>()).Handles);
        Assert.Equal(SR.GetResourceString(SR.ID2420), result.ErrorDescription);
    }

    // Metadata signature requirement

    [Fact]
    public void CreateMetadata_DerivesWantAuthnRequestsSignedFromOptions()
    {
        // Arrange
        using var unsigned = CreateProvider(serviceProvider: sp => sp.RequireSignedAuthenticationRequests = false);
        using var overridden = CreateProvider(options => options.WantAuthenticationRequestsSigned = true,
            sp => sp.RequireSignedAuthenticationRequests = false);

        // Act and assert
        Assert.Equal("false", GetWantAuthnRequestsSigned(unsigned));
        Assert.Equal("true", GetWantAuthnRequestsSigned(overridden));
    }

    [Fact]
    public void CreateMetadata_DoesNotEnumerateOptionsWhenCustomStoreIsUsed()
    {
        // Arrange
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddServer(options => options.UseSaml(saml => saml
                .SetEntityId(IdentityProviderEntityId)
                .AddSigningCertificate(IdentityProviderCertificate)
                .SetServiceProviderStore<EmptyStore>()));

        using var provider = services.BuildServiceProvider();

        using var explicitFalse = new ServiceCollection().AddOpenIddict()
            .AddServer(options => options.UseSaml(saml => saml
                .SetEntityId(IdentityProviderEntityId)
                .AddSigningCertificate(IdentityProviderCertificate)
                .SetServiceProviderStore<EmptyStore>()
                .SetWantAuthenticationRequestsSigned(false)))
            .Services.BuildServiceProvider();

        // Act and assert
        Assert.Equal("true", GetWantAuthnRequestsSigned(provider));
        Assert.Equal("false", GetWantAuthnRequestsSigned(explicitFalse));
    }

    private static string GetWantAuthnRequestsSigned(IServiceProvider provider)
    {
        var document = LoadResponse(provider.GetRequiredService<OpenIddictServerSamlService>().CreateMetadata(Endpoint));
        return document.DocumentElement!.SelectSingleNode("md:IDPSSODescriptor/@WantAuthnRequestsSigned", CreateNamespaceManager(document))!.Value!;
    }

    private static OpenIddictServerSamlServiceProvider CreateEncryptingServiceProvider()
    {
        var provider = CreateServiceProvider();
        provider.EncryptAssertions = true;
        // Note: only the public part of the certificate is registered, as a service provider metadata would provide it.
#if NET9_0_OR_GREATER
        provider.EncryptionCertificate = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(EncryptionCertificate.RawData);
#else
        provider.EncryptionCertificate = new(EncryptionCertificate.RawData);
#endif
        return provider;
    }

    private static MemoryStream CreateBody(string content) => new(Encoding.UTF8.GetBytes(content));

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

    public sealed class EmptyStore : IOpenIddictServerSamlServiceProviderStore
    {
        public ValueTask<OpenIddictServerSamlServiceProvider?> FindByEntityIdAsync(string entityId, CancellationToken cancellationToken)
            => new(result: null);
    }

    private static ServiceProvider CreateProviderWithDistributedCache(IDistributedCache cache)
    {
        var services = new ServiceCollection();
        services.AddSingleton(cache);
        services.AddOpenIddict()
            .AddServer(options => options.UseSaml(saml => saml
                .SetEntityId(IdentityProviderEntityId)
                .AddSigningCertificate(IdentityProviderCertificate)
                .AddServiceProvider(CreateServiceProvider())));

        return services.BuildServiceProvider();
    }

    public sealed class DiscardingDistributedCache : IDistributedCache
    {
        public byte[]? Get(string key) => null;
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => Task.FromResult<byte[]?>(null);
        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Remove(string key) { }
        public Task RemoveAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) { }
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
            => Task.CompletedTask;
    }

    // Stores entries in memory and blocks the first read until released.
    public sealed class BlockingDistributedCache : IDistributedCache
    {
        private readonly ConcurrentDictionary<string, byte[]> _entries = new(StringComparer.Ordinal);
        private int _calls;

        public TaskCompletionSource<bool> Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public byte[]? Get(string key) => _entries.TryGetValue(key, out var value) ? value : null;

        public async Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            if (Interlocked.Increment(ref _calls) is 1)
            {
                Entered.SetResult(true);
                await Release.Task;
            }

            return Get(key);
        }

        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Remove(string key) => _entries.TryRemove(key, out _);
        public Task RemoveAsync(string key, CancellationToken token = default)
        {
            Remove(key);
            return Task.CompletedTask;
        }

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => _entries[key] = value;
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            Set(key, value, options);
            return Task.CompletedTask;
        }
    }

    public sealed class RejectingReplayCache : IOpenIddictServerSamlReplayCache
    {
        public ValueTask<bool> TryAddAsync(string identifier, DateTimeOffset expirationDate, CancellationToken cancellationToken) => new(false);
    }

    public sealed class RecordingArtifactStore : IOpenIddictServerSamlArtifactStore
    {
        public List<string> Handles { get; } = [];

        public ValueTask AddAsync(string handle, ArtifactMessage message, CancellationToken cancellationToken)
        {
            Handles.Add(handle);
            return default;
        }

        public ValueTask<ArtifactMessage?> RemoveAsync(string handle, CancellationToken cancellationToken) => new(result: null);
    }
}
