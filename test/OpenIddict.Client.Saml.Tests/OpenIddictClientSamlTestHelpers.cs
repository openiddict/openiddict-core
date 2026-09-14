/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server.Saml;
using ServerModels = OpenIddict.Server.Saml.OpenIddictServerSamlModels;

namespace OpenIddict.Client.Saml.Tests;

/// <summary>
/// Creates SAML 2.0 identity providers (using the OpenIddict SAML identity provider) and service providers.
/// </summary>
public static class OpenIddictClientSamlTestHelpers
{
    public const string AssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion";
    public const string ProtocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol";
    public const string IdentityProviderEntityId = "https://idp.example.com/";
    public const string ServiceProviderEntityId = "https://sp.example.com/saml";
    public const string ProviderName = "Idp";

    public static readonly Uri SingleSignOnServiceUrl = new("https://idp.example.com/saml/sso", UriKind.Absolute);
    public static readonly Uri AssertionConsumerServiceUrl = new("https://sp.example.com/saml/acs", UriKind.Absolute);

    public static X509Certificate2 IdentityProviderCertificate { get; } = CreateCertificate("CN=idp.example.com");

    public static X509Certificate2 ServiceProviderCertificate { get; } = CreateCertificate("CN=sp.example.com");

    public static X509Certificate2 EncryptionCertificate { get; } = CreateCertificate("CN=encryption.sp.example.com");

    public static X509Certificate2 UnrelatedCertificate { get; } = CreateCertificate("CN=attacker.example.com");

    public static X509Certificate2 CreateCertificate(string subject)
    {
        using var key = RSA.Create(2048);

        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx, "password"), "password",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
#else
        return new X509Certificate2(certificate.Export(X509ContentType.Pfx, "password"), "password", X509KeyStorageFlags.Exportable);
#endif
    }

    public static X509Certificate2 GetPublicCertificate(X509Certificate2 certificate)
#if NET9_0_OR_GREATER
        => X509CertificateLoader.LoadCertificate(certificate.RawData);
#else
        => new(certificate.RawData);
#endif

    /// <summary>
    /// Creates the OpenIddict SAML identity provider used to issue responses.
    /// </summary>
    public static ServiceProvider CreateIdentityProvider(
        Action<OpenIddictServerSamlOptions>? configuration = null, Uri? assertionConsumerServiceUrl = null)
    {
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddServer(options => options.UseSaml(saml =>
            {
                var provider = new OpenIddictServerSamlServiceProvider
                {
                    AssertionConsumerServiceUrls = { assertionConsumerServiceUrl ?? AssertionConsumerServiceUrl },
                    EntityId = ServiceProviderEntityId,
                    SigningCertificates = { GetPublicCertificate(ServiceProviderCertificate) }
                };

                saml.SetEntityId(IdentityProviderEntityId)
                    .AddSigningCertificate(IdentityProviderCertificate)
                    .AddServiceProvider(provider);

                if (configuration is not null)
                {
                    saml.Configure(configuration);
                }
            }));

        return services.BuildServiceProvider();
    }

    public static OpenIddictClientSamlRegistration CreateRegistration() => new()
    {
        AttributeMappings = { ["mail"] = Claims.Email },
        IdentityProviderEntityId = IdentityProviderEntityId,
        ProviderDisplayName = "Identity provider",
        ProviderName = ProviderName,
        SigningCertificates = { GetPublicCertificate(IdentityProviderCertificate) },
        SingleSignOnServiceUrl = SingleSignOnServiceUrl
    };

    /// <summary>
    /// Creates the service collection of the OpenIddict SAML service provider.
    /// </summary>
    public static IServiceCollection CreateServiceProviderServices(
        Action<OpenIddictClientSamlBuilder>? configuration = null, OpenIddictClientSamlRegistration? registration = null,
        bool addRegistration = true)
    {
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddClient(options => options.UseSaml(saml =>
            {
                saml.SetEntityId(ServiceProviderEntityId)
                    .AddSigningCertificate(ServiceProviderCertificate)
                    .AddEncryptionCertificate(EncryptionCertificate);

                if (addRegistration)
                {
                    saml.AddRegistration(registration ?? CreateRegistration());
                }

                configuration?.Invoke(saml);
            }));

        return services;
    }

    public static ServiceProvider CreateServiceProvider(
        Action<OpenIddictClientSamlBuilder>? configuration = null, OpenIddictClientSamlRegistration? registration = null,
        bool addRegistration = true)
        => CreateServiceProviderServices(configuration, registration, addRegistration).BuildServiceProvider();

    /// <summary>
    /// Issues a successful response using the OpenIddict SAML identity provider.
    /// </summary>
    public static string CreateResponse(IServiceProvider identityProvider, string? inResponseTo,
        Uri? assertionConsumerServiceUrl = null, string nameId = "alice", string? sessionIndex = "session-1")
    {
        var service = identityProvider.GetRequiredService<OpenIddictServerSamlService>();
        var provider = identityProvider.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<OpenIddictServerSamlOptions>>()
            .CurrentValue.ServiceProviders[0];

        return service.CreateResponse(new ServerModels.ResponseDescriptor
        {
            Assertion = new ServerModels.AssertionDescriptor
            {
                Attributes =
                [
                    new ServerModels.AssertionAttribute { Name = "mail", Values = ["alice@example.com"] },
                    new ServerModels.AssertionAttribute { Name = "role", Values = ["admin", "user"] }
                ],
                NameId = nameId,
                SessionIndex = sessionIndex
            },
            AssertionConsumerServiceUrl = assertionConsumerServiceUrl ?? AssertionConsumerServiceUrl,
            InResponseTo = inResponseTo,
            ServiceProvider = provider
        });
    }

    public static string Encode(string xml) => Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));

    public static XmlDocument Load(string xml)
    {
        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        document.LoadXml(xml);
        return document;
    }

    public static XmlNamespaceManager CreateNamespaceManager(XmlDocument document)
    {
        var manager = new XmlNamespaceManager(document.NameTable);
        manager.AddNamespace("samlp", ProtocolNamespace);
        manager.AddNamespace("saml", AssertionNamespace);
        manager.AddNamespace("md", "urn:oasis:names:tc:SAML:2.0:metadata");
        manager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        manager.AddNamespace("xenc", "http://www.w3.org/2001/04/xmlenc#");
        return manager;
    }

    /// <summary>
    /// Replaces the assertion of the specified response by an encrypted assertion (AES-256-CBC, RSA-OAEP key transport).
    /// </summary>
    public static string EncryptAssertion(string response, X509Certificate2 certificate, bool keyInsideEncryptedData = true)
    {
        var document = Load(response);
        var assertion = (XmlElement) document.SelectSingleNode("/samlp:Response/saml:Assertion", CreateNamespaceManager(document))!;

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();

        var data = new EncryptedData
        {
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url),
            Type = EncryptedXml.XmlEncElementUrl
        };

        data.CipherData.CipherValue = new EncryptedXml().EncryptData(assertion, aes, content: false);

        using var rsa = certificate.GetRSAPublicKey()!;

        var key = new EncryptedKey { EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSAOAEPUrl) };
        key.CipherData.CipherValue = EncryptedXml.EncryptKey(aes.Key, rsa, useOAEP: true);

        var container = document.CreateElement("saml", "EncryptedAssertion", AssertionNamespace);

        if (keyInsideEncryptedData)
        {
            data.KeyInfo.AddClause(new KeyInfoEncryptedKey(key));
            container.AppendChild(document.ImportNode(data.GetXml(), deep: true));
        }

        else
        {
            container.AppendChild(document.ImportNode(data.GetXml(), deep: true));
            container.AppendChild(document.ImportNode(key.GetXml(), deep: true));
        }

        assertion.ParentNode!.ReplaceChild(container, assertion);

        return document.OuterXml;
    }

    /// <summary>
    /// Modifies the assertion of the specified response and signs it again using the identity provider certificate
    /// (or leaves it unsigned if <paramref name="sign"/> is <see langword="false"/>).
    /// </summary>
    public static string ModifyAssertion(string response, Action<XmlElement, XmlNamespaceManager> modification, bool sign = true)
    {
        var document = Load(response);
        var manager = CreateNamespaceManager(document);
        var assertion = (XmlElement) document.SelectSingleNode("/samlp:Response/saml:Assertion", manager)!;

        if (assertion.SelectSingleNode("ds:Signature", manager) is XmlNode signature)
        {
            assertion.RemoveChild(signature);
        }

        modification(assertion, manager);

        if (!sign)
        {
            return document.OuterXml;
        }

        using var key = IdentityProviderCertificate.GetRSAPrivateKey()!;

        var signed = new SignedXml(document) { SigningKey = key };
        signed.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signed.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

        var reference = new Reference("#" + assertion.GetAttribute("ID")) { DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256" };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signed.AddReference(reference);
        signed.ComputeSignature();

        assertion.InsertAfter(document.ImportNode(signed.GetXml(), deep: true), assertion.SelectSingleNode("saml:Issuer", manager));

        return document.OuterXml;
    }

    /// <summary>
    /// Signs the root element of the specified document (enveloped signature inserted after the issuer).
    /// </summary>
    public static string SignRoot(string xml, X509Certificate2 certificate)
    {
        var document = Load(xml);
        var root = document.DocumentElement!;

        using var key = certificate.GetRSAPrivateKey()!;

        var signed = new SignedXml(document) { SigningKey = key };
        signed.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signed.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

        var reference = new Reference("#" + root.GetAttribute("ID")) { DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256" };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signed.AddReference(reference);
        signed.ComputeSignature();

        var issuer = root.GetElementsByTagName("Issuer", AssertionNamespace)[0];
        var node = document.ImportNode(signed.GetXml(), deep: true);

        if (issuer is not null && ReferenceEquals(issuer.ParentNode, root))
        {
            root.InsertAfter(node, issuer);
        }

        else
        {
            root.PrependChild(node);
        }

        return document.OuterXml;
    }
}

/// <summary>
/// Represents a time provider whose current date can be changed.
/// </summary>
public sealed class TestTimeProvider : TimeProvider
{
    public DateTimeOffset UtcNow { get; set; } = DateTimeOffset.UtcNow;

    public override DateTimeOffset GetUtcNow() => UtcNow;
}
