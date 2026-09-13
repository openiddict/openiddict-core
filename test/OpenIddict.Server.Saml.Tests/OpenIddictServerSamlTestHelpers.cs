using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using Parameters = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.Parameters;

namespace OpenIddict.Server.Saml.Tests;

/// <summary>
/// Builds SAML authentication requests (as a service provider would) and validates SAML responses.
/// </summary>
public static class OpenIddictServerSamlTestHelpers
{
    public const string IdentityProviderEntityId = "https://idp.example.com/";
    public const string ServiceProviderEntityId = "https://sp.example.com/metadata";
    public const string SingleSignOnEndpoint = "https://idp.example.com/saml/sso";

    public static readonly Uri AssertionConsumerServiceUrl = new("https://sp.example.com/acs", UriKind.Absolute);
    public static readonly Uri SecondaryAssertionConsumerServiceUrl = new("https://sp.example.com/acs2", UriKind.Absolute);

    public static X509Certificate2 IdentityProviderCertificate { get; } = CreateCertificate("CN=idp.example.com");

    public static X509Certificate2 ServiceProviderCertificate { get; } = CreateCertificate("CN=sp.example.com");

    public static X509Certificate2 CreateCertificate(string subject)
    {
        using var key = RSA.Create(2048);

        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        // Note: the certificate is re-imported to ensure the private key is usable on all platforms.
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx, "password"), "password",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
#else
        return new X509Certificate2(certificate.Export(X509ContentType.Pfx, "password"), "password", X509KeyStorageFlags.Exportable);
#endif
    }

    public static OpenIddictServerSamlServiceProvider CreateServiceProvider() => new()
    {
        AssertionConsumerServiceUrls = { AssertionConsumerServiceUrl, SecondaryAssertionConsumerServiceUrl },
        AttributeMappings = { ["email"] = "mail" },
        EntityId = ServiceProviderEntityId,
        SigningCertificates = { ServiceProviderCertificate }
    };

    public static string CreateAuthenticationRequest(
        string? id = null,
        DateTimeOffset? issueInstant = null,
        string? destination = SingleSignOnEndpoint,
        string? assertionConsumerServiceUrl = null,
        string? issuer = ServiceProviderEntityId,
        string? extra = null,
        string? attributes = null)
    {
        var builder = new StringBuilder()
            .Append("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"")
            .Append(" ID=\"").Append(id ?? "_request_" + Guid.NewGuid().ToString("N")).Append('"')
            .Append(" Version=\"2.0\"")
            .Append(" IssueInstant=\"").Append((issueInstant ?? DateTimeOffset.UtcNow).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)).Append('"');

        if (destination is not null)
        {
            builder.Append(" Destination=\"").Append(destination).Append('"');
        }

        if (assertionConsumerServiceUrl is not null)
        {
            builder.Append(" AssertionConsumerServiceURL=\"").Append(assertionConsumerServiceUrl).Append('"');
        }

        builder.Append(' ').Append(attributes).Append('>');

        if (issuer is not null)
        {
            builder.Append("<saml:Issuer>").Append(issuer).Append("</saml:Issuer>");
        }

        builder.Append(extra);
        builder.Append("<samlp:NameIDPolicy AllowCreate=\"true\" /></samlp:AuthnRequest>");

        return builder.ToString();
    }

    public static string CreateRedirectQueryString(string request, string? relayState = null,
        X509Certificate2? certificate = null, string algorithm = SignatureAlgorithms.RsaSha256)
    {
        using var output = new MemoryStream();
        using (var stream = new DeflateStream(output, CompressionMode.Compress, leaveOpen: true))
        {
            var bytes = Encoding.UTF8.GetBytes(request);
            stream.Write(bytes, 0, bytes.Length);
        }

        var query = new StringBuilder()
            .Append(Parameters.SamlRequest).Append('=').Append(Uri.EscapeDataString(Convert.ToBase64String(output.ToArray())));

        if (relayState is not null)
        {
            query.Append('&').Append(Parameters.RelayState).Append('=').Append(Uri.EscapeDataString(relayState));
        }

        if (certificate is not null)
        {
            query.Append('&').Append(Parameters.SignatureAlgorithm).Append('=').Append(Uri.EscapeDataString(algorithm));

            using var key = certificate.GetRSAPrivateKey()!;
            var name = algorithm switch
            {
                SignatureAlgorithms.RsaSha256 => HashAlgorithmName.SHA256,
                SignatureAlgorithms.RsaSha512 => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA1
            };

            var signature = key.SignData(Encoding.UTF8.GetBytes(query.ToString()), name, RSASignaturePadding.Pkcs1);
            query.Append('&').Append(Parameters.Signature).Append('=').Append(Uri.EscapeDataString(Convert.ToBase64String(signature)));
        }

        return "?" + query;
    }

    public static XmlDocument SignDocument(string xml, X509Certificate2 certificate)
    {
        var document = new XmlDocument { PreserveWhitespace = true };
        document.LoadXml(xml);

        var root = document.DocumentElement!;

        using var key = certificate.GetRSAPrivateKey()!;

        var signed = new SignedXml(document) { SigningKey = key };
        signed.SignedInfo!.CanonicalizationMethod = Transforms.ExclusiveCanonicalization;
        signed.SignedInfo.SignatureMethod = SignatureAlgorithms.RsaSha256;

        var reference = new Reference("#" + root.GetAttribute("ID")) { DigestMethod = DigestAlgorithms.Sha256 };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signed.AddReference(reference);
        signed.ComputeSignature();

        var issuer = root.GetElementsByTagName(Elements.Issuer, Namespaces.Assertion)[0]!;
        root.InsertAfter(document.ImportNode(signed.GetXml(), deep: true), issuer);

        return document;
    }

    public static string EncodePost(string xml) => Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));

    public static XmlDocument LoadResponse(string xml)
    {
        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        document.LoadXml(xml);
        return document;
    }

    public static bool VerifySignature(XmlElement element, X509Certificate2 certificate)
    {
        XmlElement? signature = null;
        foreach (XmlNode node in element.ChildNodes)
        {
            if (node is XmlElement { LocalName: Elements.Signature, NamespaceURI: Namespaces.XmlDsig } candidate)
            {
                signature = candidate;
            }
        }

        if (signature is null)
        {
            return false;
        }

        // Note: the element is validated in its own document, as the .NET Framework implementation of the enveloped
        // signature transform doesn't correctly handle nested signatures (e.g an assertion signed in a signed response).
        var document = new XmlDocument { PreserveWhitespace = true };
        document.AppendChild(document.ImportNode(element, deep: true));

        var signed = new SignedXml(document);
        signed.LoadXml((XmlElement) document.DocumentElement!.ChildNodes.Cast<XmlNode>().Single(node => node is XmlElement
            { LocalName: Elements.Signature, NamespaceURI: Namespaces.XmlDsig }));

        return signed.SignedInfo!.References.Count is 1 &&
            string.Equals(((Reference) signed.SignedInfo.References[0]!).Uri, "#" + element.GetAttribute("ID"), StringComparison.Ordinal) &&
            signed.CheckSignature(certificate, verifySignatureOnly: true);
    }

    public static XmlNamespaceManager CreateNamespaceManager(XmlDocument document)
    {
        var manager = new XmlNamespaceManager(document.NameTable);
        manager.AddNamespace("samlp", Namespaces.Protocol);
        manager.AddNamespace("saml", Namespaces.Assertion);
        manager.AddNamespace("md", Namespaces.Metadata);
        manager.AddNamespace("ds", Namespaces.XmlDsig);
        return manager;
    }
}
