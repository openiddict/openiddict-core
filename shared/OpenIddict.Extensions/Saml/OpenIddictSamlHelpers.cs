/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace OpenIddict.Extensions;

/// <summary>
/// Contains the XML, encoding and signature helpers shared by the SAML 2.0 identity provider and service provider.
/// </summary>
internal static class OpenIddictSamlHelpers
{
    public const string AssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion";
    public const string MetadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata";
    public const string ProtocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol";
    public const string XmlDsigNamespace = "http://www.w3.org/2000/09/xmldsig#";
    public const string XmlEncNamespace = "http://www.w3.org/2001/04/xmlenc#";
    public const string XmlnsNamespace = "http://www.w3.org/2000/xmlns/";

    public const string RsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public const string RsaSha384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    public const string RsaSha512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

    public const string Sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    public const string Sha384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    public const string Sha512 = "http://www.w3.org/2001/04/xmlenc#sha512";

    public const string Canonicalization = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    public const string EnvelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    public const string ExclusiveCanonicalization = "http://www.w3.org/2001/10/xml-exc-c14n#";

    /// <summary>
    /// Creates a random identifier that is a valid xs:ID value.
    /// </summary>
    public static string CreateIdentifier()
    {
        var bytes = RandomNumberGenerator.GetBytes(count: 20);

        var builder = new StringBuilder("_", capacity: 41);
        foreach (var value in bytes)
        {
            builder.Append(value.ToString("x2", CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }

    /// <summary>
    /// Formats a date as a xs:dateTime value in UTC.
    /// </summary>
    public static string FormatInstant(DateTimeOffset date)
        => date.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// <summary>
    /// Parses a xs:dateTime value. SAML 2.0 requires UTC instants (SAML core, 1.3.3): values without
    /// a time zone are treated as UTC (instead of local time) and values with an offset are converted to UTC.
    /// </summary>
    public static bool TryParseInstant(string? value, out DateTimeOffset instant)
    {
        instant = default;

        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        try
        {
            var date = XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.RoundtripKind);

            instant = date.Kind switch
            {
                DateTimeKind.Unspecified => new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Utc)),
                _                        => new DateTimeOffset(date.ToUniversalTime())
            };

            return true;
        }

        catch (Exception exception) when (exception is FormatException or ArgumentException or OverflowException)
        {
            return false;
        }
    }

    /// <summary>
    /// Determines whether the specified value is a valid xs:NCName (and thus xs:ID) value.
    /// </summary>
    public static bool IsNCName(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        try
        {
            XmlConvert.VerifyNCName(value);
            return true;
        }

        catch (XmlException)
        {
            return false;
        }
    }

    /// <summary>
    /// Decodes a base64-encoded value, returning <see langword="null"/> if it is invalid.
    /// </summary>
    public static byte[]? DecodeBase64(string value)
    {
        try
        {
            return Convert.FromBase64String(value);
        }

        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// Compresses the specified payload using raw DEFLATE (RFC 1951), as required by the HTTP-Redirect binding.
    /// </summary>
    public static byte[] Deflate(byte[] data)
    {
        using var output = new MemoryStream();
        using (var stream = new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            stream.Write(data, 0, data.Length);
        }

        return output.ToArray();
    }

    /// <summary>
    /// Inflates a raw DEFLATE payload (RFC 1951), enforcing the specified maximum size.
    /// </summary>
    /// <returns>The inflated bytes, or <see langword="null"/> if the payload is invalid or too large.</returns>
    public static byte[]? Inflate(byte[] data, int maximumSize, out bool tooLarge)
    {
        tooLarge = false;

        try
        {
            using var input = new MemoryStream(data, writable: false);
            using var stream = new DeflateStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();

            var buffer = new byte[4096];
            int count;

            while ((count = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (output.Length + count > maximumSize)
                {
                    tooLarge = true;
                    return null;
                }

                output.Write(buffer, 0, count);
            }

            return output.Length is 0 ? null : output.ToArray();
        }

        catch (InvalidDataException)
        {
            return null;
        }
    }

    /// <summary>
    /// Creates the secure XML reader settings used to parse SAML messages (no DTD processing, no external resolution).
    /// </summary>
    public static XmlReaderSettings CreateReaderSettings(int maximumSize, ConformanceLevel level = ConformanceLevel.Document) => new()
    {
        CloseInput = true,
        ConformanceLevel = level,
        DtdProcessing = DtdProcessing.Prohibit,
        MaxCharactersFromEntities = 1024,
        MaxCharactersInDocument = maximumSize,
        XmlResolver = null
    };

    /// <summary>
    /// Loads an XML document using secure settings (no DTD processing, no external resolution).
    /// </summary>
    /// <returns>The document, or <see langword="null"/> if the XML is invalid.</returns>
    public static XmlDocument? LoadDocument(byte[] data, int maximumSize, out bool containsDocumentType)
    {
        containsDocumentType = false;

        try
        {
            using var reader = XmlReader.Create(new MemoryStream(data, writable: false), CreateReaderSettings(maximumSize));

            var document = new XmlDocument
            {
                PreserveWhitespace = true,
                XmlResolver = null
            };

            document.Load(reader);

            return document.DocumentElement is null ? null : document;
        }

        catch (XmlException exception)
        {
            // Note: the reader is configured to reject DTDs: this check is only used to return a more specific error.
            containsDocumentType = exception.Message.Contains("DTD", StringComparison.OrdinalIgnoreCase);
            return null;
        }
    }

    /// <summary>
    /// Returns the text content of an element, or <see langword="null"/> if the element contains child elements.
    /// </summary>
    public static string? GetTextContent(XmlElement element)
    {
        var builder = new StringBuilder();

        foreach (XmlNode node in element.ChildNodes)
        {
            switch (node.NodeType)
            {
                case XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.Whitespace or XmlNodeType.SignificantWhitespace:
                    builder.Append(node.Value);
                    break;

                case XmlNodeType.Comment:
                    break;

                default:
                    return null;
            }
        }

        return builder.ToString().Trim();
    }

    /// <summary>
    /// Returns the child elements of the specified element that have the specified name and namespace.
    /// </summary>
    public static List<XmlElement> GetChildElements(XmlElement element, string name, string ns)
    {
        List<XmlElement> elements = [];

        foreach (XmlNode node in element.ChildNodes)
        {
            if (node is XmlElement child &&
                string.Equals(child.LocalName, name, StringComparison.Ordinal) &&
                string.Equals(child.NamespaceURI, ns, StringComparison.Ordinal))
            {
                elements.Add(child);
            }
        }

        return elements;
    }

    /// <summary>
    /// Returns the value of the specified attribute, or <see langword="null"/> if the attribute is not present.
    /// </summary>
    public static string? GetAttributeOrNull(XmlElement element, string name)
        => element.HasAttribute(name) ? element.GetAttribute(name) : null;

    /// <summary>
    /// Resolves the hash algorithm corresponding to the specified RSA signature algorithm.
    /// </summary>
    public static HashAlgorithmName? GetHashAlgorithm(string? algorithm) => algorithm switch
    {
        RsaSha256 => HashAlgorithmName.SHA256,
        RsaSha384 => HashAlgorithmName.SHA384,
        RsaSha512 => HashAlgorithmName.SHA512,
        _ => null
    };

    /// <summary>
    /// Determines whether the specified digest algorithm is supported.
    /// </summary>
    public static bool IsSupportedDigestAlgorithm(string? algorithm)
        => algorithm is Sha256 or Sha384 or Sha512;

    /// <summary>
    /// Determines whether the specified certificate contains an RSA public key.
    /// </summary>
    public static bool IsRsaCertificate(X509Certificate2 certificate)
        => string.Equals(certificate.PublicKey.Oid.Value, "1.2.840.113549.1.1.1", StringComparison.Ordinal);

    /// <summary>
    /// Validates the signature of a message sent using the HTTP-Redirect binding.
    /// </summary>
    public static SignatureValidationResult ValidateRedirectSignature(
        string octets, string algorithm, string signature, IEnumerable<X509Certificate2> certificates)
    {
        if (GetHashAlgorithm(algorithm) is not HashAlgorithmName name)
        {
            return SignatureValidationResult.UnsupportedAlgorithm;
        }

        if (DecodeBase64(signature) is not byte[] bytes || bytes.Length is 0)
        {
            return SignatureValidationResult.Invalid;
        }

        var data = Encoding.UTF8.GetBytes(octets);

        foreach (var certificate in certificates)
        {
            using var key = certificate.GetRSAPublicKey();
            if (key is not null && key.VerifyData(data, bytes, name, RSASignaturePadding.Pkcs1))
            {
                return SignatureValidationResult.Valid;
            }
        }

        return SignatureValidationResult.Invalid;
    }

    /// <summary>
    /// Signs the octets of a message sent using the HTTP-Redirect binding (SAML bindings, 3.4.4.1).
    /// </summary>
    public static string CreateRedirectSignature(string octets, RSA key, string algorithm)
    {
        var name = GetHashAlgorithm(algorithm) ?? throw new ArgumentOutOfRangeException(nameof(algorithm));

        return Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(octets), name, RSASignaturePadding.Pkcs1));
    }

    /// <summary>
    /// Validates the enveloped XML signature of the specified element.
    /// </summary>
    /// <remarks>
    /// To prevent XML signature wrapping attacks, the element must contain exactly one signature as a direct child,
    /// with a single reference pointing to the element itself, whose identifier must be unique in the document.
    /// Only the element returned in <paramref name="verified"/> (or the element itself) must then be consumed
    /// by the caller, that is responsible for ensuring the element is located where it is expected.
    /// </remarks>
    [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "Only the built-in RSA, SHA-2, C14N and enveloped signature algorithms, which are statically referenced, are accepted.")]
    [UnconditionalSuppressMessage("AOT", "IL3050", Justification = "XSLT transforms are rejected before the signature is computed or validated.")]
    public static SignatureValidationResult ValidateEnvelopedSignature(
        XmlElement element, IEnumerable<X509Certificate2> certificates, out XmlElement? verified)
    {
        verified = null;

        var signatures = GetChildElements(element, "Signature", XmlDsigNamespace);
        if (signatures.Count is 0)
        {
            return SignatureValidationResult.Missing;
        }

        if (signatures.Count is not 1)
        {
            return SignatureValidationResult.Invalid;
        }

        var identifier = element.GetAttribute("ID");
        if (string.IsNullOrEmpty(identifier) || CountElementsWithIdentifier(element.OwnerDocument, identifier) is not 1)
        {
            return SignatureValidationResult.Invalid;
        }

        // Note: when the element is not the root of its document (e.g an assertion embedded in a response), it is
        // validated in a standalone document, as the enveloped signature transform locates the signature to remove
        // using its position in the entire document, which doesn't work correctly when signatures are nested.
        // The namespace declarations inherited from the ancestors are copied to preserve the canonical form.
        XmlDocument document;
        XmlElement target;

        if (ReferenceEquals(element.OwnerDocument.DocumentElement, element))
        {
            document = element.OwnerDocument;
            target = element;
        }

        else
        {
            document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
            target = (XmlElement) document.ImportNode(element, deep: true);
            document.AppendChild(target);

            CopyInScopeNamespaces(element.ParentNode, target);
        }

        var signature = GetChildElements(target, "Signature", XmlDsigNamespace)[0];

        var xml = new SignedXml(document);

        try
        {
            xml.LoadXml(signature);
        }

        catch (CryptographicException)
        {
            return SignatureValidationResult.Invalid;
        }

        if (xml.SignedInfo is null || xml.SignedInfo.References.Count is not 1 ||
            xml.SignedInfo.References[0] is not Reference reference ||
            !string.Equals(reference.Uri, "#" + identifier, StringComparison.Ordinal))
        {
            return SignatureValidationResult.Invalid;
        }

        if (GetHashAlgorithm(xml.SignatureMethod) is null || !IsSupportedDigestAlgorithm(reference.DigestMethod) ||
            xml.SignedInfo.CanonicalizationMethod is not (ExclusiveCanonicalization or Canonicalization))
        {
            return SignatureValidationResult.UnsupportedAlgorithm;
        }

        foreach (Transform transform in reference.TransformChain)
        {
            if (transform.Algorithm is not (EnvelopedSignature or ExclusiveCanonicalization or Canonicalization))
            {
                return SignatureValidationResult.UnsupportedAlgorithm;
            }
        }

        foreach (var certificate in certificates)
        {
            try
            {
                if (xml.CheckSignature(certificate, verifySignatureOnly: true))
                {
                    verified = target;
                    return SignatureValidationResult.Valid;
                }
            }

            catch (CryptographicException)
            {
                return SignatureValidationResult.Invalid;
            }
        }

        return SignatureValidationResult.Invalid;
    }

    /// <summary>
    /// Counts the elements whose identifier attribute matches the specified value.
    /// </summary>
    public static int CountElementsWithIdentifier(XmlDocument document, string identifier)
    {
        var count = 0;

        foreach (XmlNode node in document.GetElementsByTagName("*"))
        {
            if (node is not XmlElement element)
            {
                continue;
            }

            // Note: SignedXml resolves references using the "Id", "ID" and "id" attributes.
            foreach (XmlAttribute attribute in element.Attributes)
            {
                if (attribute.LocalName is "Id" or "ID" or "id" &&
                    string.Equals(attribute.Value, identifier, StringComparison.Ordinal))
                {
                    count++;
                }
            }
        }

        return count;
    }

    /// <summary>
    /// Copies the namespace declarations in scope for the specified node to the specified element,
    /// unless the element already declares the same prefix.
    /// </summary>
    public static void CopyInScopeNamespaces(XmlNode? node, XmlElement target)
    {
        for (; node is XmlElement ancestor; node = node.ParentNode)
        {
            foreach (XmlAttribute attribute in ancestor.Attributes)
            {
                if (!string.Equals(attribute.NamespaceURI, XmlnsNamespace, StringComparison.Ordinal))
                {
                    continue;
                }

                var name = attribute.Prefix.Length is 0 ? "xmlns" : "xmlns:" + attribute.LocalName;
                if (target.HasAttribute(name))
                {
                    continue;
                }

                var declaration = target.OwnerDocument.CreateAttribute(name, XmlnsNamespace);
                declaration.Value = attribute.Value;
                target.Attributes.Append(declaration);
            }
        }
    }

    /// <summary>
    /// Signs the specified element using an enveloped XML signature inserted after the specified sibling.
    /// </summary>
    [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "Only the built-in RSA, SHA-2, C14N and enveloped signature algorithms, which are statically referenced, are accepted.")]
    [UnconditionalSuppressMessage("AOT", "IL3050", Justification = "XSLT transforms are rejected before the signature is computed or validated.")]
    public static void SignElement(XmlElement element, XmlElement? insertAfter,
        X509Certificate2 certificate, RSA key, string signatureAlgorithm, string digestAlgorithm)
    {
        var document = element.OwnerDocument;

        var xml = new SignedXml(document) { SigningKey = key };
        xml.SignedInfo!.CanonicalizationMethod = ExclusiveCanonicalization;
        xml.SignedInfo.SignatureMethod = signatureAlgorithm;

        var reference = new Reference("#" + element.GetAttribute("ID"))
        {
            DigestMethod = digestAlgorithm
        };

        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        xml.AddReference(reference);

        var info = new KeyInfo();
        info.AddClause(new KeyInfoX509Data(certificate));
        xml.KeyInfo = info;

        xml.ComputeSignature();

        var node = document.ImportNode(xml.GetXml(), deep: true);

        if (insertAfter is not null)
        {
            element.InsertAfter(node, insertAfter);
        }

        else
        {
            element.PrependChild(node);
        }
    }

    /// <summary>
    /// Appends a new element (with an optional text content) to the specified parent.
    /// </summary>
    public static XmlElement AppendElement(XmlElement parent, string prefix, string name, string ns, string? text = null)
    {
        var element = parent.OwnerDocument.CreateElement(prefix, name, ns);

        if (text is not null)
        {
            element.AppendChild(parent.OwnerDocument.CreateTextNode(text));
        }

        parent.AppendChild(element);

        return element;
    }

    /// <summary>
    /// Determines whether the specified value represents the same absolute URL.
    /// </summary>
    public static bool IsSameUrl(string? value, Uri url)
        => Uri.TryCreate(value, UriKind.Absolute, out var candidate) && IsSameUrl(candidate, url);

    /// <summary>
    /// Determines whether the specified URLs are identical once normalized.
    /// </summary>
    public static bool IsSameUrl(Uri left, Uri right)
        => left.IsAbsoluteUri && right.IsAbsoluteUri &&
           Uri.Compare(left, right, UriComponents.AbsoluteUri, UriFormat.UriEscaped, StringComparison.Ordinal) is 0;

    /// <summary>
    /// Creates an HTML page automatically posting the specified fields to the specified URL.
    /// </summary>
    /// <param name="url">The URL the form is posted to.</param>
    /// <param name="fields">The hidden form fields.</param>
    /// <param name="nonce">The nonce attached to the inline script (that must be allowed by the content security policy).</param>
    public static string CreateFormPostPage(Uri url, IEnumerable<KeyValuePair<string, string>> fields, string nonce)
    {
        var builder = new StringBuilder()
            .Append("<!doctype html><html><head><meta charset=\"utf-8\" /><title>Working...</title></head><body>")
            .Append("<form id=\"saml\" method=\"post\" action=\"").Append(WebUtility.HtmlEncode(url.AbsoluteUri)).Append("\">");

        foreach (var field in fields)
        {
            builder.Append("<input type=\"hidden\" name=\"").Append(WebUtility.HtmlEncode(field.Key)).Append("\" value=\"")
                   .Append(WebUtility.HtmlEncode(field.Value)).Append("\" />");
        }

        return builder
            .Append("<noscript><button type=\"submit\">Continue</button></noscript></form>")
            .Append("<script nonce=\"").Append(WebUtility.HtmlEncode(nonce)).Append("\">document.getElementById('saml').submit();</script>")
            .Append("</body></html>")
            .ToString();
    }

    /// <summary>
    /// Creates the content security policy attached to the auto-post pages.
    /// </summary>
    public static string CreateFormPostContentSecurityPolicy(Uri url, string nonce)
        => $"default-src 'none'; script-src 'nonce-{nonce}'; " +
           $"form-action {url.GetLeftPart(UriPartial.Authority)}; frame-ancestors 'none'; base-uri 'none'";

    /// <summary>
    /// Represents the result of a signature validation.
    /// </summary>
    public enum SignatureValidationResult
    {
        Missing,
        Valid,
        Invalid,
        UnsupportedAlgorithm
    }
}
