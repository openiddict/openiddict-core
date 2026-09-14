/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using Parameters = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.Parameters;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Contains the XML, encoding and signature helpers used by the SAML identity provider.
/// </summary>
internal static class OpenIddictServerSamlHelpers
{
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
    /// Loads an XML document using secure settings (no DTD processing, no external resolution).
    /// </summary>
    /// <returns>The document, or <see langword="null"/> if the XML is invalid.</returns>
    public static XmlDocument? LoadDocument(byte[] data, int maximumSize, out bool containsDocumentType)
    {
        containsDocumentType = false;

        var settings = new XmlReaderSettings
        {
            CloseInput = true,
            DtdProcessing = DtdProcessing.Prohibit,
            MaxCharactersFromEntities = 1024,
            MaxCharactersInDocument = maximumSize,
            XmlResolver = null
        };

        try
        {
            using var reader = XmlReader.Create(new MemoryStream(data, writable: false), settings);

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
    /// Parses a raw query string, preserving the raw (still URL-encoded) values needed to validate
    /// redirect binding signatures. Parameters that are not SAML parameters are ignored.
    /// </summary>
    /// <returns>The parameters, or <see langword="null"/> if a SAML parameter is present multiple times.</returns>
    public static Dictionary<string, (string Raw, string Value)>? ParseRedirectQueryString(string? query)
    {
        var parameters = new Dictionary<string, (string Raw, string Value)>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(query))
        {
            return parameters;
        }

        if (query[0] is '?')
        {
            query = query[1..];
        }

        foreach (var segment in query.Split('&'))
        {
            if (segment.Length is 0)
            {
                continue;
            }

            var index = segment.IndexOf('=', StringComparison.Ordinal);
            var name = UrlDecode(index is -1 ? segment : segment[..index]);
            var raw = index is -1 ? string.Empty : segment[(index + 1)..];

            if (name is not (Parameters.SamlRequest or Parameters.RelayState or Parameters.SignatureAlgorithm or Parameters.Signature))
            {
                continue;
            }

            if (parameters.ContainsKey(name))
            {
                return null;
            }

            parameters[name] = (raw, UrlDecode(raw));
        }

        return parameters;

        static string UrlDecode(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));
    }

    /// <summary>
    /// Resolves the hash algorithm corresponding to the specified RSA signature algorithm.
    /// </summary>
    public static HashAlgorithmName? GetHashAlgorithm(string? algorithm) => algorithm switch
    {
        SignatureAlgorithms.RsaSha256 => HashAlgorithmName.SHA256,
        SignatureAlgorithms.RsaSha384 => HashAlgorithmName.SHA384,
        SignatureAlgorithms.RsaSha512 => HashAlgorithmName.SHA512,
        _ => null
    };

    /// <summary>
    /// Determines whether the specified digest algorithm is supported.
    /// </summary>
    public static bool IsSupportedDigestAlgorithm(string? algorithm)
        => algorithm is DigestAlgorithms.Sha256 or DigestAlgorithms.Sha384 or DigestAlgorithms.Sha512;

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
    /// Validates the enveloped XML signature of the root element of a document.
    /// </summary>
    /// <remarks>
    /// To prevent XML signature wrapping attacks, the document must contain exactly one signature, which must be
    /// a direct child of the root element and contain a single reference pointing to the root element, whose
    /// identifier must be unique in the document. Only the root element must then be consumed by the caller.
    /// </remarks>
    [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "Only the built-in RSA, SHA-2, C14N and enveloped signature algorithms, which are statically referenced, are accepted.")]
    [UnconditionalSuppressMessage("AOT", "IL3050", Justification = "XSLT transforms are rejected before the signature is computed or validated.")]
    public static SignatureValidationResult ValidateEnvelopedSignature(XmlElement root, IEnumerable<X509Certificate2> certificates)
    {
        var document = root.OwnerDocument;

        var signatures = document.GetElementsByTagName(Elements.Signature, Namespaces.XmlDsig);
        if (signatures.Count is 0)
        {
            return SignatureValidationResult.Missing;
        }

        if (signatures.Count is not 1 || signatures[0] is not XmlElement signature || !ReferenceEquals(signature.ParentNode, root))
        {
            return SignatureValidationResult.Invalid;
        }

        var identifier = root.GetAttribute("ID");
        if (string.IsNullOrEmpty(identifier) || CountElementsWithIdentifier(document, identifier) is not 1)
        {
            return SignatureValidationResult.Invalid;
        }

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
            xml.SignedInfo.CanonicalizationMethod is not (Transforms.ExclusiveCanonicalization or Transforms.Canonicalization))
        {
            return SignatureValidationResult.UnsupportedAlgorithm;
        }

        foreach (Transform transform in reference.TransformChain)
        {
            if (transform.Algorithm is not (Transforms.EnvelopedSignature or
                Transforms.ExclusiveCanonicalization or Transforms.Canonicalization))
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
                    return SignatureValidationResult.Valid;
                }
            }

            catch (CryptographicException)
            {
                return SignatureValidationResult.Invalid;
            }
        }

        return SignatureValidationResult.Invalid;

        static int CountElementsWithIdentifier(XmlDocument document, string identifier)
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
    }

    /// <summary>
    /// Signs the specified element using an enveloped XML signature inserted after the specified sibling.
    /// </summary>
    [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "Only the built-in RSA, SHA-2, C14N and enveloped signature algorithms, which are statically referenced, are accepted.")]
    [UnconditionalSuppressMessage("AOT", "IL3050", Justification = "XSLT transforms are rejected before the signature is computed or validated.")]
    public static void SignElement(XmlElement element, XmlElement? insertAfter,
        X509Certificate2 certificate, string signatureAlgorithm, string digestAlgorithm)
    {
        var document = element.OwnerDocument;

        using var key = certificate.GetRSAPrivateKey() ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0566));

        var xml = new SignedXml(document) { SigningKey = key };
        xml.SignedInfo!.CanonicalizationMethod = Transforms.ExclusiveCanonicalization;
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

        Insert(element, insertAfter, document.ImportNode(xml.GetXml(), deep: true));

        static void Insert(XmlElement element, XmlElement? insertAfter, XmlNode node)
        {
            if (insertAfter is not null)
            {
                element.InsertAfter(node, insertAfter);
            }

            else
            {
                element.PrependChild(node);
            }
        }
    }

    /// <summary>
    /// Hashes an identifier (SHA-256, base64url) so that it can be safely used as a cache key.
    /// </summary>
    public static string HashIdentifier(string identifier)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(identifier));

        return Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>
    /// Computes the relative lifetime of a cache entry expiring at the specified date. Note: a relative lifetime is used
    /// as caches use the system clock, that may differ from the configured time provider, and reject past expiration dates.
    /// </summary>
    public static TimeSpan GetCacheLifetime(DateTimeOffset expirationDate, DateTimeOffset now)
    {
        var lifetime = expirationDate - now;

        return lifetime > TimeSpan.FromSeconds(1) ? lifetime : TimeSpan.FromSeconds(1);
    }

    /// <summary>
    /// Determines whether the specified data encryption algorithm is supported.
    /// </summary>
    public static bool IsSupportedDataEncryptionAlgorithm(string? algorithm)
        => algorithm is DataEncryptionAlgorithms.Aes256Gcm or DataEncryptionAlgorithms.Aes256Cbc;

    /// <summary>
    /// Determines whether the specified key transport algorithm is supported.
    /// </summary>
    public static bool IsSupportedKeyTransportAlgorithm(string? algorithm)
        => algorithm is KeyTransportAlgorithms.RsaOaepMgf1P or KeyTransportAlgorithms.RsaOaep;

    /// <summary>
    /// Determines whether the specified certificate contains an RSA public key.
    /// </summary>
    public static bool IsRsaCertificate(X509Certificate2 certificate)
        => string.Equals(certificate.PublicKey.Oid.Value, "1.2.840.113549.1.1.1", StringComparison.Ordinal);

    /// <summary>
    /// Creates an xenc:EncryptedData element (XML Encryption 1.1, type Element) containing the specified
    /// serialized element, encrypted using a random AES-256 key transported using the RSA public key of the
    /// certificate in an embedded xenc:EncryptedKey element (SAML core, 6.2).
    /// </summary>
    public static XmlElement CreateEncryptedData(XmlDocument document, byte[] plaintext, X509Certificate2 certificate,
        string dataEncryptionAlgorithm, string keyTransportAlgorithm, string? recipient)
    {
        using var rsa = certificate.GetRSAPublicKey() ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0841));

        var key = RandomNumberGenerator.GetBytes(32);

        try
        {
            var data = document.CreateElement("xenc", Elements.EncryptedData, Namespaces.XmlEnc);
            data.SetAttribute("xmlns:xenc", Namespaces.XmlEnc);
            data.SetAttribute("Type", EncryptedTypes.Element);

            Append(data, "xenc", Elements.EncryptionMethod, Namespaces.XmlEnc).SetAttribute("Algorithm", dataEncryptionAlgorithm);

            var info = Append(data, "ds", Elements.KeyInfo, Namespaces.XmlDsig);
            info.SetAttribute("xmlns:ds", Namespaces.XmlDsig);

            var encryptedKey = Append(info, "xenc", Elements.EncryptedKey, Namespaces.XmlEnc);
            if (!string.IsNullOrEmpty(recipient))
            {
                encryptedKey.SetAttribute("Recipient", recipient);
            }

            var method = Append(encryptedKey, "xenc", Elements.EncryptionMethod, Namespaces.XmlEnc);
            method.SetAttribute("Algorithm", keyTransportAlgorithm);

            RSAEncryptionPadding padding;

            switch (keyTransportAlgorithm)
            {
                // Note: rsa-oaep-mgf1p always uses MGF1 with SHA-1 (XML Encryption 1.1, 5.5.2).
                case KeyTransportAlgorithms.RsaOaepMgf1P:
                    Append(method, "ds", Elements.DigestMethod, Namespaces.XmlDsig).SetAttribute("Algorithm", DigestAlgorithms.Sha1);
                    padding = RSAEncryptionPadding.OaepSHA1;
                    break;

                // Note: .NET uses the same hash algorithm for the OAEP digest and MGF1.
                case KeyTransportAlgorithms.RsaOaep:
                    Append(method, "ds", Elements.DigestMethod, Namespaces.XmlDsig).SetAttribute("Algorithm", DigestAlgorithms.Sha256);

                    var mgf = Append(method, "xenc11", Elements.MaskGenerationFunction, Namespaces.XmlEnc11);
                    mgf.SetAttribute("xmlns:xenc11", Namespaces.XmlEnc11);
                    mgf.SetAttribute("Algorithm", MaskGenerationFunctions.Mgf1Sha256);

                    padding = RSAEncryptionPadding.OaepSHA256;
                    break;

                default: throw new InvalidOperationException(SR.FormatID0842(dataEncryptionAlgorithm, keyTransportAlgorithm));
            }

            var keyInfo = Append(encryptedKey, "ds", Elements.KeyInfo, Namespaces.XmlDsig);
            var x509 = Append(keyInfo, "ds", Elements.X509Data, Namespaces.XmlDsig);
            Append(x509, "ds", Elements.X509Certificate, Namespaces.XmlDsig, Convert.ToBase64String(certificate.RawData));

            var keyCipher = Append(encryptedKey, "xenc", Elements.CipherData, Namespaces.XmlEnc);
            Append(keyCipher, "xenc", Elements.CipherValue, Namespaces.XmlEnc, Convert.ToBase64String(rsa.Encrypt(key, padding)));

            var cipher = Append(data, "xenc", Elements.CipherData, Namespaces.XmlEnc);
            Append(cipher, "xenc", Elements.CipherValue, Namespaces.XmlEnc, Convert.ToBase64String(dataEncryptionAlgorithm switch
            {
                DataEncryptionAlgorithms.Aes256Gcm => EncryptAesGcm(key, plaintext),
                DataEncryptionAlgorithms.Aes256Cbc => EncryptAesCbc(key, plaintext),
                _ => throw new InvalidOperationException(SR.FormatID0842(dataEncryptionAlgorithm, keyTransportAlgorithm))
            }));

            return data;
        }

        finally
        {
            Array.Clear(key, 0, key.Length);
        }

        static XmlElement Append(XmlElement parent, string prefix, string name, string ns, string? text = null)
        {
            var element = parent.OwnerDocument.CreateElement(prefix, name, ns);
            if (text is not null)
            {
                element.AppendChild(parent.OwnerDocument.CreateTextNode(text));
            }

            parent.AppendChild(element);
            return element;
        }

        // Note: the cipher value is the concatenation of the 96-bit IV, the ciphertext
        // and the 128-bit authentication tag (XML Encryption 1.1, 5.2.4).
        static byte[] EncryptAesGcm(byte[] key, byte[] plaintext)
        {
            var result = new byte[12 + plaintext.Length + 16];
            var nonce = RandomNumberGenerator.GetBytes(12);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];

            using (var aes = new AesGcm(key, tagSizeInBytes: 16))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            Buffer.BlockCopy(nonce, 0, result, 0, 12);
            Buffer.BlockCopy(ciphertext, 0, result, 12, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, 12 + ciphertext.Length, 16);

            return result;
        }

        // Note: the cipher value is the concatenation of the 128-bit IV and the ciphertext (XML Encryption 1.1, 5.2.2).
        // PKCS#7 padding is a valid instance of the padding scheme required by XML Encryption.
        static byte[] EncryptAesCbc(byte[] key, byte[] plaintext)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            var ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);

            var result = new byte[aes.IV.Length + ciphertext.Length];
            Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
            Buffer.BlockCopy(ciphertext, 0, result, aes.IV.Length, ciphertext.Length);

            return result;
        }
    }

    /// <summary>
    /// Creates a SAML 2.0 artifact of type 0x0004 (SAML bindings, 3.6.4.2).
    /// </summary>
    /// <param name="entityId">The entity identifier of the issuer, whose SHA-1 hash is used as the SourceID.</param>
    /// <param name="endpointIndex">The index of the artifact resolution service.</param>
    /// <param name="handle">The random message handle.</param>
    public static string CreateArtifact(string entityId, ushort endpointIndex, out byte[] handle)
    {
        handle = RandomNumberGenerator.GetBytes(20);

        var artifact = new byte[44];
        artifact[0] = (byte) (ArtifactTypes.Saml2 >> 8);
        artifact[1] = (byte) ArtifactTypes.Saml2;
        artifact[2] = (byte) (endpointIndex >> 8);
        artifact[3] = (byte) endpointIndex;

        // Note: SHA-1 is mandated by the artifact format to identify the issuer: it is not used as a security control.
#pragma warning disable CA5350
        Buffer.BlockCopy(SHA1.HashData(Encoding.UTF8.GetBytes(entityId)), 0, artifact, 4, 20);
#pragma warning restore CA5350
        Buffer.BlockCopy(handle, 0, artifact, 24, 20);

        return Convert.ToBase64String(artifact);
    }

    /// <summary>
    /// Parses a SAML 2.0 artifact of type 0x0004 issued by the specified entity.
    /// </summary>
    /// <returns>The message handle, or <see langword="null"/> if the artifact is invalid or was not issued by the entity.</returns>
    public static byte[]? ParseArtifact(string? value, string entityId)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 64 || DecodeBase64(value) is not { Length: 44 } artifact)
        {
            return null;
        }

        if (((artifact[0] << 8) | artifact[1]) is not ArtifactTypes.Saml2)
        {
            return null;
        }

#pragma warning disable CA5350
        var source = SHA1.HashData(Encoding.UTF8.GetBytes(entityId));
#pragma warning restore CA5350

        for (var index = 0; index < 20; index++)
        {
            if (artifact[4 + index] != source[index])
            {
                return null;
            }
        }

        var handle = new byte[20];
        Buffer.BlockCopy(artifact, 24, handle, 0, 20);

        return handle;
    }

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
