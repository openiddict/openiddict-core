/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using static OpenIddict.Client.Saml.OpenIddictClientSamlConstants;
using static OpenIddict.Extensions.OpenIddictSamlHelpers;

namespace OpenIddict.Client.Saml;

/// <summary>
/// Decrypts XML Encryption (1.0/1.1) elements, such as SAML encrypted assertions and identifiers.
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><description>
///     Only RSA-OAEP key transport is supported (RSA 1.5 is rejected to prevent Bleichenbacher attacks) with
///     AES-CBC or AES-GCM (AES-GCM is only supported on .NET). Only inline CipherValue elements are accepted:
///     CipherReference, RetrievalMethod and any other form of external resolution are never used.
///   </description></item>
///   <item><description>
///     Every failure is reported identically (<see langword="null"/>) to avoid exposing a decryption oracle.
///   </description></item>
/// </list>
/// </remarks>
internal static class OpenIddictClientSamlDecryptor
{
    /// <summary>
    /// Decrypts the EncryptedData element contained in the specified element (e.g saml:EncryptedAssertion).
    /// </summary>
    /// <param name="container">The element containing the xenc:EncryptedData element and, optionally, xenc:EncryptedKey elements.</param>
    /// <param name="certificates">The decryption certificates.</param>
    /// <param name="maximumSize">The maximum size of the decrypted document.</param>
    /// <returns>The decrypted element, loaded as the root of a new document, or <see langword="null"/> if it cannot be decrypted.</returns>
    public static XmlElement? Decrypt(XmlElement container, IEnumerable<X509Certificate2> certificates, int maximumSize)
    {
        var data = GetChildElements(container, "EncryptedData", Namespaces.XmlEnc);
        if (data.Count is not 1 || GetAlgorithm(data[0]) is not { Length: > 0 } algorithm ||
            GetCipherValue(data[0]) is not byte[] ciphertext)
        {
            return null;
        }

        List<XmlElement> keys = [];

        foreach (var info in GetChildElements(data[0], "KeyInfo", Namespaces.XmlDsig))
        {
            keys.AddRange(GetChildElements(info, "EncryptedKey", Namespaces.XmlEnc));
        }

        // Note: the SAML 2.0 core specification (2.2.4) allows EncryptedKey elements to be siblings of EncryptedData.
        keys.AddRange(GetChildElements(container, "EncryptedKey", Namespaces.XmlEnc));

        foreach (var key in keys)
        {
            if (GetAlgorithm(key) is not { Length: > 0 } transport || GetKeyTransportPadding(key, transport) is not RSAEncryptionPadding padding ||
                GetCipherValue(key) is not byte[] wrapped)
            {
                continue;
            }

            foreach (var certificate in certificates)
            {
                using var rsa = certificate.GetRSAPrivateKey();
                if (rsa is null)
                {
                    continue;
                }

                byte[] secret;

                try
                {
                    secret = rsa.Decrypt(wrapped, padding);
                }

                catch (CryptographicException)
                {
                    continue;
                }

                if (DecryptData(algorithm, secret, ciphertext) is byte[] plaintext &&
                    Load(plaintext, data[0].ParentNode!, maximumSize) is XmlElement element)
                {
                    return element;
                }
            }
        }

        return null;
    }

    private static string? GetAlgorithm(XmlElement element)
        => GetChildElements(element, "EncryptionMethod", Namespaces.XmlEnc) is [XmlElement method]
            ? method.GetAttribute("Algorithm") : null;

    private static byte[]? GetCipherValue(XmlElement element)
    {
        if (GetChildElements(element, "CipherData", Namespaces.XmlEnc) is not [XmlElement data] ||
            GetChildElements(data, "CipherValue", Namespaces.XmlEnc) is not [XmlElement value] ||
            GetTextContent(value) is not { Length: > 0 } text)
        {
            return null;
        }

        // Note: base64 values in XML documents can contain whitespace (e.g line breaks).
        return DecodeBase64(RemoveWhitespace(text));

        static string RemoveWhitespace(string value)
        {
            var buffer = new char[value.Length];
            var length = 0;

            foreach (var character in value)
            {
                if (!char.IsWhiteSpace(character))
                {
                    buffer[length++] = character;
                }
            }

            return new string(buffer, 0, length);
        }
    }

    private static RSAEncryptionPadding? GetKeyTransportPadding(XmlElement key, string algorithm)
    {
        var method = GetChildElements(key, "EncryptionMethod", Namespaces.XmlEnc)[0];

        var digest = GetChildElements(method, "DigestMethod", Namespaces.XmlDsig) switch
        {
            [] => DigestAlgorithms.Sha1,
            [XmlElement element] => element.GetAttribute("Algorithm"),
            _ => null
        };

        var mgf = GetChildElements(method, "MGF", Namespaces.XmlEnc11) switch
        {
            [] => MaskGenerationFunctions.Mgf1Sha1,
            [XmlElement element] => element.GetAttribute("Algorithm"),
            _ => null
        };

        // Note: .NET only supports OAEP when the same hash algorithm is used for the digest and the mask generation function.
        return (algorithm, digest, mgf) switch
        {
            (KeyTransportAlgorithms.RsaOaepMgf1p, DigestAlgorithms.Sha1, MaskGenerationFunctions.Mgf1Sha1) => RSAEncryptionPadding.OaepSHA1,

            (KeyTransportAlgorithms.RsaOaep, DigestAlgorithms.Sha1,   MaskGenerationFunctions.Mgf1Sha1)   => RSAEncryptionPadding.OaepSHA1,
            (KeyTransportAlgorithms.RsaOaep, DigestAlgorithms.Sha256, MaskGenerationFunctions.Mgf1Sha256) => RSAEncryptionPadding.OaepSHA256,
            (KeyTransportAlgorithms.RsaOaep, DigestAlgorithms.Sha384, MaskGenerationFunctions.Mgf1Sha384) => RSAEncryptionPadding.OaepSHA384,
            (KeyTransportAlgorithms.RsaOaep, DigestAlgorithms.Sha512, MaskGenerationFunctions.Mgf1Sha512) => RSAEncryptionPadding.OaepSHA512,

            _ => null
        };
    }

    private static byte[]? DecryptData(string algorithm, byte[] key, byte[] ciphertext)
    {
        switch (algorithm)
        {
            case EncryptionAlgorithms.Aes128Cbc when key.Length is 16:
            case EncryptionAlgorithms.Aes192Cbc when key.Length is 24:
            case EncryptionAlgorithms.Aes256Cbc when key.Length is 32:
                return DecryptCbc(key, ciphertext);

#if NET
            case EncryptionAlgorithms.Aes128Gcm when key.Length is 16:
            case EncryptionAlgorithms.Aes192Gcm when key.Length is 24:
            case EncryptionAlgorithms.Aes256Gcm when key.Length is 32:
                return DecryptGcm(key, ciphertext);
#endif
            default: return null;
        }

        static byte[]? DecryptCbc(byte[] key, byte[] ciphertext)
        {
            // XML Encryption 1.0, 5.2.1: the IV is prepended to the ciphertext.
            if (ciphertext.Length < 32 || ciphertext.Length % 16 is not 0)
            {
                return null;
            }

            using var aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;

            var iv = new byte[16];
            Buffer.BlockCopy(ciphertext, 0, iv, 0, 16);
            aes.IV = iv;

            byte[] plaintext;

            try
            {
                using var decryptor = aes.CreateDecryptor();
                plaintext = decryptor.TransformFinalBlock(ciphertext, 16, ciphertext.Length - 16);
            }

            catch (CryptographicException)
            {
                return null;
            }

            // XML Encryption 1.0, 5.2: the padding octets are arbitrary, except the last one, that contains the padding length.
            var padding = plaintext[^1];
            if (padding is 0 or > 16 || padding > plaintext.Length)
            {
                return null;
            }

            var result = new byte[plaintext.Length - padding];
            Buffer.BlockCopy(plaintext, 0, result, 0, result.Length);

            return result;
        }

#if NET
        static byte[]? DecryptGcm(byte[] key, byte[] ciphertext)
        {
            // XML Encryption 1.1, 5.2.4: the 96-bit IV is prepended and the 128-bit tag is appended to the ciphertext.
            if (ciphertext.Length < 12 + 16)
            {
                return null;
            }

            var nonce = ciphertext.AsSpan(0, 12);
            var tag = ciphertext.AsSpan(ciphertext.Length - 16);
            var content = ciphertext.AsSpan(12, ciphertext.Length - 12 - 16);
            var plaintext = new byte[content.Length];

            try
            {
                using var aes = new AesGcm(key, tagSizeInBytes: 16);
                aes.Decrypt(nonce, content, tag, plaintext);
            }

            catch (CryptographicException)
            {
                return null;
            }

            return plaintext;
        }
#endif
    }

    private static XmlElement? Load(byte[] plaintext, XmlNode context, int maximumSize)
    {
        var table = new NameTable();
        var manager = new XmlNamespaceManager(table);

        // Note: the decrypted content is an XML fragment serialized in the context of the EncryptedData element
        // (XML Encryption 1.0, 4.5): the namespace declarations in scope for this element must be resolvable.
        var ancestors = new List<XmlElement>();
        for (var node = context; node is XmlElement element; node = node.ParentNode)
        {
            ancestors.Add(element);
        }

        for (var index = ancestors.Count - 1; index >= 0; index--)
        {
            manager.PushScope();

            foreach (XmlAttribute attribute in ancestors[index].Attributes)
            {
                if (string.Equals(attribute.NamespaceURI, XmlnsNamespace, StringComparison.Ordinal))
                {
                    manager.AddNamespace(attribute.Prefix.Length is 0 ? string.Empty : attribute.LocalName, attribute.Value);
                }
            }
        }

        var document = new XmlDocument(table) { PreserveWhitespace = true, XmlResolver = null };

        try
        {
            using var reader = XmlReader.Create(new MemoryStream(plaintext, writable: false),
                CreateReaderSettings(maximumSize, ConformanceLevel.Fragment),
                new XmlParserContext(table, manager, xmlLang: null, XmlSpace.None));

            XmlElement? result = null;

            while (document.ReadNode(reader) is XmlNode node)
            {
                switch (node.NodeType)
                {
                    case XmlNodeType.Element when result is null:
                        result = (XmlElement) node;
                        break;

                    case XmlNodeType.Whitespace or XmlNodeType.SignificantWhitespace or XmlNodeType.Comment or XmlNodeType.XmlDeclaration:
                        break;

                    default: return null;
                }
            }

            if (result is null)
            {
                return null;
            }

            document.AppendChild(result);
            CopyInScopeNamespaces(context, result);

            return result;
        }

        catch (XmlException)
        {
            return null;
        }
    }
}
