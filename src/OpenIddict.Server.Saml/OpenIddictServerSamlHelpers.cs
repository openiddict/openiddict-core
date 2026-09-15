/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using static OpenIddict.Extensions.OpenIddictSamlHelpers;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using Parameters = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.Parameters;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Contains the helpers specific to the SAML identity provider (the generic XML, encoding
/// and signature helpers are shared with the service provider in <c>OpenIddictSamlHelpers</c>).
/// </summary>
internal static class OpenIddictServerSamlHelpers
{
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

            if (name is not (Parameters.SamlRequest or Parameters.SamlResponse or Parameters.RelayState or
                             Parameters.SignatureAlgorithm or Parameters.Signature))
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
    /// Validates the enveloped XML signature of the root element of a document.
    /// </summary>
    /// <remarks>
    /// In addition to the rules enforced by <c>OpenIddictSamlHelpers.ValidateEnvelopedSignature()</c>,
    /// the document must contain exactly one signature, which must be a direct child of the root element.
    /// </remarks>
    public static SignatureValidationResult ValidateRootSignature(XmlElement root, IEnumerable<X509Certificate2> certificates)
        => ValidateSingleSignature(root, certificates, requireDocumentElement: true);

    /// <summary>
    /// Validates the enveloped XML signature of a message element that may be embedded in
    /// another document (e.g. a SOAP envelope): the document must contain exactly one
    /// signature, which must be a direct child of the message element.
    /// </summary>
    public static SignatureValidationResult ValidateMessageSignature(XmlElement element, IEnumerable<X509Certificate2> certificates)
        => ValidateSingleSignature(element, certificates, requireDocumentElement: false);

    private static SignatureValidationResult ValidateSingleSignature(XmlElement element,
        IEnumerable<X509Certificate2> certificates, bool requireDocumentElement)
    {
        var signatures = element.OwnerDocument.GetElementsByTagName(Elements.Signature, Namespaces.XmlDsig);
        if (signatures.Count is 0)
        {
            return SignatureValidationResult.Missing;
        }

        if (signatures.Count is not 1 || signatures[0] is not XmlElement signature ||
            !ReferenceEquals(signature.ParentNode, element) ||
            (requireDocumentElement && !ReferenceEquals(element.OwnerDocument.DocumentElement, element)))
        {
            return SignatureValidationResult.Invalid;
        }

        return ValidateEnvelopedSignature(element, certificates, out _);
    }

    /// <summary>
    /// Signs the specified element using an enveloped XML signature inserted after the specified sibling.
    /// </summary>
    public static void SignElement(XmlElement element, XmlElement? insertAfter,
        X509Certificate2 certificate, string signatureAlgorithm, string digestAlgorithm)
    {
        using var key = certificate.GetRSAPrivateKey() ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0566));

        OpenIddict.Extensions.OpenIddictSamlHelpers.SignElement(element, insertAfter, certificate, key, signatureAlgorithm, digestAlgorithm);
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
}
