/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.Saml;

/// <summary>
/// Exposes common constants used by the OpenIddict SAML 2.0 service provider components.
/// </summary>
public static class OpenIddictClientSamlConstants
{
    /// <summary>
    /// Gets the authentication type attached to the identities created from SAML assertions.
    /// </summary>
    public const string AuthenticationType = "OpenIddict.Client.Saml";

    public static class Bindings
    {
        public const string HttpPost = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
        public const string HttpRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    }

    public static class Claims
    {
        public const string AuthenticationContextClass = "saml_authn_context_class";
        public const string NameIdFormat = "saml_name_id_format";
        public const string SessionIndex = "saml_session_index";
    }

    public static class DigestAlgorithms
    {
        public const string Sha1 = "http://www.w3.org/2000/09/xmldsig#sha1";
        public const string Sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
        public const string Sha384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
        public const string Sha512 = "http://www.w3.org/2001/04/xmlenc#sha512";
    }

    public static class EncryptionAlgorithms
    {
        public const string Aes128Cbc = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
        public const string Aes192Cbc = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
        public const string Aes256Cbc = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
        public const string Aes128Gcm = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
        public const string Aes192Gcm = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
        public const string Aes256Gcm = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
    }

    public static class KeyTransportAlgorithms
    {
        public const string RsaOaep = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
        public const string RsaOaepMgf1p = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
    }

    public static class MaskGenerationFunctions
    {
        public const string Mgf1Sha1 = "http://www.w3.org/2009/xmlenc11#mgf1sha1";
        public const string Mgf1Sha256 = "http://www.w3.org/2009/xmlenc11#mgf1sha256";
        public const string Mgf1Sha384 = "http://www.w3.org/2009/xmlenc11#mgf1sha384";
        public const string Mgf1Sha512 = "http://www.w3.org/2009/xmlenc11#mgf1sha512";
    }

    public static class MediaTypes
    {
        public const string Metadata = "application/samlmetadata+xml";
    }

    public static class NameIdFormats
    {
        public const string EmailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
        public const string Entity = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
        public const string Persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
        public const string Transient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
        public const string Unspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
    }

    public static class Namespaces
    {
        public const string Assertion = "urn:oasis:names:tc:SAML:2.0:assertion";
        public const string Metadata = "urn:oasis:names:tc:SAML:2.0:metadata";
        public const string Protocol = "urn:oasis:names:tc:SAML:2.0:protocol";
        public const string XmlDsig = "http://www.w3.org/2000/09/xmldsig#";
        public const string XmlEnc = "http://www.w3.org/2001/04/xmlenc#";
        public const string XmlEnc11 = "http://www.w3.org/2009/xmlenc11#";
    }

    public static class Parameters
    {
        public const string RelayState = "RelayState";
        public const string SamlRequest = "SAMLRequest";
        public const string SamlResponse = "SAMLResponse";
        public const string Signature = "Signature";
        public const string SignatureAlgorithm = "SigAlg";
    }

    public static class Properties
    {
        public const string ProviderName = ".saml_provider_name";
        public const string RegistrationId = ".saml_registration_id";
    }

    public static class SignatureAlgorithms
    {
        public const string RsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        public const string RsaSha384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
        public const string RsaSha512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    }

    public static class StatusCodes
    {
        public const string AuthnFailed = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
        public const string NoPassive = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
        public const string Requester = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        public const string RequestDenied = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";
        public const string Responder = "urn:oasis:names:tc:SAML:2.0:status:Responder";
        public const string Success = "urn:oasis:names:tc:SAML:2.0:status:Success";
        public const string VersionMismatch = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
    }
}
