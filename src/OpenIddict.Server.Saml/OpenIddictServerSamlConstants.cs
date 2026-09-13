/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server.Saml;

/// <summary>
/// Exposes common constants used by the OpenIddict SAML 2.0 identity provider components.
/// </summary>
public static class OpenIddictServerSamlConstants
{
    public static class Bindings
    {
        public const string HttpPost = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
        public const string HttpRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    }

    public static class AuthenticationContextClasses
    {
        public const string PasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
        public const string Unspecified = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
    }

    public static class AttributeNameFormats
    {
        public const string Basic = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
        public const string Unspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";
        public const string Uri = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
    }

    public static class ConfirmationMethods
    {
        public const string Bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    }

    public static class DigestAlgorithms
    {
        public const string Sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
        public const string Sha384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
        public const string Sha512 = "http://www.w3.org/2001/04/xmlenc#sha512";
    }

    public static class Elements
    {
        public const string Assertion = "Assertion";
        public const string AssertionConsumerService = "AssertionConsumerService";
        public const string Attribute = "Attribute";
        public const string AttributeStatement = "AttributeStatement";
        public const string AttributeValue = "AttributeValue";
        public const string Audience = "Audience";
        public const string AudienceRestriction = "AudienceRestriction";
        public const string AuthnContext = "AuthnContext";
        public const string AuthnContextClassRef = "AuthnContextClassRef";
        public const string AuthnRequest = "AuthnRequest";
        public const string AuthnStatement = "AuthnStatement";
        public const string Conditions = "Conditions";
        public const string EntityDescriptor = "EntityDescriptor";
        public const string IdpSsoDescriptor = "IDPSSODescriptor";
        public const string Issuer = "Issuer";
        public const string KeyDescriptor = "KeyDescriptor";
        public const string KeyInfo = "KeyInfo";
        public const string NameId = "NameID";
        public const string NameIdFormat = "NameIDFormat";
        public const string NameIdPolicy = "NameIDPolicy";
        public const string Response = "Response";
        public const string Signature = "Signature";
        public const string SingleSignOnService = "SingleSignOnService";
        public const string Status = "Status";
        public const string StatusCode = "StatusCode";
        public const string StatusMessage = "StatusMessage";
        public const string Subject = "Subject";
        public const string SubjectConfirmation = "SubjectConfirmation";
        public const string SubjectConfirmationData = "SubjectConfirmationData";
        public const string X509Certificate = "X509Certificate";
        public const string X509Data = "X509Data";
    }

    public static class MediaTypes
    {
        public const string Metadata = "application/samlmetadata+xml";
    }

    public static class NameIdFormats
    {
        public const string EmailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
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
    }

    public static class Parameters
    {
        public const string RelayState = "RelayState";
        public const string SamlRequest = "SAMLRequest";
        public const string SamlResponse = "SAMLResponse";
        public const string ServiceProvider = "sp";
        public const string Signature = "Signature";
        public const string SignatureAlgorithm = "SigAlg";
        public const string State = "openiddict_saml_state";
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
        public const string InvalidNameIdPolicy = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy";
        public const string NoPassive = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
        public const string Requester = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        public const string RequestDenied = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";
        public const string RequestUnsupported = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported";
        public const string Responder = "urn:oasis:names:tc:SAML:2.0:status:Responder";
        public const string Success = "urn:oasis:names:tc:SAML:2.0:status:Success";
        public const string UnsupportedBinding = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding";
        public const string VersionMismatch = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
    }

    public static class Transforms
    {
        public const string Canonicalization = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
        public const string EnvelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
        public const string ExclusiveCanonicalization = "http://www.w3.org/2001/10/xml-exc-c14n#";
    }
}
