/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Globalization;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using Parameters = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.Parameters;
using static OpenIddict.Server.Saml.OpenIddictServerSamlHelpers;
using static OpenIddict.Server.Saml.OpenIddictServerSamlModels;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Provides the host-agnostic SAML 2.0 identity provider operations: authentication request validation,
/// response and assertion generation and metadata generation.
/// </summary>
public sealed class OpenIddictServerSamlService
{
    private readonly ILogger<OpenIddictServerSamlService> _logger;
    private readonly IOptionsMonitor<OpenIddictServerSamlOptions> _options;
    private readonly IOpenIddictServerSamlServiceProviderStore _store;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSamlService"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="options">The SAML options.</param>
    /// <param name="store">The service provider store.</param>
    public OpenIddictServerSamlService(
        ILogger<OpenIddictServerSamlService> logger,
        IOptionsMonitor<OpenIddictServerSamlOptions> options,
        IOpenIddictServerSamlServiceProviderStore store)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    /// <summary>
    /// Resolves and validates a service provider using its entity identifier.
    /// </summary>
    /// <param name="entityId">The entity identifier.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The service provider, or <see langword="null"/> if it cannot be found.</returns>
    /// <exception cref="InvalidOperationException">The service provider returned by the store is invalid.</exception>
    public ValueTask<OpenIddictServerSamlServiceProvider?> FindServiceProviderAsync(string entityId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(entityId);

        return ExecuteAsync(entityId, cancellationToken);

        async ValueTask<OpenIddictServerSamlServiceProvider?> ExecuteAsync(string entityId, CancellationToken cancellationToken)
        {
            var provider = await _store.FindByEntityIdAsync(entityId, cancellationToken);
            if (provider is null)
            {
                return null;
            }

            if (!string.Equals(provider.EntityId, entityId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0574));
            }

            OpenIddictServerSamlConfiguration.ValidateServiceProvider(provider);

            return provider;
        }
    }

    /// <summary>
    /// Validates an authentication request sent using the HTTP-Redirect binding.
    /// </summary>
    /// <param name="query">The raw (URL-encoded) query string of the request.</param>
    /// <param name="endpoint">The absolute URL of the single sign-on endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation result.</returns>
    public ValueTask<AuthenticationRequestResult> ValidateRedirectAuthenticationRequestAsync(
        string? query, Uri endpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        return ExecuteAsync(query, endpoint, cancellationToken);

        async ValueTask<AuthenticationRequestResult> ExecuteAsync(string? query, Uri endpoint, CancellationToken cancellationToken)
        {
            var options = _options.CurrentValue;

            var parameters = ParseRedirectQueryString(query);
            if (parameters is null)
            {
                return Reject(SR.ID2259);
            }

            parameters.TryGetValue(Parameters.RelayState, out var state);
            var relayState = parameters.ContainsKey(Parameters.RelayState) ? state.Value : null;

            if (!parameters.TryGetValue(Parameters.SamlRequest, out var request) || string.IsNullOrEmpty(request.Value))
            {
                return Reject(SR.ID2266, relayState: relayState);
            }

            if (request.Value.Length > options.MaximumMessageSize * 2)
            {
                return Reject(SR.ID2247, relayState: relayState);
            }

            if (DecodeBase64(request.Value) is not byte[] compressed)
            {
                return Reject(SR.ID2246, relayState: relayState);
            }

            var data = Inflate(compressed, options.MaximumMessageSize, out bool tooLarge);
            if (data is null)
            {
                return Reject(tooLarge ? SR.ID2247 : SR.ID2246, relayState: relayState);
            }

            SignatureValidationResult? result = null;
            (string Octets, string Algorithm, string Signature)? signature = null;

            if (parameters.TryGetValue(Parameters.Signature, out var value))
            {
                if (!parameters.TryGetValue(Parameters.SignatureAlgorithm, out var algorithm))
                {
                    result = SignatureValidationResult.Invalid;
                }

                else
                {
                    // Note: the signed octets are built from the raw values, as received (SAML bindings, 3.4.4.1).
                    var builder = new StringBuilder()
                        .Append(Parameters.SamlRequest).Append('=').Append(request.Raw);

                    if (parameters.ContainsKey(Parameters.RelayState))
                    {
                        builder.Append('&').Append(Parameters.RelayState).Append('=').Append(state.Raw);
                    }

                    builder.Append('&').Append(Parameters.SignatureAlgorithm).Append('=').Append(algorithm.Raw);

                    signature = (builder.ToString(), algorithm.Value, value.Value);
                }
            }

            else
            {
                result = SignatureValidationResult.Missing;
            }

            return await ValidateAsync(data, Bindings.HttpRedirect, relayState, endpoint, result, signature, cancellationToken);
        }
    }

    /// <summary>
    /// Validates an authentication request sent using the HTTP-POST binding.
    /// </summary>
    /// <param name="request">The SAMLRequest form parameter.</param>
    /// <param name="relayState">The RelayState form parameter, if any.</param>
    /// <param name="endpoint">The absolute URL of the single sign-on endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation result.</returns>
    public ValueTask<AuthenticationRequestResult> ValidatePostAuthenticationRequestAsync(
        string? request, string? relayState, Uri endpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        return ExecuteAsync(request, relayState, endpoint, cancellationToken);

        async ValueTask<AuthenticationRequestResult> ExecuteAsync(
            string? request, string? relayState, Uri endpoint, CancellationToken cancellationToken)
        {
            var options = _options.CurrentValue;

            if (string.IsNullOrEmpty(request))
            {
                return Reject(SR.ID2266, relayState: relayState);
            }

            if (request.Length > options.MaximumMessageSize * 2)
            {
                return Reject(SR.ID2247, relayState: relayState);
            }

            if (DecodeBase64(request) is not byte[] data || data.Length is 0)
            {
                return Reject(SR.ID2246, relayState: relayState);
            }

            if (data.Length > options.MaximumMessageSize)
            {
                return Reject(SR.ID2247, relayState: relayState);
            }

            return await ValidateAsync(data, Bindings.HttpPost, relayState, endpoint, result: null, signature: null, cancellationToken);
        }
    }

    /// <summary>
    /// Validates an identity provider-initiated (unsolicited) single sign-on request.
    /// </summary>
    /// <param name="entityId">The entity identifier of the service provider.</param>
    /// <param name="relayState">The relay state, if any.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation result.</returns>
    public ValueTask<AuthenticationRequestResult> ValidateIdentityProviderInitiatedRequestAsync(
        string? entityId, string? relayState, CancellationToken cancellationToken = default)
    {
        return ExecuteAsync(entityId, relayState, cancellationToken);

        async ValueTask<AuthenticationRequestResult> ExecuteAsync(string? entityId, string? relayState, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(entityId) || await FindServiceProviderAsync(entityId, cancellationToken) is not { } provider)
            {
                return Reject(SR.ID2251, relayState: relayState);
            }

            if (!provider.AllowIdentityProviderInitiatedSingleSignOn)
            {
                return Reject(SR.ID2262, provider, relayState: relayState);
            }

            return new AuthenticationRequestResult
            {
                AssertionConsumerServiceUrl = provider.AssertionConsumerServiceUrls[0],
                CanReturnErrorToServiceProvider = true,
                RelayState = relayState,
                ServiceProvider = provider
            };
        }
    }

    private async ValueTask<AuthenticationRequestResult> ValidateAsync(byte[] data, string binding, string? relayState, Uri endpoint,
        SignatureValidationResult? result, (string Octets, string Algorithm, string Signature)? signature,
        CancellationToken cancellationToken)
    {
        var options = _options.CurrentValue;

        if (LoadDocument(data, options.MaximumMessageSize, out bool containsDocumentType) is not XmlDocument document)
        {
            return Reject(containsDocumentType ? SR.ID2248 : SR.ID2246, relayState: relayState);
        }

        var root = document.DocumentElement!;
        if (!string.Equals(root.LocalName, Elements.AuthnRequest, StringComparison.Ordinal) ||
            !string.Equals(root.NamespaceURI, Namespaces.Protocol, StringComparison.Ordinal) ||
            !string.Equals(root.GetAttribute("Version"), "2.0", StringComparison.Ordinal))
        {
            return Reject(SR.ID2249, relayState: relayState);
        }

        var identifier = root.GetAttribute("ID");
        if (string.IsNullOrEmpty(identifier) || !IsNCName(identifier) ||
            !TryParseInstant(root.GetAttribute("IssueInstant"), out var instant))
        {
            return Reject(SR.ID2249, relayState: relayState);
        }

        var issuers = GetChildElements(root, Elements.Issuer, Namespaces.Assertion);
        if (issuers.Count is not 1 || GetTextContent(issuers[0]) is not { Length: > 0 } issuer)
        {
            return Reject(SR.ID2251, relayState: relayState);
        }

        if (await FindServiceProviderAsync(issuer, cancellationToken) is not { } provider)
        {
            return Reject(SR.ID2251, relayState: relayState);
        }

        // Validate the signature before using any other value of the request.
        if (signature is var (octets, algorithm, value))
        {
            result = ValidateRedirectSignature(octets, algorithm, value, provider.SigningCertificates);
        }

        else if (binding is Bindings.HttpPost)
        {
            result = ValidateEnvelopedSignature(root, provider.SigningCertificates);
        }

        switch (result)
        {
            case SignatureValidationResult.Invalid:
                return Reject(SR.ID2254, provider, relayState);

            case SignatureValidationResult.UnsupportedAlgorithm:
                return Reject(SR.ID2255, provider, relayState);

            case SignatureValidationResult.Missing when provider.RequireSignedAuthenticationRequests:
                return Reject(SR.ID2253, provider, relayState);
        }

        var signed = result is SignatureValidationResult.Valid;

        var now = options.TimeProvider.GetUtcNow();
        if (instant > now + options.ClockSkew || instant < now - options.AuthenticationRequestLifetime - options.ClockSkew)
        {
            return Reject(SR.ID2250, provider, relayState);
        }

        var destination = root.HasAttribute("Destination") ? root.GetAttribute("Destination") : null;
        if ((signed && string.IsNullOrEmpty(destination)) || (destination is not null && !IsSameUrl(destination, endpoint)))
        {
            return Reject(SR.ID2252, provider, relayState);
        }

        // Resolve the assertion consumer service URL, that must correspond to a registered URL.
        var url = root.HasAttribute("AssertionConsumerServiceURL") ? root.GetAttribute("AssertionConsumerServiceURL") : null;
        var index = root.HasAttribute("AssertionConsumerServiceIndex") ? root.GetAttribute("AssertionConsumerServiceIndex") : null;

        Uri? acs = (url, index) switch
        {
            (not null, not null) => null,
            (not null, null) => provider.AssertionConsumerServiceUrls.Find(candidate => IsSameUrl(url, candidate)),
            (null, not null) => int.TryParse(index, NumberStyles.None, CultureInfo.InvariantCulture, out var position) &&
                position < provider.AssertionConsumerServiceUrls.Count ? provider.AssertionConsumerServiceUrls[position] : null,
            _ => provider.AssertionConsumerServiceUrls[0]
        };

        if (acs is null)
        {
            return Reject(SR.ID2256, provider, relayState);
        }

        // From this point, errors can be returned to the service provider.
        if (root.HasAttribute("ProtocolBinding") &&
            !string.Equals(root.GetAttribute("ProtocolBinding"), Bindings.HttpPost, StringComparison.Ordinal))
        {
            return Reject(SR.ID2257, provider, relayState, acs, identifier, StatusCodes.Responder, StatusCodes.UnsupportedBinding);
        }

        if (GetChildElements(root, Elements.Subject, Namespaces.Assertion).Count is not 0)
        {
            return Reject(SR.ID2265, provider, relayState, acs, identifier, StatusCodes.Requester, StatusCodes.RequestUnsupported);
        }

        string? format = null;

        var policies = GetChildElements(root, Elements.NameIdPolicy, Namespaces.Protocol);
        if (policies.Count > 1)
        {
            return Reject(SR.ID2249, provider, relayState, acs, identifier, StatusCodes.Requester);
        }

        if (policies.Count is 1 && policies[0].HasAttribute("Format"))
        {
            format = policies[0].GetAttribute("Format");

            if (format is not NameIdFormats.Unspecified && !string.Equals(format, provider.NameIdFormat, StringComparison.Ordinal))
            {
                return Reject(SR.ID2258, provider, relayState, acs, identifier, StatusCodes.Requester, StatusCodes.InvalidNameIdPolicy);
            }
        }

        if (!TryParseBoolean(root, "ForceAuthn", out var force) || !TryParseBoolean(root, "IsPassive", out var passive))
        {
            return Reject(SR.ID2249, provider, relayState, acs, identifier, StatusCodes.Requester);
        }

        return new AuthenticationRequestResult
        {
            AssertionConsumerServiceUrl = acs,
            CanReturnErrorToServiceProvider = true,
            RelayState = relayState,
            RequestId = identifier,
            Request = new AuthenticationRequest
            {
                Binding = binding,
                Destination = destination,
                ForceAuthentication = force,
                Id = identifier,
                IsPassive = passive,
                IssueInstant = instant,
                Issuer = issuer,
                IsSigned = signed,
                NameIdFormat = format
            },
            ServiceProvider = provider
        };

        static bool IsNCName(string value)
        {
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

        static bool TryParseBoolean(XmlElement element, string name, out bool value)
        {
            value = false;

            if (!element.HasAttribute(name))
            {
                return true;
            }

            switch (element.GetAttribute(name).Trim())
            {
                case "true" or "1":
                    value = true;
                    return true;

                case "false" or "0":
                    return true;

                default: return false;
            }
        }
    }

    private AuthenticationRequestResult Reject(string description, OpenIddictServerSamlServiceProvider? provider = null,
        string? relayState = null, Uri? acs = null, string? identifier = null,
        string status = StatusCodes.Requester, string? secondLevelStatus = null)
    {
        var message = SR.GetResourceString(description);

        _logger.LogInformation(6324, SR.GetResourceString(SR.ID6324), message);

        return new AuthenticationRequestResult
        {
            AssertionConsumerServiceUrl = acs,
            CanReturnErrorToServiceProvider = acs is not null,
            ErrorDescription = message,
            RelayState = relayState,
            RequestId = identifier,
            SecondLevelStatus = secondLevelStatus,
            ServiceProvider = provider,
            Status = status
        };
    }

    /// <summary>
    /// Creates a SAML response containing a signed assertion (for successful responses) or an error status.
    /// </summary>
    /// <param name="descriptor">The response descriptor.</param>
    /// <returns>The serialized XML response (not base64-encoded).</returns>
    public string CreateResponse(ResponseDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);

        var options = _options.CurrentValue;
        var provider = descriptor.ServiceProvider;

        if (descriptor.Assertion is not null && string.IsNullOrEmpty(descriptor.Assertion.NameId))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0575));
        }

        var certificate = GetSigningCertificate(options);
        var now = options.TimeProvider.GetUtcNow();
        var acs = descriptor.AssertionConsumerServiceUrl.AbsoluteUri;

        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };

        var response = document.CreateElement("samlp", Elements.Response, Namespaces.Protocol);
        response.SetAttribute("xmlns:saml", Namespaces.Assertion);
        response.SetAttribute("ID", CreateIdentifier());
        response.SetAttribute("Version", "2.0");
        response.SetAttribute("IssueInstant", FormatInstant(now));
        response.SetAttribute("Destination", acs);

        if (!string.IsNullOrEmpty(descriptor.InResponseTo))
        {
            response.SetAttribute("InResponseTo", descriptor.InResponseTo);
        }

        document.AppendChild(response);

        var issuer = AppendElement(response, "saml", Elements.Issuer, Namespaces.Assertion, options.EntityId);

        var status = AppendElement(response, "samlp", Elements.Status, Namespaces.Protocol);
        var code = AppendElement(status, "samlp", Elements.StatusCode, Namespaces.Protocol);
        code.SetAttribute("Value", descriptor.Assertion is null ? descriptor.Status : StatusCodes.Success);

        if (descriptor.Assertion is null && !string.IsNullOrEmpty(descriptor.SecondLevelStatus))
        {
            AppendElement(code, "samlp", Elements.StatusCode, Namespaces.Protocol).SetAttribute("Value", descriptor.SecondLevelStatus);
        }

        if (descriptor.Assertion is null && !string.IsNullOrEmpty(descriptor.StatusMessage))
        {
            AppendElement(status, "samlp", Elements.StatusMessage, Namespaces.Protocol, descriptor.StatusMessage);
        }

        if (descriptor.Assertion is AssertionDescriptor assertion)
        {
            var expiration = now + (provider.AssertionLifetime ?? options.AssertionLifetime);

            var element = AppendElement(response, "saml", Elements.Assertion, Namespaces.Assertion);
            element.SetAttribute("ID", CreateIdentifier());
            element.SetAttribute("Version", "2.0");
            element.SetAttribute("IssueInstant", FormatInstant(now));

            var assertionIssuer = AppendElement(element, "saml", Elements.Issuer, Namespaces.Assertion, options.EntityId);

            var subject = AppendElement(element, "saml", Elements.Subject, Namespaces.Assertion);
            var name = AppendElement(subject, "saml", Elements.NameId, Namespaces.Assertion, assertion.NameId);
            name.SetAttribute("Format", assertion.NameIdFormat);

            var confirmation = AppendElement(subject, "saml", Elements.SubjectConfirmation, Namespaces.Assertion);
            confirmation.SetAttribute("Method", ConfirmationMethods.Bearer);

            var data = AppendElement(confirmation, "saml", Elements.SubjectConfirmationData, Namespaces.Assertion);
            if (!string.IsNullOrEmpty(descriptor.InResponseTo))
            {
                data.SetAttribute("InResponseTo", descriptor.InResponseTo);
            }

            data.SetAttribute("NotOnOrAfter", FormatInstant(expiration));
            data.SetAttribute("Recipient", acs);

            var conditions = AppendElement(element, "saml", Elements.Conditions, Namespaces.Assertion);
            conditions.SetAttribute("NotBefore", FormatInstant(now));
            conditions.SetAttribute("NotOnOrAfter", FormatInstant(expiration));

            var restriction = AppendElement(conditions, "saml", Elements.AudienceRestriction, Namespaces.Assertion);
            AppendElement(restriction, "saml", Elements.Audience, Namespaces.Assertion, provider.EntityId);

            var statement = AppendElement(element, "saml", Elements.AuthnStatement, Namespaces.Assertion);
            statement.SetAttribute("AuthnInstant", FormatInstant(assertion.AuthenticationInstant ?? now));

            if (!string.IsNullOrEmpty(assertion.SessionIndex))
            {
                statement.SetAttribute("SessionIndex", assertion.SessionIndex);
            }

            var context = AppendElement(statement, "saml", Elements.AuthnContext, Namespaces.Assertion);
            AppendElement(context, "saml", Elements.AuthnContextClassRef, Namespaces.Assertion, assertion.AuthenticationContextClass);

            if (assertion.Attributes.Count is not 0)
            {
                var attributes = AppendElement(element, "saml", Elements.AttributeStatement, Namespaces.Assertion);

                foreach (var attribute in assertion.Attributes)
                {
                    var node = AppendElement(attributes, "saml", Elements.Attribute, Namespaces.Assertion);
                    node.SetAttribute("Name", attribute.Name);
                    node.SetAttribute("NameFormat", attribute.NameFormat);

                    foreach (var value in attribute.Values)
                    {
                        AppendElement(node, "saml", Elements.AttributeValue, Namespaces.Assertion, value);
                    }
                }
            }

            SignElement(element, assertionIssuer, certificate, options.SignatureAlgorithm, options.DigestAlgorithm);

            _logger.LogInformation(6325, SR.GetResourceString(SR.ID6325), provider.EntityId);
        }

        else
        {
            _logger.LogInformation(6326, SR.GetResourceString(SR.ID6326), descriptor.Status, provider.EntityId, descriptor.StatusMessage);
        }

        // Note: error responses are always signed, as they don't contain a signed assertion.
        if (descriptor.Assertion is null || (provider.SignResponses ?? options.SignResponses))
        {
            SignElement(response, issuer, certificate, options.SignatureAlgorithm, options.DigestAlgorithm);
        }

        return document.OuterXml;
    }

    /// <summary>
    /// Creates the metadata document (EntityDescriptor) of the identity provider.
    /// </summary>
    /// <param name="endpoint">The absolute URL of the single sign-on endpoint.</param>
    /// <returns>The serialized XML metadata.</returns>
    public string CreateMetadata(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        var options = _options.CurrentValue;

        var document = new XmlDocument { XmlResolver = null };

        var descriptor = document.CreateElement("md", Elements.EntityDescriptor, Namespaces.Metadata);
        descriptor.SetAttribute("entityID", options.EntityId);
        document.AppendChild(descriptor);

        var idp = AppendElement(descriptor, "md", Elements.IdpSsoDescriptor, Namespaces.Metadata);
        idp.SetAttribute("WantAuthnRequestsSigned", options.ServiceProviders.TrueForAll(
            static provider => provider.RequireSignedAuthenticationRequests) ? "true" : "false");
        idp.SetAttribute("protocolSupportEnumeration", Namespaces.Protocol);

        foreach (var certificate in options.SigningCertificates)
        {
            var key = AppendElement(idp, "md", Elements.KeyDescriptor, Namespaces.Metadata);
            key.SetAttribute("use", "signing");

            var info = AppendElement(key, "ds", Elements.KeyInfo, Namespaces.XmlDsig);
            var data = AppendElement(info, "ds", Elements.X509Data, Namespaces.XmlDsig);
            AppendElement(data, "ds", Elements.X509Certificate, Namespaces.XmlDsig, Convert.ToBase64String(certificate.RawData));
        }

        foreach (var format in (string[]) [NameIdFormats.EmailAddress, NameIdFormats.Persistent, NameIdFormats.Transient, NameIdFormats.Unspecified])
        {
            AppendElement(idp, "md", Elements.NameIdFormat, Namespaces.Metadata, format);
        }

        foreach (var binding in (string[]) [Bindings.HttpRedirect, Bindings.HttpPost])
        {
            var service = AppendElement(idp, "md", Elements.SingleSignOnService, Namespaces.Metadata);
            service.SetAttribute("Binding", binding);
            service.SetAttribute("Location", endpoint.AbsoluteUri);
        }

        return document.OuterXml;
    }

    /// <summary>
    /// Creates an HTML page automatically posting the SAML response to the assertion consumer service.
    /// </summary>
    /// <param name="url">The assertion consumer service URL.</param>
    /// <param name="response">The serialized XML response returned by <see cref="CreateResponse(ResponseDescriptor)"/>.</param>
    /// <param name="relayState">The relay state, if any.</param>
    /// <param name="nonce">The nonce attached to the inline script (that must be allowed by the content security policy).</param>
    /// <returns>The HTML page.</returns>
    public static string CreateFormPostPage(Uri url, string response, string? relayState, string nonce)
    {
        ArgumentNullException.ThrowIfNull(url);
        ArgumentException.ThrowIfNullOrEmpty(response);
        ArgumentException.ThrowIfNullOrEmpty(nonce);

        var builder = new StringBuilder()
            .Append("<!doctype html><html><head><meta charset=\"utf-8\" /><title>Working...</title></head><body>")
            .Append("<form id=\"saml\" method=\"post\" action=\"").Append(WebUtility.HtmlEncode(url.AbsoluteUri)).Append("\">")
            .Append("<input type=\"hidden\" name=\"").Append(Parameters.SamlResponse).Append("\" value=\"")
            .Append(WebUtility.HtmlEncode(Convert.ToBase64String(Encoding.UTF8.GetBytes(response)))).Append("\" />");

        if (relayState is not null)
        {
            builder.Append("<input type=\"hidden\" name=\"").Append(Parameters.RelayState).Append("\" value=\"")
                   .Append(WebUtility.HtmlEncode(relayState)).Append("\" />");
        }

        return builder
            .Append("<noscript><button type=\"submit\">Continue</button></noscript></form>")
            .Append("<script nonce=\"").Append(WebUtility.HtmlEncode(nonce)).Append("\">document.getElementById('saml').submit();</script>")
            .Append("</body></html>")
            .ToString();
    }

    private static X509Certificate2 GetSigningCertificate(OpenIddictServerSamlOptions options)
    {
        var now = options.TimeProvider.GetUtcNow().UtcDateTime;

        return options.SigningCertificates.Find(certificate => certificate.HasPrivateKey &&
                   certificate.NotBefore.ToUniversalTime() <= now && certificate.NotAfter.ToUniversalTime() >= now) ??
               options.SigningCertificates.Find(static certificate => certificate.HasPrivateKey) ??
               throw new InvalidOperationException(SR.GetResourceString(SR.ID0566));
    }

    private static XmlElement AppendElement(XmlElement parent, string prefix, string name, string ns, string? text = null)
    {
        var element = parent.OwnerDocument.CreateElement(prefix, name, ns);

        if (text is not null)
        {
            element.AppendChild(parent.OwnerDocument.CreateTextNode(text));
        }

        parent.AppendChild(element);

        return element;
    }

    private static bool IsSameUrl(string value, Uri url)
        => Uri.TryCreate(value, UriKind.Absolute, out var candidate) &&
           Uri.Compare(candidate, url, UriComponents.AbsoluteUri, UriFormat.UriEscaped, StringComparison.Ordinal) is 0;

    private static bool TryParseInstant(string value, out DateTimeOffset instant)
    {
        instant = default;

        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        try
        {
            instant = XmlConvert.ToDateTimeOffset(value);
            return true;
        }

        catch (FormatException)
        {
            return false;
        }
    }
}
