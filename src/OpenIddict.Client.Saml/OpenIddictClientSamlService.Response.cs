/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using static OpenIddict.Client.Saml.OpenIddictClientSamlConstants;
using static OpenIddict.Client.Saml.OpenIddictClientSamlModels;
using static OpenIddict.Extensions.OpenIddictSamlHelpers;
using Claims = OpenIddict.Abstractions.OpenIddictConstants.Claims;
using SamlClaims = OpenIddict.Client.Saml.OpenIddictClientSamlConstants.Claims;
using StatusCodes = OpenIddict.Client.Saml.OpenIddictClientSamlConstants.StatusCodes;

namespace OpenIddict.Client.Saml;

public sealed partial class OpenIddictClientSamlService
{
    private const string BearerConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

    /// <summary>
    /// Validates a SAML response received by the assertion consumer service using the HTTP-POST binding
    /// (SAML bindings, 3.5 and SAML profiles, 4.1.4.3) and creates a principal from the validated assertion.
    /// </summary>
    /// <param name="response">The raw (base64-encoded) SAMLResponse form parameter.</param>
    /// <param name="relayState">The RelayState form parameter, if any.</param>
    /// <param name="state">
    /// The request state restored by the host (using the relay state), or <see langword="null"/>
    /// if no pending request corresponds to the response (e.g for unsolicited responses).
    /// </param>
    /// <param name="assertionConsumerServiceUrl">The absolute URL of the assertion consumer service.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation result.</returns>
    public ValueTask<ResponseValidationResult> ValidateResponseAsync(string? response, string? relayState,
        RequestState? state, Uri assertionConsumerServiceUrl, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertionConsumerServiceUrl);

        return ExecuteAsync(response, relayState, state, assertionConsumerServiceUrl, cancellationToken);

        async ValueTask<ResponseValidationResult> ExecuteAsync(string? response, string? relayState,
            RequestState? state, Uri acs, CancellationToken cancellationToken)
        {
            var options = _options.CurrentValue;
            var now = options.TimeProvider.GetUtcNow();

            if (string.IsNullOrEmpty(response))
            {
                return Reject(SR.ID2440, relayState: relayState);
            }

            if (response.Length > options.MaximumMessageSize * 2 || DecodeBase64(response) is not byte[] data ||
                data.Length is 0 || data.Length > options.MaximumMessageSize)
            {
                return Reject(SR.ID2441, relayState: relayState);
            }

            // Note: DTDs are always rejected to prevent XML external entity and entity expansion attacks.
            if (LoadDocument(data, options.MaximumMessageSize, out bool containsDocumentType) is not XmlDocument document)
            {
                return Reject(containsDocumentType ? SR.ID2442 : SR.ID2441, relayState: relayState);
            }

            var root = document.DocumentElement!;
            if (!string.Equals(root.LocalName, "Response", StringComparison.Ordinal) ||
                !string.Equals(root.NamespaceURI, Namespaces.Protocol, StringComparison.Ordinal) ||
                !string.Equals(root.GetAttribute("Version"), "2.0", StringComparison.Ordinal) ||
                !IsNCName(root.GetAttribute("ID")) || !TryParseInstant(root.GetAttribute("IssueInstant"), out _))
            {
                return Reject(SR.ID2443, relayState: relayState);
            }

            // SAML core, 3.2.2: the Issuer element of the response is optional, but must correspond to the identity provider if present.
            string? issuer = null;

            switch (GetChildElements(root, "Issuer", Namespaces.Assertion))
            {
                case []: break;

                case [XmlElement node] when GetTextContent(node) is { Length: > 0 } text && IsEntityIssuer(node):
                    issuer = text;
                    break;

                default: return Reject(SR.ID2444, relayState: relayState);
            }

            var inResponseTo = GetAttributeOrNull(root, "InResponseTo");

            // Resolve the registration: for solicited responses, the registration is resolved from the request state.
            // Unsolicited responses are only accepted for registrations that explicitly allow them (SAML profiles, 4.1.5).
            OpenIddictClientSamlRegistration registration;

            if (state is not null)
            {
                if (state.ExpirationDate <= now || !string.Equals(state.RelayState, relayState, StringComparison.Ordinal) ||
                    !IsSameUrl(state.AssertionConsumerServiceUrl, acs) ||
                    !string.Equals(inResponseTo, state.RequestId, StringComparison.Ordinal))
                {
                    return Reject(SR.ID2447, relayState: relayState, state: state);
                }

                try
                {
                    registration = await GetRegistrationByIdAsync(state.RegistrationId, cancellationToken);
                }

                catch (InvalidOperationException)
                {
                    return Reject(SR.ID2447, relayState: relayState, state: state);
                }
            }

            else
            {
                // Note: a response referencing a request can only be accepted if the corresponding state is available.
                if (inResponseTo is not null)
                {
                    return Reject(SR.ID2447, relayState: relayState);
                }

                if (issuer is null)
                {
                    return Reject(SR.ID2448, relayState: relayState);
                }

                var candidates = (await GetRegistrationsByEntityIdAsync(issuer, cancellationToken))
                    .Where(static registration => registration.AllowUnsolicitedResponses)
                    .ToList();

                if (candidates.Count is not 1)
                {
                    return Reject(SR.ID2448, relayState: relayState);
                }

                registration = candidates[0];
            }

            IdentityProviderConfiguration configuration;

            try
            {
                configuration = await GetIdentityProviderConfigurationAsync(registration, cancellationToken);
            }

            catch (InvalidOperationException exception)
            {
                _logger.LogWarning(6684, exception, SR.GetResourceString(SR.ID6684), registration.RegistrationId);

                return Reject(SR.ID2445, registration, relayState, state);
            }

            if (issuer is not null && !string.Equals(issuer, configuration.EntityId, StringComparison.Ordinal))
            {
                return Reject(SR.ID2444, registration, relayState, state);
            }

            // Validate the signature of the response before using any other value it contains. Only the root element
            // is accepted as a signed element and only its direct children are used (XML signature wrapping defense).
            var result = ValidateEnvelopedSignature(root, configuration.SigningCertificates, out _);
            if (result is SignatureValidationResult.Invalid or SignatureValidationResult.UnsupportedAlgorithm)
            {
                return Reject(SR.ID2445, registration, relayState, state);
            }

            var signed = result is SignatureValidationResult.Valid;

            // SAML bindings, 3.5.5.2: if the message is signed, the Destination attribute MUST be present.
            var destination = GetAttributeOrNull(root, "Destination");
            if ((signed && destination is null) || (destination is not null && !IsSameUrl(destination, acs)))
            {
                return Reject(SR.ID2446, registration, relayState, state);
            }

            if (GetChildElements(root, "Status", Namespaces.Protocol) is not [XmlElement status] ||
                GetChildElements(status, "StatusCode", Namespaces.Protocol) is not [XmlElement code] ||
                GetAttributeOrNull(code, "Value") is not { Length: > 0 } value)
            {
                return Reject(SR.ID2443, registration, relayState, state);
            }

            if (!string.Equals(value, StatusCodes.Success, StringComparison.Ordinal))
            {
                var secondLevelStatus = GetChildElements(code, "StatusCode", Namespaces.Protocol) is [XmlElement child]
                    ? GetAttributeOrNull(child, "Value") : null;
                var message = GetChildElements(status, "StatusMessage", Namespaces.Protocol) is [XmlElement node]
                    ? GetTextContent(node) : null;

                _logger.LogInformation(6683, SR.GetResourceString(SR.ID6683), value, secondLevelStatus, message);

                // Note: the status values are controlled by the sender of the response (that may not be authenticated
                // at this stage): they are exposed as-is in the result but never included in the error description,
                // that is typically returned to the user agent by the hosts.
                return new ResponseValidationResult
                {
                    ErrorDescription = SR.GetResourceString(SR.ID2449),
                    Registration = registration,
                    RelayState = relayState,
                    SecondLevelStatus = secondLevelStatus,
                    State = state,
                    Status = value,
                    StatusMessage = message
                };
            }

            // SAML profiles, 4.1.4.2: the response must contain exactly one assertion (encrypted or not).
            var assertions = GetChildElements(root, "Assertion", Namespaces.Assertion);
            var encryptedAssertions = GetChildElements(root, "EncryptedAssertion", Namespaces.Assertion);

            if (assertions.Count + encryptedAssertions.Count is not 1)
            {
                return Reject(SR.ID2450, registration, relayState, state);
            }

            if (registration.RequireEncryptedAssertions && encryptedAssertions.Count is 0)
            {
                return Reject(SR.ID2457, registration, relayState, state);
            }

            XmlElement assertion;
            if (encryptedAssertions is [XmlElement encrypted])
            {
                if (Decrypt(encrypted, "Assertion") is not XmlElement decrypted)
                {
                    return Reject(SR.ID2451, registration, relayState, state);
                }

                assertion = decrypted;
            }

            else
            {
                assertion = assertions[0];
            }

            // Note: when the assertion is individually signed, the verified copy returned by the signature validation
            // routine (and not the original element) is used for all the subsequent checks.
            result = ValidateEnvelopedSignature(assertion, configuration.SigningCertificates, out var verified);

            switch (result)
            {
                case SignatureValidationResult.Invalid or SignatureValidationResult.UnsupportedAlgorithm:
                    return Reject(SR.ID2445, registration, relayState, state);

                case SignatureValidationResult.Valid:
                    assertion = verified!;
                    break;

                case SignatureValidationResult.Missing when !signed || registration.RequireSignedAssertions:
                    return Reject(SR.ID2452, registration, relayState, state);
            }

            var assertionSigned = result is SignatureValidationResult.Valid;

            if (!string.Equals(assertion.GetAttribute("Version"), "2.0", StringComparison.Ordinal) ||
                GetAttributeOrNull(assertion, "ID") is not { Length: > 0 } identifier || !IsNCName(identifier) ||
                !TryParseInstant(assertion.GetAttribute("IssueInstant"), out _))
            {
                return Reject(SR.ID2443, registration, relayState, state);
            }

            // SAML profiles, 4.1.4.2: the Issuer element of the assertion is mandatory.
            if (GetChildElements(assertion, "Issuer", Namespaces.Assertion) is not [XmlElement element] ||
                !IsEntityIssuer(element) || !string.Equals(GetTextContent(element), configuration.EntityId, StringComparison.Ordinal))
            {
                return Reject(SR.ID2444, registration, relayState, state);
            }

            // Validate the subject and the bearer subject confirmation (SAML profiles, 4.1.4.2 and 4.1.4.3).
            if (GetChildElements(assertion, "Subject", Namespaces.Assertion) is not [XmlElement subject])
            {
                return Reject(SR.ID2453, registration, relayState, state);
            }

            XmlElement? name = (GetChildElements(subject, "NameID", Namespaces.Assertion),
                                GetChildElements(subject, "EncryptedID", Namespaces.Assertion)) switch
            {
                ([XmlElement node], []) => node,
                ([], [XmlElement node]) => Decrypt(node, "NameID"),
                _ => null
            };

            if (name is null || GetTextContent(name) is not { Length: > 0 } nameId)
            {
                return Reject(SR.ID2453, registration, relayState, state);
            }

            DateTimeOffset? confirmationExpiration = null;

            foreach (var confirmation in GetChildElements(subject, "SubjectConfirmation", Namespaces.Assertion))
            {
                if (!string.Equals(confirmation.GetAttribute("Method"), BearerConfirmationMethod, StringComparison.Ordinal) ||
                    GetChildElements(confirmation, "SubjectConfirmationData", Namespaces.Assertion) is not [XmlElement confirmationData])
                {
                    continue;
                }

                // SAML profiles, 4.1.4.2: the bearer SubjectConfirmationData MUST contain Recipient and NotOnOrAfter
                // attributes and MUST NOT contain a NotBefore attribute (confirmations containing it are ignored).
                if (confirmationData.HasAttribute("NotBefore") ||
                    !IsSameUrl(GetAttributeOrNull(confirmationData, "Recipient"), acs) ||
                    !TryParseInstant(confirmationData.GetAttribute("NotOnOrAfter"), out var notOnOrAfter) ||
                    notOnOrAfter <= now - options.ClockSkew ||
                    !string.Equals(GetAttributeOrNull(confirmationData, "InResponseTo"), state?.RequestId, StringComparison.Ordinal))
                {
                    continue;
                }

                confirmationExpiration = notOnOrAfter;
                break;
            }

            if (confirmationExpiration is null)
            {
                return Reject(SR.ID2453, registration, relayState, state);
            }

            // Validate the conditions (SAML core, 2.5.1): all the conditions must be valid and understood.
            if (GetChildElements(assertion, "Conditions", Namespaces.Assertion) is not [XmlElement conditions])
            {
                return Reject(SR.ID2454, registration, relayState, state);
            }

            DateTimeOffset? conditionsExpiration = null;

            if (conditions.HasAttribute("NotBefore") && (!TryParseInstant(conditions.GetAttribute("NotBefore"), out var start) ||
                start > now + options.ClockSkew))
            {
                return Reject(SR.ID2454, registration, relayState, state);
            }

            if (conditions.HasAttribute("NotOnOrAfter"))
            {
                if (!TryParseInstant(conditions.GetAttribute("NotOnOrAfter"), out var end) || end <= now - options.ClockSkew)
                {
                    return Reject(SR.ID2454, registration, relayState, state);
                }

                conditionsExpiration = end;
            }

            var restrictions = 0;

            foreach (XmlNode node in conditions.ChildNodes)
            {
                if (node is not XmlElement condition)
                {
                    continue;
                }

                if (!string.Equals(condition.NamespaceURI, Namespaces.Assertion, StringComparison.Ordinal))
                {
                    return Reject(SR.ID2454, registration, relayState, state);
                }

                switch (condition.LocalName)
                {
                    // SAML core, 2.5.1.4: the service provider must be listed in every audience restriction.
                    case "AudienceRestriction":
                        if (!GetChildElements(condition, "Audience", Namespaces.Assertion).Exists(audience =>
                            string.Equals(GetTextContent(audience), options.EntityId, StringComparison.Ordinal)))
                        {
                            return Reject(SR.ID2454, registration, relayState, state);
                        }

                        restrictions++;
                        break;

                    // Note: assertions are always consumed only once (see below).
                    case "OneTimeUse" or "ProxyRestriction": break;

                    // SAML core, 2.5.1.2: unknown conditions (including extension conditions) make the assertion invalid.
                    default: return Reject(SR.ID2454, registration, relayState, state);
                }
            }

            // SAML profiles, 4.1.4.2: the assertion MUST contain an audience restriction including the service provider.
            if (restrictions is 0)
            {
                return Reject(SR.ID2454, registration, relayState, state);
            }

            // SAML profiles, 4.1.4.2: at least one authentication statement is required.
            if (GetChildElements(assertion, "AuthnStatement", Namespaces.Assertion) is not [XmlElement statement, ..] ||
                !TryParseInstant(statement.GetAttribute("AuthnInstant"), out var authenticationInstant))
            {
                return Reject(SR.ID2455, registration, relayState, state);
            }

            DateTimeOffset? sessionExpiration = null;
            if (statement.HasAttribute("SessionNotOnOrAfter"))
            {
                if (!TryParseInstant(statement.GetAttribute("SessionNotOnOrAfter"), out var date) || date <= now - options.ClockSkew)
                {
                    return Reject(SR.ID2455, registration, relayState, state);
                }

                sessionExpiration = date;
            }

            // When forced authentication was requested, the user must have been authenticated after the request was sent.
            if (state is { ForceAuthentication: true } && authenticationInstant < state.CreationDate - options.ClockSkew)
            {
                return Reject(SR.ID2459, registration, relayState, state);
            }

            string? contextClass = null;
            if (GetChildElements(statement, "AuthnContext", Namespaces.Assertion) is [XmlElement context] &&
                GetChildElements(context, "AuthnContextClassRef", Namespaces.Assertion) is [XmlElement reference])
            {
                contextClass = GetTextContent(reference);
            }

            var attributes = ImmutableArray.CreateBuilder<SamlAttribute>();

            foreach (var attributeStatement in GetChildElements(assertion, "AttributeStatement", Namespaces.Assertion))
            {
                foreach (XmlNode node in attributeStatement.ChildNodes)
                {
                    var attribute = node switch
                    {
                        XmlElement { LocalName: "Attribute", NamespaceURI: Namespaces.Assertion } item => item,
                        XmlElement { LocalName: "EncryptedAttribute", NamespaceURI: Namespaces.Assertion } item => Decrypt(item, "Attribute"),
                        _ => null
                    };

                    if (attribute is null || GetAttributeOrNull(attribute, "Name") is not { Length: > 0 } attributeName)
                    {
                        continue;
                    }

                    var values = ImmutableArray.CreateBuilder<string>();

                    foreach (var item in GetChildElements(attribute, "AttributeValue", Namespaces.Assertion))
                    {
                        // Note: only simple (text) values are supported: complex values are ignored.
                        if (GetTextContent(item) is string text)
                        {
                            values.Add(text);
                        }
                    }

                    attributes.Add(new SamlAttribute
                    {
                        FriendlyName = GetAttributeOrNull(attribute, "FriendlyName"),
                        Name = attributeName,
                        NameFormat = GetAttributeOrNull(attribute, "NameFormat"),
                        Values = values.ToImmutable()
                    });
                }
            }

            // SAML profiles, 4.1.4.5: assertions must not be accepted more than once.
            var expiration = conditionsExpiration > confirmationExpiration ? conditionsExpiration.Value : confirmationExpiration.Value;
            if (!await _provider.GetRequiredService<IOpenIddictClientSamlReplayCache>().TryAddAsync(
                configuration.EntityId + "\n" + identifier, expiration + options.ClockSkew, cancellationToken))
            {
                return Reject(SR.ID2456, registration, relayState, state);
            }

            var model = new Assertion
            {
                Attributes = attributes.ToImmutable(),
                AuthenticationContextClass = contextClass,
                AuthenticationInstant = authenticationInstant,
                ExpirationDate = conditionsExpiration,
                Id = identifier,
                IsEncrypted = encryptedAssertions.Count is not 0,
                IsSigned = assertionSigned,
                Issuer = configuration.EntityId,
                NameId = nameId,
                NameIdFormat = GetAttributeOrNull(name, "Format"),
                SessionExpirationDate = sessionExpiration,
                SessionIndex = GetAttributeOrNull(statement, "SessionIndex")
            };

            _logger.LogInformation(6681, SR.GetResourceString(SR.ID6681), configuration.EntityId, registration.RegistrationId);

            return new ResponseValidationResult
            {
                Assertion = model,
                Principal = CreatePrincipal(registration, model),
                Registration = registration,
                RelayState = relayState,
                State = state,
                Status = value
            };

            XmlElement? Decrypt(XmlElement container, string expected)
                => OpenIddictClientSamlDecryptor.Decrypt(container, options.EncryptionCertificates, options.MaximumMessageSize) is XmlElement result &&
                   string.Equals(result.LocalName, expected, StringComparison.Ordinal) &&
                   string.Equals(result.NamespaceURI, Namespaces.Assertion, StringComparison.Ordinal) ? result : null;

            // SAML core, 2.2.5: the format of an Issuer element is "entity" if omitted.
            static bool IsEntityIssuer(XmlElement element)
                => GetAttributeOrNull(element, "Format") is null or NameIdFormats.Entity;
        }
    }

    /// <summary>
    /// Creates the principal corresponding to the specified validated assertion.
    /// </summary>
    /// <param name="registration">The registration.</param>
    /// <param name="assertion">The validated assertion.</param>
    /// <returns>The principal.</returns>
    public static ClaimsPrincipal CreatePrincipal(OpenIddictClientSamlRegistration registration, Assertion assertion)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(assertion);

        var identity = new ClaimsIdentity(AuthenticationType, Claims.Name, Claims.Role);
        var issuer = assertion.Issuer;

        Add(Claims.Subject, assertion.NameId);
        Add(ClaimTypes.NameIdentifier, assertion.NameId);
        Add(SamlClaims.NameIdFormat, assertion.NameIdFormat);
        Add(SamlClaims.SessionIndex, assertion.SessionIndex);
        Add(SamlClaims.AuthenticationContextClass, assertion.AuthenticationContextClass);
        Add(Claims.Private.RegistrationId, registration.RegistrationId);
        Add(Claims.Private.ProviderName, registration.ProviderName);

        foreach (var attribute in assertion.Attributes)
        {
            var type = registration.AttributeMappings.TryGetValue(attribute.Name, out var mapping) ? mapping : attribute.Name;

            foreach (var value in attribute.Values)
            {
                Add(type, value);
            }
        }

        return new ClaimsPrincipal(identity);

        void Add(string type, string? value)
        {
            if (!string.IsNullOrEmpty(type) && !string.IsNullOrEmpty(value))
            {
                identity.AddClaim(new Claim(type, value, ClaimValueTypes.String, issuer, issuer));
            }
        }
    }

    private ResponseValidationResult Reject(string description, OpenIddictClientSamlRegistration? registration = null,
        string? relayState = null, RequestState? state = null)
    {
        var message = SR.GetResourceString(description);

        _logger.LogInformation(6680, SR.GetResourceString(SR.ID6680), message);

        return new ResponseValidationResult
        {
            ErrorDescription = message,
            Registration = registration,
            RelayState = relayState,
            State = state
        };
    }
}
