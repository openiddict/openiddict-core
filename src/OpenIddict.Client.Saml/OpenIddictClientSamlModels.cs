/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace OpenIddict.Client.Saml;

/// <summary>
/// Contains the models used by the OpenIddict SAML 2.0 service provider.
/// </summary>
public static class OpenIddictClientSamlModels
{
    /// <summary>
    /// Represents the identity provider configuration resolved from a registration (and its metadata, if applicable).
    /// </summary>
    public sealed record class IdentityProviderConfiguration
    {
        /// <summary>
        /// Gets the entity identifier of the identity provider.
        /// </summary>
        public required string EntityId { get; init; }

        /// <summary>
        /// Gets the single sign-on service URLs, indexed by binding.
        /// </summary>
        public required ImmutableDictionary<string, Uri> SingleSignOnServices { get; init; }

        /// <summary>
        /// Gets the certificates used by the identity provider to sign responses and assertions.
        /// </summary>
        public required ImmutableArray<X509Certificate2> SigningCertificates { get; init; }

        /// <summary>
        /// Gets a boolean indicating whether the identity provider requires signed authentication requests.
        /// </summary>
        public bool WantAuthenticationRequestsSigned { get; init; }

        /// <summary>
        /// Gets the date after which the imported metadata must no longer be used (computed from the validUntil and
        /// cacheDuration attributes), or <see langword="null"/> if the metadata doesn't expire.
        /// </summary>
        public DateTimeOffset? ExpirationDate { get; init; }
    }

    /// <summary>
    /// Represents an authentication request ready to be sent to the identity provider.
    /// </summary>
    public sealed record class AuthenticationRequestMessage
    {
        /// <summary>
        /// Gets the identifier of the request (expected as the InResponseTo value of the response).
        /// </summary>
        public required string RequestId { get; init; }

        /// <summary>
        /// Gets the binding used to send the request.
        /// </summary>
        public required string Binding { get; init; }

        /// <summary>
        /// Gets the URL of the single sign-on service the request is sent to.
        /// </summary>
        public required Uri Destination { get; init; }

        /// <summary>
        /// Gets the serialized XML request (signed when the HTTP-POST binding is used and requests are signed).
        /// </summary>
        public required string Xml { get; init; }

        /// <summary>
        /// Gets the URL the user agent must be redirected to (HTTP-Redirect binding only).
        /// </summary>
        public Uri? RedirectUrl { get; init; }

        /// <summary>
        /// Gets the form parameters that must be posted to <see cref="Destination"/> (HTTP-POST binding only).
        /// </summary>
        public ImmutableDictionary<string, string> FormParameters { get; init; } = ImmutableDictionary<string, string>.Empty;

        /// <summary>
        /// Gets the relay state attached to the request, if any.
        /// </summary>
        public string? RelayState { get; init; }

        /// <summary>
        /// Gets a boolean indicating whether the request was signed.
        /// </summary>
        public bool IsSigned { get; init; }

        /// <summary>
        /// Gets a boolean indicating whether the identity provider was asked to authenticate the user again.
        /// </summary>
        public bool ForceAuthentication { get; init; }
    }

    /// <summary>
    /// Represents the state of a pending authentication request, that must be persisted (and protected) by the host.
    /// </summary>
    public sealed record class RequestState
    {
        /// <summary>
        /// Gets the identifier of the authentication request.
        /// </summary>
        public required string RequestId { get; init; }

        /// <summary>
        /// Gets the identifier of the registration the request was sent to.
        /// </summary>
        public required string RegistrationId { get; init; }

        /// <summary>
        /// Gets the relay state sent with the request, used to correlate the response.
        /// </summary>
        public string? RelayState { get; init; }

        /// <summary>
        /// Gets the assertion consumer service URL the response is expected to be sent to.
        /// </summary>
        public required Uri AssertionConsumerServiceUrl { get; init; }

        /// <summary>
        /// Gets the creation date of the state.
        /// </summary>
        public required DateTimeOffset CreationDate { get; init; }

        /// <summary>
        /// Gets the expiration date of the state.
        /// </summary>
        public required DateTimeOffset ExpirationDate { get; init; }

        /// <summary>
        /// Gets a boolean indicating whether the identity provider was asked to authenticate the user again.
        /// </summary>
        public bool ForceAuthentication { get; init; }

        /// <summary>
        /// Gets the host-specific properties attached to the state (e.g the return URL).
        /// </summary>
        public ImmutableDictionary<string, string?> Properties { get; init; } = ImmutableDictionary<string, string?>.Empty;
    }

    /// <summary>
    /// Represents a SAML attribute extracted from a validated assertion.
    /// </summary>
    public sealed record class SamlAttribute
    {
        /// <summary>
        /// Gets the name of the attribute.
        /// </summary>
        public required string Name { get; init; }

        /// <summary>
        /// Gets the name format of the attribute, if specified.
        /// </summary>
        public string? NameFormat { get; init; }

        /// <summary>
        /// Gets the friendly name of the attribute, if specified.
        /// </summary>
        public string? FriendlyName { get; init; }

        /// <summary>
        /// Gets the simple (text) values of the attribute.
        /// </summary>
        public ImmutableArray<string> Values { get; init; } = [];
    }

    /// <summary>
    /// Represents a validated SAML assertion.
    /// </summary>
    public sealed record class Assertion
    {
        /// <summary>
        /// Gets the identifier of the assertion.
        /// </summary>
        public required string Id { get; init; }

        /// <summary>
        /// Gets the issuer of the assertion.
        /// </summary>
        public required string Issuer { get; init; }

        /// <summary>
        /// Gets the NameID value of the subject.
        /// </summary>
        public required string NameId { get; init; }

        /// <summary>
        /// Gets the NameID format of the subject, if specified.
        /// </summary>
        public string? NameIdFormat { get; init; }

        /// <summary>
        /// Gets the session index attached to the authentication statement, if specified.
        /// </summary>
        public string? SessionIndex { get; init; }

        /// <summary>
        /// Gets the authentication instant.
        /// </summary>
        public DateTimeOffset AuthenticationInstant { get; init; }

        /// <summary>
        /// Gets the authentication context class, if specified.
        /// </summary>
        public string? AuthenticationContextClass { get; init; }

        /// <summary>
        /// Gets the expiration date of the assertion, if specified.
        /// </summary>
        public DateTimeOffset? ExpirationDate { get; init; }

        /// <summary>
        /// Gets the date after which the session established by the identity provider expires, if specified.
        /// </summary>
        public DateTimeOffset? SessionExpirationDate { get; init; }

        /// <summary>
        /// Gets the attributes of the assertion.
        /// </summary>
        public ImmutableArray<SamlAttribute> Attributes { get; init; } = [];

        /// <summary>
        /// Gets a boolean indicating whether the assertion was individually signed.
        /// </summary>
        public bool IsSigned { get; init; }

        /// <summary>
        /// Gets a boolean indicating whether the assertion was encrypted.
        /// </summary>
        public bool IsEncrypted { get; init; }
    }

    /// <summary>
    /// Represents the result of the validation of a SAML response.
    /// </summary>
    public sealed record class ResponseValidationResult
    {
        /// <summary>
        /// Gets a boolean indicating whether the response was successfully validated.
        /// </summary>
        public bool Succeeded => ErrorDescription is null;

        /// <summary>
        /// Gets the registration the response was validated with, if it could be resolved.
        /// </summary>
        public OpenIddictClientSamlRegistration? Registration { get; init; }

        /// <summary>
        /// Gets the request state the response corresponds to, if applicable.
        /// </summary>
        public RequestState? State { get; init; }

        /// <summary>
        /// Gets the validated assertion, if applicable.
        /// </summary>
        public Assertion? Assertion { get; init; }

        /// <summary>
        /// Gets the principal created from the validated assertion, if applicable.
        /// </summary>
        public ClaimsPrincipal? Principal { get; init; }

        /// <summary>
        /// Gets the relay state returned by the identity provider, if any.
        /// </summary>
        public string? RelayState { get; init; }

        /// <summary>
        /// Gets the top-level status code returned by the identity provider, if the response could be parsed.
        /// </summary>
        public string? Status { get; init; }

        /// <summary>
        /// Gets the second-level status code returned by the identity provider, if any.
        /// </summary>
        public string? SecondLevelStatus { get; init; }

        /// <summary>
        /// Gets the status message returned by the identity provider, if any.
        /// </summary>
        public string? StatusMessage { get; init; }

        /// <summary>
        /// Gets the error description, if the response was rejected.
        /// </summary>
        public string? ErrorDescription { get; init; }
    }
}
