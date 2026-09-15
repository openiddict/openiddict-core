/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Contains the models used by the OpenIddict SAML 2.0 identity provider.
/// </summary>
public static class OpenIddictServerSamlModels
{
    /// <summary>
    /// Represents a validated SAML 2.0 authentication request.
    /// </summary>
    public sealed record class AuthenticationRequest
    {
        /// <summary>
        /// Gets the identifier of the request (used as the InResponseTo value).
        /// </summary>
        public required string Id { get; init; }

        /// <summary>
        /// Gets the entity identifier of the service provider that issued the request.
        /// </summary>
        public required string Issuer { get; init; }

        /// <summary>
        /// Gets the issue instant of the request.
        /// </summary>
        public required DateTimeOffset IssueInstant { get; init; }

        /// <summary>
        /// Gets the binding used to send the request.
        /// </summary>
        public required string Binding { get; init; }

        /// <summary>
        /// Gets the destination of the request, if specified.
        /// </summary>
        public string? Destination { get; init; }

        /// <summary>
        /// Gets a boolean indicating whether the user must be authenticated again.
        /// </summary>
        public bool ForceAuthentication { get; init; }

        /// <summary>
        /// Gets a boolean indicating whether the user must not be visibly involved.
        /// </summary>
        public bool IsPassive { get; init; }

        /// <summary>
        /// Gets the NameID format requested by the service provider, if specified.
        /// </summary>
        public string? NameIdFormat { get; init; }

        /// <summary>
        /// Gets a boolean indicating whether the request was signed (and the signature validated).
        /// </summary>
        public bool IsSigned { get; init; }
    }

    /// <summary>
    /// Represents the result of the validation of a SAML 2.0 authentication request.
    /// </summary>
    public sealed record class AuthenticationRequestResult
    {
        /// <summary>
        /// Gets the validated request, if available.
        /// </summary>
        public AuthenticationRequest? Request { get; init; }

        /// <summary>
        /// Gets the service provider, if it could be resolved.
        /// </summary>
        public OpenIddictServerSamlServiceProvider? ServiceProvider { get; init; }

        /// <summary>
        /// Gets the validated assertion consumer service URL, if available.
        /// </summary>
        public Uri? AssertionConsumerServiceUrl { get; init; }

        /// <summary>
        /// Gets the identifier of the request, if it could be extracted from a trusted request
        /// (used as the InResponseTo value of error responses).
        /// </summary>
        public string? RequestId { get; init; }

        /// <summary>
        /// Gets the binding used to return the response to the assertion consumer service
        /// (<see cref="OpenIddictServerSamlConstants.Bindings.HttpPost"/> or
        /// <see cref="OpenIddictServerSamlConstants.Bindings.HttpArtifact"/>), if available.
        /// </summary>
        public string? ResponseBinding { get; init; }

        /// <summary>
        /// Gets the relay state, if specified.
        /// </summary>
        public string? RelayState { get; init; }

        /// <summary>
        /// Gets the SAML status code describing the error, if applicable.
        /// </summary>
        public string? Status { get; init; }

        /// <summary>
        /// Gets the second-level SAML status code describing the error, if applicable.
        /// </summary>
        public string? SecondLevelStatus { get; init; }

        /// <summary>
        /// Gets the error description, if applicable.
        /// </summary>
        public string? ErrorDescription { get; init; }

        /// <summary>
        /// Gets a boolean indicating whether the request was successfully validated.
        /// </summary>
        public bool Succeeded => Status is null;

        /// <summary>
        /// Gets a boolean indicating whether an error response can be safely returned to the service provider
        /// (i.e the service provider, the assertion consumer service URL and the signature were validated).
        /// </summary>
        public bool CanReturnErrorToServiceProvider { get; init; }
    }

    /// <summary>
    /// Represents the state of a validated request, persisted by the host while the user is authenticated.
    /// </summary>
    public sealed record class RequestState
    {
        /// <summary>
        /// Gets the unique identifier of the state, used to enforce single use when request replay protection is enabled.
        /// </summary>
        public string? Id { get; init; }

        /// <summary>
        /// Gets the entity identifier of the service provider.
        /// </summary>
        public required string ServiceProvider { get; init; }

        /// <summary>
        /// Gets the binding used to return the response to the assertion consumer service.
        /// If <see langword="null"/>, <see cref="OpenIddictServerSamlConstants.Bindings.HttpPost"/> is used.
        /// </summary>
        public string? ResponseBinding { get; init; }

        /// <summary>
        /// Gets the validated assertion consumer service URL.
        /// </summary>
        public required Uri AssertionConsumerServiceUrl { get; init; }

        /// <summary>
        /// Gets the validated authentication request, or <see langword="null"/> for identity provider-initiated single sign-on.
        /// </summary>
        public AuthenticationRequest? Request { get; init; }

        /// <summary>
        /// Gets the relay state, if any.
        /// </summary>
        public string? RelayState { get; init; }

        /// <summary>
        /// Gets the date at which the request was validated (truncated to the second).
        /// </summary>
        public required DateTimeOffset CreationDate { get; init; }

        /// <summary>
        /// Gets the date after which the state can no longer be used.
        /// </summary>
        public required DateTimeOffset ExpirationDate { get; init; }
    }

    /// <summary>
    /// Represents the context used to create an assertion.
    /// </summary>
    public sealed record class AssertionContext
    {
        /// <summary>
        /// Gets the authenticated principal.
        /// </summary>
        public required ClaimsPrincipal Principal { get; init; }

        /// <summary>
        /// Gets the service provider.
        /// </summary>
        public required OpenIddictServerSamlServiceProvider ServiceProvider { get; init; }

        /// <summary>
        /// Gets the authentication request (also restored after the user was challenged),
        /// or <see langword="null"/> for identity provider-initiated single sign-on.
        /// </summary>
        public AuthenticationRequest? Request { get; init; }

        /// <summary>
        /// Gets the date at which the user was authenticated, if known.
        /// </summary>
        public DateTimeOffset? AuthenticationInstant { get; init; }

        /// <summary>
        /// Gets the <see cref="System.Threading.CancellationToken"/> that can be used to abort the operation.
        /// </summary>
        public CancellationToken CancellationToken { get; init; }
    }

    /// <summary>
    /// Describes the subject, authentication statement and attributes of an assertion.
    /// </summary>
    public sealed record class AssertionDescriptor
    {
        /// <summary>
        /// Gets or sets the NameID value.
        /// </summary>
        public required string NameId { get; init; }

        /// <summary>
        /// Gets or sets the NameID format.
        /// </summary>
        public string NameIdFormat { get; init; } = OpenIddictServerSamlConstants.NameIdFormats.Unspecified;

        /// <summary>
        /// Gets or sets the date at which the user was authenticated.
        /// </summary>
        public DateTimeOffset? AuthenticationInstant { get; init; }

        /// <summary>
        /// Gets or sets the session index, if applicable.
        /// </summary>
        public string? SessionIndex { get; init; }

        /// <summary>
        /// Gets or sets the authentication context class reference.
        /// </summary>
        public string AuthenticationContextClass { get; init; } = OpenIddictServerSamlConstants.AuthenticationContextClasses.Unspecified;

        /// <summary>
        /// Gets or sets the attributes included in the assertion.
        /// </summary>
        public IReadOnlyList<AssertionAttribute> Attributes { get; init; } = [];
    }

    /// <summary>
    /// Represents a SAML attribute.
    /// </summary>
    public sealed record class AssertionAttribute
    {
        /// <summary>
        /// Gets or sets the attribute name.
        /// </summary>
        public required string Name { get; init; }

        /// <summary>
        /// Gets or sets the attribute name format.
        /// </summary>
        public string NameFormat { get; init; } = OpenIddictServerSamlConstants.AttributeNameFormats.Unspecified;

        /// <summary>
        /// Gets or sets the attribute values.
        /// </summary>
        public required IReadOnlyList<string> Values { get; init; }
    }

    /// <summary>
    /// Describes a SAML response.
    /// </summary>
    public sealed record class ResponseDescriptor
    {
        /// <summary>
        /// Gets or sets the service provider.
        /// </summary>
        public required OpenIddictServerSamlServiceProvider ServiceProvider { get; init; }

        /// <summary>
        /// Gets or sets the assertion consumer service URL (used as the Destination and Recipient).
        /// </summary>
        public required Uri AssertionConsumerServiceUrl { get; init; }

        /// <summary>
        /// Gets or sets the identifier of the request, or <see langword="null"/> for unsolicited responses.
        /// </summary>
        public string? InResponseTo { get; init; }

        /// <summary>
        /// Gets or sets the assertion, or <see langword="null"/> for error responses.
        /// </summary>
        public AssertionDescriptor? Assertion { get; init; }

        /// <summary>
        /// Gets or sets the top-level status code. Must be <see cref="OpenIddictServerSamlConstants.StatusCodes.Success"/>
        /// when an assertion is specified.
        /// </summary>
        public string Status { get; init; } = OpenIddictServerSamlConstants.StatusCodes.Success;

        /// <summary>
        /// Gets or sets the second-level status code, if applicable.
        /// </summary>
        public string? SecondLevelStatus { get; init; }

        /// <summary>
        /// Gets or sets the status message, if applicable.
        /// </summary>
        public string? StatusMessage { get; init; }
    }

    /// <summary>
    /// Represents a validated SAML 2.0 logout request sent by a service provider (SAML core, 3.7.1).
    /// </summary>
    public sealed record class LogoutRequest
    {
        /// <summary>
        /// Gets the identifier of the request (used as the InResponseTo value of the logout response).
        /// </summary>
        public required string Id { get; init; }

        /// <summary>
        /// Gets the entity identifier of the service provider that issued the request.
        /// </summary>
        public required string Issuer { get; init; }

        /// <summary>
        /// Gets the issue instant of the request.
        /// </summary>
        public required DateTimeOffset IssueInstant { get; init; }

        /// <summary>
        /// Gets the binding used to send the request.
        /// </summary>
        public required string Binding { get; init; }

        /// <summary>
        /// Gets the NameID identifying the principal.
        /// </summary>
        public required string NameId { get; init; }

        /// <summary>
        /// Gets the format of the NameID, if specified.
        /// </summary>
        public string? NameIdFormat { get; init; }

        /// <summary>
        /// Gets the NameQualifier of the NameID, if specified.
        /// </summary>
        public string? NameQualifier { get; init; }

        /// <summary>
        /// Gets the SPNameQualifier of the NameID, if specified.
        /// </summary>
        public string? SPNameQualifier { get; init; }

        /// <summary>
        /// Gets the session indexes identifying the sessions to terminate. If empty, all
        /// the sessions of the principal at the service provider must be terminated.
        /// </summary>
        public IReadOnlyList<string> SessionIndexes { get; init; } = [];

        /// <summary>
        /// Gets the destination of the request, if specified.
        /// </summary>
        public string? Destination { get; init; }

        /// <summary>
        /// Gets the date after which the request must be discarded, if specified.
        /// </summary>
        public DateTimeOffset? NotOnOrAfter { get; init; }

        /// <summary>
        /// Gets the reason of the logout, if specified.
        /// </summary>
        public string? Reason { get; init; }
    }

    /// <summary>
    /// Represents the result of the validation of a SAML 2.0 logout request.
    /// </summary>
    public sealed record class LogoutRequestResult
    {
        /// <summary>
        /// Gets the validated request, if available.
        /// </summary>
        public LogoutRequest? Request { get; init; }

        /// <summary>
        /// Gets the service provider, if it could be resolved.
        /// </summary>
        public OpenIddictServerSamlServiceProvider? ServiceProvider { get; init; }

        /// <summary>
        /// Gets the identifier of the request, if it could be extracted from a trusted request.
        /// </summary>
        public string? RequestId { get; init; }

        /// <summary>
        /// Gets the binding used to send the request, if available.
        /// </summary>
        public string? Binding { get; init; }

        /// <summary>
        /// Gets the relay state, if specified.
        /// </summary>
        public string? RelayState { get; init; }

        /// <summary>
        /// Gets the SAML status code describing the error, if applicable.
        /// </summary>
        public string? Status { get; init; }

        /// <summary>
        /// Gets the second-level SAML status code describing the error, if applicable.
        /// </summary>
        public string? SecondLevelStatus { get; init; }

        /// <summary>
        /// Gets the error description, if applicable.
        /// </summary>
        public string? ErrorDescription { get; init; }

        /// <summary>
        /// Gets a boolean indicating whether the request was successfully validated.
        /// </summary>
        public bool Succeeded => Status is null;

        /// <summary>
        /// Gets a boolean indicating whether an error logout response can be safely returned to the service provider
        /// (i.e the service provider, its single logout service and the signature of the request were validated).
        /// </summary>
        public bool CanReturnErrorToServiceProvider { get; init; }
    }

    /// <summary>
    /// Represents the result of the validation of a SAML 2.0 logout response returned by a service provider.
    /// </summary>
    public sealed record class LogoutResponseResult
    {
        /// <summary>
        /// Gets the identifier of the response, if available.
        /// </summary>
        public string? Id { get; init; }

        /// <summary>
        /// Gets the identifier of the logout request the response corresponds to, if available.
        /// </summary>
        public string? InResponseTo { get; init; }

        /// <summary>
        /// Gets the service provider, if it could be resolved.
        /// </summary>
        public OpenIddictServerSamlServiceProvider? ServiceProvider { get; init; }

        /// <summary>
        /// Gets the top-level status code returned by the service provider, if available.
        /// </summary>
        public string? Status { get; init; }

        /// <summary>
        /// Gets the second-level status code returned by the service provider, if available.
        /// </summary>
        public string? SecondLevelStatus { get; init; }

        /// <summary>
        /// Gets the relay state, if specified.
        /// </summary>
        public string? RelayState { get; init; }

        /// <summary>
        /// Gets the reason why the response was rejected, if applicable.
        /// </summary>
        public string? ErrorDescription { get; init; }

        /// <summary>
        /// Gets a boolean indicating whether the response was successfully validated (the status
        /// returned by the service provider is exposed by <see cref="Status"/> and may indicate a failure).
        /// </summary>
        public bool Succeeded => ErrorDescription is null;
    }

    /// <summary>
    /// Represents a SAML service provider session that must be notified when a server-side session is terminated.
    /// </summary>
    public sealed record class LogoutParticipant
    {
        /// <summary>
        /// Gets the entity identifier of the service provider.
        /// </summary>
        public required string ServiceProvider { get; init; }

        /// <summary>
        /// Gets the identifier of the server-side session entry (used as the SessionIndex).
        /// </summary>
        public required string SessionId { get; init; }

        /// <summary>
        /// Gets the NameID issued to the service provider.
        /// </summary>
        public required string NameId { get; init; }

        /// <summary>
        /// Gets the format of the NameID issued to the service provider, if available.
        /// </summary>
        public string? NameIdFormat { get; init; }

        /// <summary>
        /// Gets the binding of the single logout service of the service provider.
        /// </summary>
        public required string Binding { get; init; }

        /// <summary>
        /// Gets the location of the single logout service of the service provider.
        /// </summary>
        public required Uri Url { get; init; }
    }

    /// <summary>
    /// Describes the response a host must return to the user agent to continue or complete a single logout operation.
    /// </summary>
    public sealed record class LogoutAction
    {
        /// <summary>
        /// Gets the URL the user agent must be redirected to (HTTP-Redirect binding or local return URL), if applicable.
        /// </summary>
        public Uri? RedirectUrl { get; init; }

        /// <summary>
        /// Gets the URL the form containing <see cref="FormFields"/> must be posted to (HTTP-POST binding), if applicable.
        /// </summary>
        public Uri? FormPostUrl { get; init; }

        /// <summary>
        /// Gets the fields of the form posted to <see cref="FormPostUrl"/>.
        /// </summary>
        public IReadOnlyList<KeyValuePair<string, string>> FormFields { get; init; } = [];

        /// <summary>
        /// Gets the front-channel logout URIs (e.g of OpenID Connect client applications) that must be rendered in
        /// hidden iframes before the user agent is redirected or the form is posted.
        /// </summary>
        public IReadOnlyList<Uri> FrontchannelLogoutUris { get; init; } = [];

        /// <summary>
        /// Gets a boolean indicating whether the host must sign the user out of the local authentication scheme.
        /// </summary>
        public bool SignOut { get; init; }

        /// <summary>
        /// Gets a boolean indicating whether the logout could not be propagated to all the session participants.
        /// </summary>
        public bool PartialLogout { get; init; }

        /// <summary>
        /// Gets the identifiers of the server-side session entries terminated by this operation.
        /// </summary>
        public IReadOnlyList<string> TerminatedSessionIds { get; init; } = [];

        /// <summary>
        /// Gets a boolean indicating whether the operation is completed and no navigation is required.
        /// </summary>
        public bool IsCompleted => RedirectUrl is null && FormPostUrl is null && FrontchannelLogoutUris.Count is 0;
    }

    /// <summary>
    /// Represents a SAML message stored until the artifact representing it is resolved.
    /// </summary>
    public sealed record class ArtifactMessage
    {
        /// <summary>
        /// Gets the entity identifier of the service provider the message is intended for.
        /// </summary>
        public required string ServiceProvider { get; init; }

        /// <summary>
        /// Gets the serialized XML message.
        /// </summary>
        public required string Message { get; init; }

        /// <summary>
        /// Gets the date after which the artifact can no longer be resolved.
        /// </summary>
        public required DateTimeOffset ExpirationDate { get; init; }
    }

    /// <summary>
    /// Represents the result of an artifact resolution request.
    /// </summary>
    public sealed record class ArtifactResolutionResult
    {
        /// <summary>
        /// Gets the serialized SOAP envelope returned to the requester.
        /// </summary>
        public required string Content { get; init; }

        /// <summary>
        /// Gets the reason why the artifact was not resolved or the SOAP fault was returned, if applicable.
        /// Note: this value is not returned to the requester (empty responses don't include a reason).
        /// </summary>
        public string? ErrorDescription { get; init; }

        /// <summary>
        /// Gets a boolean indicating whether the envelope contains a SOAP fault
        /// (in which case the HTTP status code must be 500, per SAML bindings, 3.2.3.3).
        /// </summary>
        public bool IsFault { get; init; }

        /// <summary>
        /// Gets a boolean indicating whether the artifact was resolved and a message returned.
        /// </summary>
        public bool Resolved { get; init; }
    }
}
