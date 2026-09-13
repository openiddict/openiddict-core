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
        /// Gets the authentication request, or <see langword="null"/> for identity provider-initiated single sign-on.
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
}
