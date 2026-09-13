/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Exposes the models used by the OpenIddict backend-for-frontend (BFF) components.
/// </summary>
public static class OpenIddictClientAspNetCoreBffModels
{
    /// <summary>
    /// Represents an access token that can be attached to requests sent to remote APIs.
    /// </summary>
    public sealed record class AccessToken
    {
        /// <summary>
        /// Gets or sets the access token.
        /// </summary>
        public required string Value { get; init; }

        /// <summary>
        /// Gets or sets the type of the access token (e.g "Bearer" or "DPoP"), if available.
        /// </summary>
        public string? TokenType { get; init; }

        /// <summary>
        /// Gets or sets the expiration date of the access token, if available.
        /// </summary>
        public DateTimeOffset? ExpirationDate { get; init; }

        /// <summary>
        /// Gets or sets the identifier of the client registration used to obtain the access token, if available.
        /// </summary>
        public string? RegistrationId { get; init; }
    }

    /// <summary>
    /// Represents a request for an access token obtained using the client credentials grant.
    /// </summary>
    public sealed record class ClientAccessTokenRequest
    {
        /// <summary>
        /// Gets or sets the identifier of the client registration, if applicable.
        /// </summary>
        public string? RegistrationId { get; init; }

        /// <summary>
        /// Gets or sets the scopes, if applicable.
        /// </summary>
        public List<string>? Scopes { get; init; }

        /// <summary>
        /// Gets or sets the resources, if applicable.
        /// </summary>
        public List<string>? Resources { get; init; }
    }

    /// <summary>
    /// Represents a validated back-channel logout notification.
    /// </summary>
    public sealed record class BackchannelLogoutNotification
    {
        /// <summary>
        /// Gets or sets the HTTP context.
        /// </summary>
        public required HttpContext HttpContext { get; init; }

        /// <summary>
        /// Gets or sets the client registration associated with the issuer of the logout token.
        /// </summary>
        public required OpenIddictClientRegistration Registration { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the validated logout token.
        /// </summary>
        public required ClaimsPrincipal Principal { get; init; }

        /// <summary>
        /// Gets or sets the issuer of the logout token.
        /// </summary>
        public required string Issuer { get; init; }

        /// <summary>
        /// Gets or sets the subject of the logout token, if available.
        /// </summary>
        public string? Subject { get; init; }

        /// <summary>
        /// Gets or sets the session identifier of the logout token, if available.
        /// </summary>
        public string? SessionId { get; init; }
    }
}
