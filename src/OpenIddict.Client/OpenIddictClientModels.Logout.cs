/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Security.Claims;

namespace OpenIddict.Client;

public static partial class OpenIddictClientModels
{
    /// <summary>
    /// Represents a logout token authentication request, used to validate the logout tokens sent to back-channel
    /// logout endpoints that are not handled by the OpenIddict client hosts (e.g custom endpoints).
    /// </summary>
    public sealed record class LogoutTokenAuthenticationRequest
    {
        /// <summary>
        /// Gets or sets the cancellation token that will be
        /// used to determine if the operation was aborted.
        /// </summary>
        public CancellationToken CancellationToken { get; init; }

        /// <summary>
        /// Gets or sets the logout token sent by the authorization server.
        /// </summary>
        public required string LogoutToken { get; init; }

        /// <summary>
        /// Gets or sets the maximum age of logout tokens that don't include an "exp" claim, if applicable.
        /// If no value is specified, <see cref="OpenIddictClientOptions.LogoutTokenMaximumAge"/> is used.
        /// </summary>
        public TimeSpan? MaximumAge { get; init; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the logout token must include an "exp" claim.
        /// If no value is specified, <see cref="OpenIddictClientOptions.DisableLogoutTokenExpirationRequirement"/> is used.
        /// </summary>
        public bool? RequireExpiration { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that will be added to the context.
        /// </summary>
        public Dictionary<string, string?>? Properties { get; init; }

        /// <summary>
        /// Gets or sets the unique identifier of the client registration that will be used, if applicable.
        /// If no value is specified, the registration is resolved using the issuer and the audiences of the logout token.
        /// </summary>
        public string? RegistrationId { get; init; }
    }

    /// <summary>
    /// Represents a logout token authentication result.
    /// </summary>
    public sealed record class LogoutTokenAuthenticationResult
    {
        /// <summary>
        /// Gets or sets a merged principal containing all the claims extracted from the logout token.
        /// </summary>
        public required ClaimsPrincipal Principal { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the logout token.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public required ClaimsPrincipal LogoutTokenPrincipal { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that were present in the context.
        /// </summary>
        public required Dictionary<string, string?> Properties { get; init; }

        /// <summary>
        /// Gets or sets the client registration associated with the authorization server that issued the logout token.
        /// </summary>
        public required OpenIddictClientRegistration Registration { get; init; }

        /// <summary>
        /// Gets or sets the issuer of the logout token.
        /// </summary>
        public required Uri Issuer { get; init; }

        /// <summary>
        /// Gets or sets the session identifier ("sid") extracted from the logout token, if available.
        /// </summary>
        public required string? SessionId { get; init; }

        /// <summary>
        /// Gets or sets the subject ("sub") extracted from the logout token, if available.
        /// </summary>
        public required string? Subject { get; init; }
    }
}
