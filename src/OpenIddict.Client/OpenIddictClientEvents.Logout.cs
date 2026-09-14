/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;

namespace OpenIddict.Client;

public static partial class OpenIddictClientEvents
{
    /// <summary>
    /// Represents an event called for each request to the back-channel logout endpoint to give the
    /// user code a chance to manually extract the logout request from the ambient HTTP context.
    /// </summary>
    public sealed class ExtractBackchannelLogoutRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractBackchannelLogoutRequestContext"/> class.
        /// </summary>
        public ExtractBackchannelLogoutRequestContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request or <see langword="null"/> if it wasn't extracted yet.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }
    }

    /// <summary>
    /// Represents an event called for each request to the back-channel logout endpoint
    /// to determine if the request is valid and should continue to be processed.
    /// </summary>
    public sealed class ValidateBackchannelLogoutRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidateBackchannelLogoutRequestContext"/> class.
        /// </summary>
        public ValidateBackchannelLogoutRequestContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        public OpenIddictRequest Request
        {
            get => Transaction.Request!;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets the security principal extracted from the logout token.
        /// </summary>
        public ClaimsPrincipal? Principal { get; set; }

        /// <summary>
        /// Gets or sets the session identifier ("sid") extracted from the logout token, if available.
        /// </summary>
        public string? SessionId { get; set; }

        /// <summary>
        /// Gets or sets the subject ("sub") extracted from the logout token, if available.
        /// </summary>
        public string? Subject { get; set; }
    }

    /// <summary>
    /// Represents an event called for each validated back-channel logout request to allow the user code to terminate
    /// the sessions matching the logout token (OpenID Connect Back-Channel Logout 1.0, section 2.7).
    /// </summary>
    public sealed class HandleBackchannelLogoutRequestContext : BaseValidatingTicketContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleBackchannelLogoutRequestContext"/> class.
        /// </summary>
        public HandleBackchannelLogoutRequestContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        public OpenIddictRequest Request
        {
            get => Transaction.Request!;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets the session identifier ("sid") extracted from the logout token, if available.
        /// When present, only the session identified by this value must be terminated.
        /// </summary>
        public string? SessionId { get; set; }

        /// <summary>
        /// Gets or sets the subject ("sub") extracted from the logout token, if available.
        /// When no session identifier is present, all the sessions of this subject must be terminated.
        /// </summary>
        public string? Subject { get; set; }
    }

    /// <summary>
    /// Represents an event called before the back-channel logout response is returned to the caller.
    /// </summary>
    public sealed class ApplyBackchannelLogoutResponseContext : BaseRequestContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyBackchannelLogoutResponseContext"/> class.
        /// </summary>
        public ApplyBackchannelLogoutResponseContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request, or <see langword="null"/> if it couldn't be extracted.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets the response.
        /// </summary>
        public OpenIddictResponse Response
        {
            get => Transaction.Response!;
            set => Transaction.Response = value;
        }
    }

    /// <summary>
    /// Represents an event called for each request to the front-channel logout endpoint to give the
    /// user code a chance to manually extract the logout request from the ambient HTTP context.
    /// </summary>
    public sealed class ExtractFrontchannelLogoutRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractFrontchannelLogoutRequestContext"/> class.
        /// </summary>
        public ExtractFrontchannelLogoutRequestContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request or <see langword="null"/> if it wasn't extracted yet.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }
    }

    /// <summary>
    /// Represents an event called for each request to the front-channel logout endpoint
    /// to determine if the request is valid and should continue to be processed.
    /// </summary>
    public sealed class ValidateFrontchannelLogoutRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidateFrontchannelLogoutRequestContext"/> class.
        /// </summary>
        public ValidateFrontchannelLogoutRequestContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        public OpenIddictRequest Request
        {
            get => Transaction.Request!;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets the session identifier ("sid") specified by the authorization server.
        /// </summary>
        public string? SessionId { get; set; }
    }

    /// <summary>
    /// Represents an event called for each validated front-channel logout request to allow the user code to
    /// terminate the session identified by the request (OpenID Connect Front-Channel Logout 1.0, section 3).
    /// </summary>
    public sealed class HandleFrontchannelLogoutRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleFrontchannelLogoutRequestContext"/> class.
        /// </summary>
        public HandleFrontchannelLogoutRequestContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        public OpenIddictRequest Request
        {
            get => Transaction.Request!;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets the session identifier ("sid") specified by the authorization server.
        /// </summary>
        public string? SessionId { get; set; }

        /// <summary>
        /// Determines whether the specified principal (typically extracted from the local authentication
        /// cookie) represents the session targeted by the front-channel logout request: the principal
        /// must contain a "sid" claim matching <see cref="SessionId"/> and, when present, its registration
        /// identifier and the issuer of its "sid" claim must match the resolved client registration.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <returns><see langword="true"/> if the principal matches the session, <see langword="false"/> otherwise.</returns>
        public bool IsMatchingSession(ClaimsPrincipal principal)
        {
            ArgumentNullException.ThrowIfNull(principal);

            if (string.IsNullOrEmpty(SessionId) || Transaction.Registration is not OpenIddictClientRegistration registration)
            {
                return false;
            }

            // Note: session identifiers are only unique per issuer.
            //
            // See https://openid.net/specs/openid-connect-frontchannel-1_0.html#ClaimsContents for more information.
            var claim = principal.FindFirst(Claims.SessionId);
            if (claim is null || !string.Equals(claim.Value, SessionId, StringComparison.Ordinal))
            {
                return false;
            }

            var identifier = principal.GetClaim(Claims.Private.RegistrationId);
            if (!string.IsNullOrEmpty(identifier) && !string.Equals(identifier, registration.RegistrationId, StringComparison.Ordinal))
            {
                return false;
            }

            if (Uri.TryCreate(claim.Issuer, UriKind.Absolute, out Uri? issuer) && !OpenIddictHelpers.IsImplicitFileUri(issuer) &&
                registration.Issuer is { IsAbsoluteUri: true } &&
                !string.Equals(issuer.AbsoluteUri.TrimEnd('/'), registration.Issuer.AbsoluteUri.TrimEnd('/'), StringComparison.Ordinal))
            {
                return false;
            }

            return true;
        }
    }

    /// <summary>
    /// Represents an event called before the front-channel logout response is returned to the caller.
    /// </summary>
    public sealed class ApplyFrontchannelLogoutResponseContext : BaseRequestContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyFrontchannelLogoutResponseContext"/> class.
        /// </summary>
        public ApplyFrontchannelLogoutResponseContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request, or <see langword="null"/> if it couldn't be extracted.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets the response.
        /// </summary>
        public OpenIddictResponse Response
        {
            get => Transaction.Response!;
            set => Transaction.Response = value;
        }
    }
}
