/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;

namespace OpenIddict.Server;

public static partial class OpenIddictServerEvents
{
    /// <summary>
    /// Represents an event called for each request to the backchannel authentication endpoint to give
    /// the user code a chance to manually extract the request from the ambient HTTP context.
    /// </summary>
    public sealed class ExtractBackchannelAuthenticationRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractBackchannelAuthenticationRequestContext"/> class.
        /// </summary>
        public ExtractBackchannelAuthenticationRequestContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request, or <see langword="null"/> if it wasn't extracted yet.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }
    }

    /// <summary>
    /// Represents an event called for each request to the backchannel authentication endpoint
    /// to determine if the request is valid and should continue to be processed.
    /// </summary>
    public sealed class ValidateBackchannelAuthenticationRequestContext : BaseValidatingClientContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidateBackchannelAuthenticationRequestContext"/> class.
        /// </summary>
        public ValidateBackchannelAuthenticationRequestContext(OpenIddictServerTransaction transaction)
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
        /// Gets or sets the security principal extracted
        /// from the identity token hint, if applicable.
        /// </summary>
        public ClaimsPrincipal? IdentityTokenHintPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the security principal extracted from the signed
        /// authentication request (i.e the "request" parameter), if applicable.
        /// </summary>
        public ClaimsPrincipal? RequestObjectPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the JWS algorithm used to sign the authentication request, if applicable.
        /// </summary>
        public string? RequestObjectSigningAlgorithm { get; set; }

        /// <summary>
        /// Gets or sets the token delivery mode (poll, ping or push) registered for the client application.
        /// </summary>
        public string? TokenDeliveryMode { get; set; }
    }

    /// <summary>
    /// Represents an event called for each validated backchannel authentication request to allow the user code
    /// to identify the end user (using the login_hint, login_hint_token or id_token_hint parameters), notify
    /// the end user out-of-band and attach a principal containing the identity of the end user.
    /// </summary>
    public sealed class HandleBackchannelAuthenticationRequestContext : BaseValidatingTicketContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleBackchannelAuthenticationRequestContext"/> class.
        /// </summary>
        public HandleBackchannelAuthenticationRequestContext(OpenIddictServerTransaction transaction)
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
        /// Gets or sets the security principal extracted
        /// from the identity token hint, if applicable.
        /// </summary>
        public ClaimsPrincipal? IdentityTokenHintPrincipal { get; set; }

        /// <summary>
        /// Gets the additional parameters returned to the client application.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Parameters { get; private set; }
            = new(StringComparer.Ordinal);

        /// <summary>
        /// Allows OpenIddict to return a sign-in response using the specified principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        public void SignIn(ClaimsPrincipal principal) => Principal = principal;

        /// <summary>
        /// Allows OpenIddict to return a sign-in response using the specified principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="parameters">The additional parameters returned to the client application.</param>
        public void SignIn(ClaimsPrincipal principal, IDictionary<string, OpenIddictParameter> parameters)
        {
            Principal = principal;
            Parameters = new(parameters, StringComparer.Ordinal);
        }
    }

    /// <summary>
    /// Represents an event called before the backchannel authentication response is returned to the caller.
    /// </summary>
    public sealed class ApplyBackchannelAuthenticationResponseContext : BaseRequestContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyBackchannelAuthenticationResponseContext"/> class.
        /// </summary>
        public ApplyBackchannelAuthenticationResponseContext(OpenIddictServerTransaction transaction)
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

        /// <summary>
        /// Gets the error code returned to the client application.
        /// When the response indicates a successful response,
        /// this property returns <see langword="null"/>.
        /// </summary>
        public string? Error => Response.Error;
    }

    /// <summary>
    /// Represents an event called when a ping or push notification must be sent to the client notification
    /// endpoint of a client application after a backchannel authentication request was completed. Handlers
    /// (e.g the OpenIddict.Server.SystemNetHttp integration) are expected to send the notification and call
    /// <see cref="BaseRequestContext.HandleRequest()"/> once delivered, or to reject the context if delivery failed.
    /// </summary>
    /// <remarks>
    /// See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2
    /// and https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.
    /// </remarks>
    public sealed class SendBackchannelNotificationContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="SendBackchannelNotificationContext"/> class.
        /// </summary>
        public SendBackchannelNotificationContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the identifier of the client application to which the notification is sent.
        /// </summary>
        public required string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client notification endpoint URI.
        /// </summary>
        public required Uri ClientNotificationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the bearer client notification token sent in the Authorization header.
        /// </summary>
        public required string ClientNotificationToken { get; set; }

        /// <summary>
        /// Gets or sets the token delivery mode (ping or push).
        /// </summary>
        public required string TokenDeliveryMode { get; set; }

        /// <summary>
        /// Gets or sets the notification payload, serialized as a JSON object.
        /// </summary>
        public required OpenIddictResponse Notification { get; set; }

        /// <summary>
        /// Gets or sets the attempt number (starting at 1).
        /// </summary>
        public int Attempt { get; set; } = 1;
    }
}
