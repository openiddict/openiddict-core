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
    /// Represents an event called for each request to the logout endpoint to give the user code
    /// a chance to manually update the logout request before it is sent to the identity provider.
    /// </summary>
    public sealed class PrepareLogoutRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="PrepareLogoutRequestContext"/> class.
        /// </summary>
        public PrepareLogoutRequestContext(OpenIddictClientTransaction transaction)
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
        /// Gets or sets the principal containing the claims stored in the state object.
        /// </summary>
        public ClaimsPrincipal StatePrincipal { get; set; } = new ClaimsPrincipal(new ClaimsIdentity());
    }

    /// <summary>
    /// Represents an event called for each request to the logout endpoint
    /// to give the user code a chance to manually send the logout request.
    /// </summary>
    public sealed class ApplyLogoutRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="PrepareLogoutRequestContext"/> class.
        /// </summary>
        public ApplyLogoutRequestContext(OpenIddictClientTransaction transaction)
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

        public string EndSessionEndpoint { get; set; } = null!;
    }

    /// <summary>
    /// Represents an event called for each request to the post-logout redirection endpoint to give the user code
    /// a chance to manually extract the redirection request from the ambient HTTP context.
    /// </summary>
    public sealed class ExtractPostLogoutRedirectionRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractPostLogoutRedirectionRequestContext"/> class.
        /// </summary>
        public ExtractPostLogoutRedirectionRequestContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request or <see langword="null"/> if it was extracted yet.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }
    }

    /// <summary>
    /// Represents an event called for each request to the post-logout redirection endpoint
    /// to determine if the request is valid and should continue to be processed.
    /// </summary>
    public sealed class ValidatePostLogoutRedirectionRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidatePostLogoutRedirectionRequestContext"/> class.
        /// </summary>
        public ValidatePostLogoutRedirectionRequestContext(OpenIddictClientTransaction transaction)
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
        /// Gets or sets the security principal extracted from the identity token,
        /// if applicable to the current redirection request. If no identity token
        /// is available at the validation stage, a token request will typically be
        /// sent to retrieve a complete set of tokens (e.g logout code flow).
        /// </summary>
        public ClaimsPrincipal? Principal { get; set; }

        /// <summary>
        /// Gets or sets the security principal extracted from the state token.
        /// </summary>
        public ClaimsPrincipal? StateTokenPrincipal { get; set; }
    }

    /// <summary>
    /// Represents an event called for each validated redirection request
    /// to allow the user code to decide how the request should be handled.
    /// </summary>
    public sealed class HandlePostLogoutRedirectionRequestContext : BaseValidatingTicketContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandlePostLogoutRedirectionRequestContext"/> class.
        /// </summary>
        public HandlePostLogoutRedirectionRequestContext(OpenIddictClientTransaction transaction)
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
        /// Gets the additional parameters returned to the client application.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Parameters { get; private set; }
            = new(StringComparer.Ordinal);
    }

    /// <summary>
    /// Represents an event called before the redirection response is returned to the caller.
    /// </summary>
    public sealed class ApplyPostLogoutRedirectionResponseContext : BaseRequestContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyPostLogoutRedirectionResponseContext"/> class.
        /// </summary>
        public ApplyPostLogoutRedirectionResponseContext(OpenIddictClientTransaction transaction)
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
