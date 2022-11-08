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
    /// Represents an event called for each request to the token endpoint
    /// to give the user code a chance to add parameters to the token request.
    /// </summary>
    public sealed class PrepareTokenRequestContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="PrepareTokenRequestContext"/> class.
        /// </summary>
        public PrepareTokenRequestContext(OpenIddictClientTransaction transaction)
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
        /// Gets or sets the grant type sent to the token endpoint.
        /// </summary>
        public string? GrantType { get; set; }

        /// <summary>
        /// Gets or sets the authorization code sent to the token endpoint, if applicable.
        /// </summary>
        public string? AuthorizationCode { get; set; }
    }

    /// <summary>
    /// Represents an event called for each request to the token endpoint
    /// to send the token request to the remote authorization server.
    /// </summary>
    public sealed class ApplyTokenRequestContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyTokenRequestContext"/> class.
        /// </summary>
        public ApplyTokenRequestContext(OpenIddictClientTransaction transaction)
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
    }

    /// <summary>
    /// Represents an event called for each token response
    /// to extract the response parameters from the server response.
    /// </summary>
    public sealed class ExtractTokenResponseContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractTokenResponseContext"/> class.
        /// </summary>
        public ExtractTokenResponseContext(OpenIddictClientTransaction transaction)
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
        /// Gets or sets the response, or <see langword="null"/> if it wasn't extracted yet.
        /// </summary>
        public OpenIddictResponse? Response
        {
            get => Transaction.Response;
            set => Transaction.Response = value;
        }
    }

    /// <summary>
    /// Represents an event called for each token response.
    /// </summary>
    public sealed class HandleTokenResponseContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleTokenResponseContext"/> class.
        /// </summary>
        public HandleTokenResponseContext(OpenIddictClientTransaction transaction)
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
        /// Gets or sets the response.
        /// </summary>
        public OpenIddictResponse Response
        {
            get => Transaction.Response!;
            set => Transaction.Response = value;
        }

        /// <summary>
        /// Gets or sets the access token resolved from the token response.
        /// </summary>
        public string? AccessToken { get; set; }

        /// <summary>
        /// Gets or sets the identity token resolved from the token response.
        /// </summary>
        public string? IdentityToken { get; set; }

        /// <summary>
        /// Gets or sets the refresh token resolved from the token response.
        /// </summary>
        public string? RefreshToken { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims resolved from the token response.
        /// </summary>
        public ClaimsPrincipal? Principal { get; set; }
    }
}
