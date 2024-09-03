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
    /// Represents an event called for each request to the userinfo endpoint
    /// to give the user code a chance to add parameters to the userinfo request.
    /// </summary>
    public sealed class PrepareUserInfoRequestContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="PrepareUserInfoRequestContext"/> class.
        /// </summary>
        public PrepareUserInfoRequestContext(OpenIddictClientTransaction transaction)
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
    /// Represents an event called for each request to the userinfo endpoint
    /// to send the userinfo request to the remote authorization server.
    /// </summary>
    public sealed class ApplyUserInfoRequestContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyUserInfoRequestContext"/> class.
        /// </summary>
        public ApplyUserInfoRequestContext(OpenIddictClientTransaction transaction)
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
    /// Represents an event called for each userinfo response
    /// to extract the response parameters from the server response.
    /// </summary>
    public sealed class ExtractUserInfoResponseContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractUserInfoResponseContext"/> class.
        /// </summary>
        public ExtractUserInfoResponseContext(OpenIddictClientTransaction transaction)
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

        /// <summary>
        /// Gets or sets the userinfo token, if available.
        /// </summary>
        public string? UserInfoToken { get; set; }
    }

    /// <summary>
    /// Represents an event called for each userinfo response.
    /// </summary>
    public sealed class HandleUserInfoResponseContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleUserInfoResponseContext"/> class.
        /// </summary>
        public HandleUserInfoResponseContext(OpenIddictClientTransaction transaction)
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
        /// Gets or sets the userinfo token, if available.
        /// </summary>
        public string? UserInfoToken { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims resolved from the userinfo response.
        /// </summary>
        public ClaimsPrincipal? Principal { get; set; }
    }
}
