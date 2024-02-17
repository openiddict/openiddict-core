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
    /// Represents an event called for each request to the revocation endpoint
    /// to give the user code a chance to add parameters to the revocation request.
    /// </summary>
    public sealed class PrepareRevocationRequestContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="PrepareRevocationRequestContext"/> class.
        /// </summary>
        public PrepareRevocationRequestContext(OpenIddictClientTransaction transaction)
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
        /// Gets or sets the token sent to the revocation endpoint.
        /// </summary>
        public string? Token
        {
            get => Request.Token;
            set => Request.Token = value;
        }

        /// <summary>
        /// Gets or sets the token type sent to the revocation endpoint.
        /// </summary>
        public string? TokenTypeHint
        {
            get => Request.TokenTypeHint;
            set => Request.TokenTypeHint = value;
        }
    }

    /// <summary>
    /// Represents an event called for each request to the revocation endpoint
    /// to send the revocation request to the remote authorization server.
    /// </summary>
    public sealed class ApplyRevocationRequestContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyRevocationRequestContext"/> class.
        /// </summary>
        public ApplyRevocationRequestContext(OpenIddictClientTransaction transaction)
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
    /// Represents an event called for each revocation response
    /// to extract the response parameters from the server response.
    /// </summary>
    public sealed class ExtractRevocationResponseContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractRevocationResponseContext"/> class.
        /// </summary>
        public ExtractRevocationResponseContext(OpenIddictClientTransaction transaction)
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
    /// Represents an event called for each revocation response.
    /// </summary>
    public sealed class HandleRevocationResponseContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleRevocationResponseContext"/> class.
        /// </summary>
        public HandleRevocationResponseContext(OpenIddictClientTransaction transaction)
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
        /// Gets or sets the token sent to the revocation endpoint.
        /// </summary>
        public string? Token { get; set; }
    }
}
