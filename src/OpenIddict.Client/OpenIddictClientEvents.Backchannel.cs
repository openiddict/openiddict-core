/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client;

public static partial class OpenIddictClientEvents
{
    /// <summary>
    /// Represents an event called for each request to the backchannel authentication endpoint
    /// to give the user code a chance to add parameters to the backchannel authentication request.
    /// </summary>
    public sealed class PrepareBackchannelAuthenticationRequestContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="PrepareBackchannelAuthenticationRequestContext"/> class.
        /// </summary>
        public PrepareBackchannelAuthenticationRequestContext(OpenIddictClientTransaction transaction)
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
    /// Represents an event called for each request to the backchannel authentication endpoint
    /// to send the backchannel authentication request to the remote authorization server.
    /// </summary>
    public sealed class ApplyBackchannelAuthenticationRequestContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyBackchannelAuthenticationRequestContext"/> class.
        /// </summary>
        public ApplyBackchannelAuthenticationRequestContext(OpenIddictClientTransaction transaction)
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
    /// Represents an event called for each backchannel authentication response
    /// to extract the response parameters from the server response.
    /// </summary>
    public sealed class ExtractBackchannelAuthenticationResponseContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractBackchannelAuthenticationResponseContext"/> class.
        /// </summary>
        public ExtractBackchannelAuthenticationResponseContext(OpenIddictClientTransaction transaction)
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
    /// Represents an event called for each backchannel authentication response.
    /// </summary>
    public sealed class HandleBackchannelAuthenticationResponseContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleBackchannelAuthenticationResponseContext"/> class.
        /// </summary>
        public HandleBackchannelAuthenticationResponseContext(OpenIddictClientTransaction transaction)
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
    }
}
