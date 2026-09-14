/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client;

public static partial class OpenIddictClientEvents
{
    /// <summary>
    /// Represents an abstract base class used by the dynamic client registration events (RFC 7591 and RFC 7592).
    /// </summary>
    public abstract class BaseRegistrationContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="BaseRegistrationContext"/> class.
        /// </summary>
        protected BaseRegistrationContext(OpenIddictClientTransaction transaction)
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
        /// Gets or sets the HTTP method used to send the request: POST for registration requests (RFC 7591)
        /// and GET, PUT or DELETE for read, update and delete requests (RFC 7592).
        /// </summary>
        public string RequestMethod { get; set; } = "POST";

        /// <summary>
        /// Gets or sets the bearer token attached to the request (i.e the initial access
        /// token for registration requests or the registration access token), if applicable.
        /// </summary>
        public string? AccessToken { get; set; }
    }

    /// <summary>
    /// Represents an event called for each request to the registration endpoint
    /// to give the user code a chance to add metadata to the registration request.
    /// </summary>
    public sealed class PrepareRegistrationRequestContext : BaseRegistrationContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="PrepareRegistrationRequestContext"/> class.
        /// </summary>
        public PrepareRegistrationRequestContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }
    }

    /// <summary>
    /// Represents an event called for each request to the registration endpoint
    /// to send the registration request to the remote authorization server.
    /// </summary>
    public sealed class ApplyRegistrationRequestContext : BaseRegistrationContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyRegistrationRequestContext"/> class.
        /// </summary>
        public ApplyRegistrationRequestContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }
    }

    /// <summary>
    /// Represents an event called for each registration response
    /// to extract the response parameters from the server response.
    /// </summary>
    public sealed class ExtractRegistrationResponseContext : BaseRegistrationContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractRegistrationResponseContext"/> class.
        /// </summary>
        public ExtractRegistrationResponseContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
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
    /// Represents an event called for each registration response.
    /// </summary>
    public sealed class HandleRegistrationResponseContext : BaseRegistrationContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleRegistrationResponseContext"/> class.
        /// </summary>
        public HandleRegistrationResponseContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
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
