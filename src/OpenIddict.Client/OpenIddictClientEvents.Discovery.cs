/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Client;

public static partial class OpenIddictClientEvents
{
    /// <summary>
    /// Represents an event called for each request to the configuration endpoint
    /// to give the user code a chance to add parameters to the configuration request.
    /// </summary>
    public class PrepareConfigurationRequestContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="PrepareConfigurationRequestContext"/> class.
        /// </summary>
        public PrepareConfigurationRequestContext(OpenIddictClientTransaction transaction)
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
    /// Represents an event called for each request to the configuration endpoint
    /// to send the configuration request to the remote authorization server.
    /// </summary>
    public class ApplyConfigurationRequestContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyConfigurationRequestContext"/> class.
        /// </summary>
        public ApplyConfigurationRequestContext(OpenIddictClientTransaction transaction)
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
    /// Represents an event called for each configuration response
    /// to extract the response parameters from the server response.
    /// </summary>
    public class ExtractConfigurationResponseContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractConfigurationResponseContext"/> class.
        /// </summary>
        public ExtractConfigurationResponseContext(OpenIddictClientTransaction transaction)
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
    /// Represents an event called for each validated configuration response.
    /// </summary>
    public class HandleConfigurationResponseContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleConfigurationResponseContext"/> class.
        /// </summary>
        public HandleConfigurationResponseContext(OpenIddictClientTransaction transaction)
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
        /// Gets the OpenID Connect configuration.
        /// </summary>
        public OpenIddictConfiguration Configuration { get; } = new OpenIddictConfiguration();
    }

    /// <summary>
    /// Represents an event called for each request to the cryptography endpoint
    /// to give the user code a chance to add parameters to the cryptography request.
    /// </summary>
    public class PrepareCryptographyRequestContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="PrepareCryptographyRequestContext"/> class.
        /// </summary>
        public PrepareCryptographyRequestContext(OpenIddictClientTransaction transaction)
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
    /// Represents an event called for each request to the cryptography endpoint
    /// to send the cryptography request to the remote authorization server.
    /// </summary>
    public class ApplyCryptographyRequestContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyCryptographyRequestContext"/> class.
        /// </summary>
        public ApplyCryptographyRequestContext(OpenIddictClientTransaction transaction)
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
    /// Represents an event called for each cryptography response
    /// to extract the response parameters from the server response.
    /// </summary>
    public class ExtractCryptographyResponseContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractCryptographyResponseContext"/> class.
        /// </summary>
        public ExtractCryptographyResponseContext(OpenIddictClientTransaction transaction)
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
    /// Represents an event called for each validated cryptography response.
    /// </summary>
    public class HandleCryptographyResponseContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleCryptographyResponseContext"/> class.
        /// </summary>
        public HandleCryptographyResponseContext(OpenIddictClientTransaction transaction)
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
        /// Gets the security keys.
        /// </summary>
        public JsonWebKeySet SecurityKeys { get; } = new JsonWebKeySet();
    }
}
