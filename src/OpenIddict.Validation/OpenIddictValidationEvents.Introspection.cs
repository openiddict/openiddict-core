/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using OpenIddict.Abstractions;

namespace OpenIddict.Validation
{
    public static partial class OpenIddictValidationEvents
    {
        /// <summary>
        /// Represents an event called for each request to the introspection endpoint
        /// to give the user code a chance to add parameters to the introspection request.
        /// </summary>
        public class PrepareIntrospectionRequestContext : BaseExternalContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="PrepareIntrospectionRequestContext"/> class.
            /// </summary>
            public PrepareIntrospectionRequestContext(OpenIddictValidationTransaction transaction)
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
            /// Gets or sets the token sent to the introspection endpoint.
            /// </summary>
            public string? Token { get; set; }

            /// <summary>
            /// Gets or sets the token type sent to the introspection endpoint.
            /// </summary>
            public string? TokenTypeHint { get; set; }
        }

        /// <summary>
        /// Represents an event called for each request to the introspection endpoint
        /// to send the introspection request to the remote authorization server.
        /// </summary>
        public class ApplyIntrospectionRequestContext : BaseExternalContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ApplyIntrospectionRequestContext"/> class.
            /// </summary>
            public ApplyIntrospectionRequestContext(OpenIddictValidationTransaction transaction)
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
        /// Represents an event called for each introspection response
        /// to extract the response parameters from the server response.
        /// </summary>
        public class ExtractIntrospectionResponseContext : BaseExternalContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ExtractIntrospectionResponseContext"/> class.
            /// </summary>
            public ExtractIntrospectionResponseContext(OpenIddictValidationTransaction transaction)
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
            /// Gets or sets the response, or <c>null</c> if it wasn't extracted yet.
            /// </summary>
            public OpenIddictResponse? Response
            {
                get => Transaction.Response;
                set => Transaction.Response = value;
            }
        }

        /// <summary>
        /// Represents an event called for each introspection response.
        /// </summary>
        public class HandleIntrospectionResponseContext : BaseExternalContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="HandleIntrospectionResponseContext"/> class.
            /// </summary>
            public HandleIntrospectionResponseContext(OpenIddictValidationTransaction transaction)
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
            /// Gets or sets the token sent to the introspection endpoint.
            /// </summary>
            public string? Token { get; set; }

            /// <summary>
            /// Gets or sets the principal containing the claims resolved from the introspection response.
            /// </summary>
            public ClaimsPrincipal? Principal { get; set; }
        }
    }
}
