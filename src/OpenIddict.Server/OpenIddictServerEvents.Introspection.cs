/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Security.Claims;
using OpenIddict.Abstractions;

namespace OpenIddict.Server
{
    public static partial class OpenIddictServerEvents
    {
        /// <summary>
        /// Represents an event called for each request to the introspection endpoint to give the user code
        /// a chance to manually extract the introspection request from the ambient HTTP context.
        /// </summary>
        public class ExtractIntrospectionRequestContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ExtractIntrospectionRequestContext"/> class.
            /// </summary>
            public ExtractIntrospectionRequestContext(OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets or sets the request, or <c>null</c> if it wasn't extracted yet.
            /// </summary>
            public OpenIddictRequest? Request
            {
                get => Transaction.Request;
                set => Transaction.Request = value;
            }
        }

        /// <summary>
        /// Represents an event called for each request to the introspection endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public class ValidateIntrospectionRequestContext : BaseValidatingClientContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ValidateIntrospectionRequestContext"/> class.
            /// </summary>
            public ValidateIntrospectionRequestContext(OpenIddictServerTransaction transaction)
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
            /// Gets the optional token_type_hint parameter extracted from the
            /// introspection request, or <c>null</c> if it cannot be found.
            /// </summary>
            public string? TokenTypeHint => Request?.TokenTypeHint;

            /// <summary>
            /// Gets or sets the security principal extracted from the introspected token, if available.
            /// </summary>
            public ClaimsPrincipal? Principal { get; set; }
        }

        /// <summary>
        /// Represents an event called for each validated introspection request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public class HandleIntrospectionRequestContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="HandleIntrospectionRequestContext"/> class.
            /// </summary>
            public HandleIntrospectionRequestContext(OpenIddictServerTransaction transaction)
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
            /// Gets or sets the security principal extracted from the introspected token.
            /// </summary>
            public ClaimsPrincipal Principal { get; set; } = default!;

            /// <summary>
            /// Gets the additional claims returned to the caller.
            /// </summary>
            public IDictionary<string, OpenIddictParameter> Claims { get; } =
                new Dictionary<string, OpenIddictParameter>(StringComparer.Ordinal);

            /// <summary>
            /// Gets the list of audiences returned to the caller
            /// as part of the "aud" claim, if applicable.
            /// </summary>
            public HashSet<string> Audiences { get; } = new HashSet<string>(StringComparer.Ordinal);

            /// <summary>
            /// Gets or sets the "client_id" claim returned to the caller, if applicable.
            /// </summary>
            public string? ClientId { get; set; }

            /// <summary>
            /// Gets or sets the "exp" claim
            /// returned to the caller, if applicable.
            /// </summary>
            public DateTimeOffset? ExpiresAt { get; set; }

            /// <summary>
            /// Gets or sets the "iat" claim
            /// returned to the caller, if applicable.
            /// </summary>
            public DateTimeOffset? IssuedAt { get; set; }

            /// <summary>
            /// Gets or sets the "nbf" claim
            /// returned to the caller, if applicable.
            /// </summary>
            public DateTimeOffset? NotBefore { get; set; }

            /// <summary>
            /// Gets the list of scopes returned to the caller
            /// as part of the "scope" claim, if applicable.
            /// </summary>
            public HashSet<string> Scopes { get; } = new HashSet<string>(StringComparer.Ordinal);

            /// <summary>
            /// Gets or sets the "sub" claim
            /// returned to the caller, if applicable.
            /// </summary>
            public string? Subject { get; set; }

            /// <summary>
            /// Gets or sets the "jti" claim
            /// returned to the caller, if applicable.
            /// </summary>
            public string? TokenId { get; set; }

            /// <summary>
            /// Gets or sets the "token_type" claim
            /// returned to the caller, if applicable.
            /// </summary>
            public string? TokenType { get; set; }

            /// <summary>
            /// Gets or sets the "token_usage" claim
            /// returned to the caller, if applicable.
            /// </summary>
            public string? TokenUsage { get; set; }

            /// <summary>
            /// Gets or sets the "username" claim
            /// returned to the caller, if applicable.
            /// </summary>
            public string? Username { get; set; }
        }

        /// <summary>
        /// Represents an event called before the introspection response is returned to the caller.
        /// </summary>
        public class ApplyIntrospectionResponseContext : BaseRequestContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ApplyIntrospectionResponseContext"/> class.
            /// </summary>
            public ApplyIntrospectionResponseContext(OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets or sets the request, or <c>null</c> if it couldn't be extracted.
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
            /// this property returns <c>null</c>.
            /// </summary>
            public string? Error => Response.Error;
        }
    }
}
