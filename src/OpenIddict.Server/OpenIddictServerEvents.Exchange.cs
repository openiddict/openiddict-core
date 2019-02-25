/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Security.Claims;
using JetBrains.Annotations;

namespace OpenIddict.Server
{
    public static partial class OpenIddictServerEvents
    {
        /// <summary>
        /// Represents an event called for each request to the token endpoint to give the user code
        /// a chance to manually extract the token request from the ambient HTTP context.
        /// </summary>
        public class ExtractTokenRequestContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ExtractTokenRequestContext"/> class.
            /// </summary>
            public ExtractTokenRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }
        }

        /// <summary>
        /// Represents an event called for each request to the token endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public class ValidateTokenRequestContext : BaseValidatingClientContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ValidateTokenRequestContext"/> class.
            /// </summary>
            public ValidateTokenRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets or sets the security principal extracted from the authorization
            /// code or the refresh token, if applicable to the current token request.
            /// </summary>
            public ClaimsPrincipal Principal { get; set; }
        }

        /// <summary>
        /// Represents an event called for each validated token request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public class HandleTokenRequestContext : BaseValidatingTicketContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="HandleTokenRequestContext"/> class.
            /// </summary>
            public HandleTokenRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }
        }

        /// <summary>
        /// Represents an event called before the token response is returned to the caller.
        /// </summary>
        public class ApplyTokenResponseContext : BaseRequestContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ApplyTokenResponseContext"/> class.
            /// </summary>
            public ApplyTokenResponseContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets or sets the security principal used to forge the token response.
            /// </summary>
            public ClaimsPrincipal Principal { get; set; }

            /// <summary>
            /// Gets the error code returned to the client application.
            /// When the response indicates a successful response,
            /// this property returns <c>null</c>.
            /// </summary>
            public string Error => Response.Error;
        }
    }
}
