/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using JetBrains.Annotations;

namespace OpenIddict.Server
{
    public static partial class OpenIddictServerEvents
    {
        /// <summary>
        /// Represents an event called for each request to the device endpoint to give the user code
        /// a chance to manually extract the device request from the ambient HTTP context.
        /// </summary>
        public class ExtractDeviceRequestContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ExtractDeviceRequestContext"/> class.
            /// </summary>
            public ExtractDeviceRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }
        }

        /// <summary>
        /// Represents an event called for each request to the device endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public class ValidateDeviceRequestContext : BaseValidatingClientContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ValidateDeviceRequestContext"/> class.
            /// </summary>
            public ValidateDeviceRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }
        }

        /// <summary>
        /// Represents an event called for each validated device request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public class HandleDeviceRequestContext : BaseValidatingTicketContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="HandleDeviceRequestContext"/> class.
            /// </summary>
            public HandleDeviceRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }
        }

        /// <summary>
        /// Represents an event called before the device response is returned to the caller.
        /// </summary>
        public class ApplyDeviceResponseContext : BaseRequestContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ApplyDeviceResponseContext"/> class.
            /// </summary>
            public ApplyDeviceResponseContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets the error code returned to the client application.
            /// When the response indicates a successful response,
            /// this property returns <c>null</c>.
            /// </summary>
            public string Error => Response.Error;
        }

        /// <summary>
        /// Represents an event called for each request to the verification endpoint to give the user code
        /// a chance to manually extract the verification request from the ambient HTTP context.
        /// </summary>
        public class ExtractVerificationRequestContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ExtractVerificationRequestContext"/> class.
            /// </summary>
            public ExtractVerificationRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }
        }

        /// <summary>
        /// Represents an event called for each request to the verification endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public class ValidateVerificationRequestContext : BaseValidatingClientContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ValidateVerificationRequestContext"/> class.
            /// </summary>
            public ValidateVerificationRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets or sets the security principal extracted from the user code.
            /// </summary>
            public ClaimsPrincipal Principal { get; set; }
        }

        /// <summary>
        /// Represents an event called for each validated verification request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public class HandleVerificationRequestContext : BaseValidatingTicketContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="HandleVerificationRequestContext"/> class.
            /// </summary>
            public HandleVerificationRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }
        }

        /// <summary>
        /// Represents an event called before the verification response is returned to the caller.
        /// </summary>
        public class ApplyVerificationResponseContext : BaseRequestContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ApplyVerificationResponseContext"/> class.
            /// </summary>
            public ApplyVerificationResponseContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets the error code returned to the client application.
            /// When the response indicates a successful response,
            /// this property returns <c>null</c>.
            /// </summary>
            public string Error => Response.Error;
        }
    }
}
