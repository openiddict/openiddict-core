/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Security.Claims;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace OpenIddict.Validation
{
    public static partial class OpenIddictValidationEvents
    {
        /// <summary>
        /// Represents an abstract base class used for certain event contexts.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public abstract class BaseContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="BaseContext"/> class.
            /// </summary>
            protected BaseContext([NotNull] OpenIddictValidationTransaction transaction)
                => Transaction = transaction ?? throw new ArgumentNullException(nameof(transaction));

            /// <summary>
            /// Gets the environment associated with the current request being processed.
            /// </summary>
            public OpenIddictValidationTransaction Transaction { get; }

            /// <summary>
            /// Gets or sets the endpoint type that handled the request, if applicable.
            /// </summary>
            public OpenIddictValidationEndpointType EndpointType
            {
                get => Transaction.EndpointType;
                set => Transaction.EndpointType = value;
            }

            /// <summary>
            /// Gets or sets the issuer address associated with the current transaction, if available.
            /// </summary>
            public Uri Issuer
            {
                get => Transaction.Issuer;
                set => Transaction.Issuer = value;
            }

            /// <summary>
            /// Gets the logger responsible of logging processed operations.
            /// </summary>
            public ILogger Logger => Transaction.Logger;

            /// <summary>
            /// Gets the OpenIddict validation options.
            /// </summary>
            public OpenIddictValidationOptions Options => Transaction.Options;

            /// <summary>
            /// Gets the dictionary containing the properties associated with this event.
            /// </summary>
            public IDictionary<string, object> Properties { get; }
                = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

            /// <summary>
            /// Gets or sets the OpenIddict request or <c>null</c> if it couldn't be extracted.
            /// </summary>
            public OpenIddictRequest Request
            {
                get => Transaction.Request;
                set => Transaction.Request = value;
            }

            /// <summary>
            /// Gets or sets the OpenIddict response, if applicable.
            /// </summary>
            public OpenIddictResponse Response
            {
                get => Transaction.Response;
                set => Transaction.Response = value;
            }
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public abstract class BaseRequestContext : BaseContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="BaseRequestContext"/> class.
            /// </summary>
            protected BaseRequestContext([NotNull] OpenIddictValidationTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets a boolean indicating whether the request was fully handled.
            /// </summary>
            public bool IsRequestHandled { get; private set; }

            /// <summary>
            /// Gets a boolean indicating whether the request processing was skipped.
            /// </summary>
            public bool IsRequestSkipped { get; private set; }

            /// <summary>
            /// Marks the request as fully handled. Once declared handled,
            /// a request shouldn't be processed further by the underlying host.
            /// </summary>
            public void HandleRequest() => IsRequestHandled = true;

            /// <summary>
            /// Marks the request as skipped. Once declared skipped, a request
            /// shouldn't be processed further by OpenIddict but should be allowed
            /// to go through the next components in the processing pipeline
            /// (if this pattern is supported by the underlying host).
            /// </summary>
            public void SkipRequest() => IsRequestSkipped = true;
        }

        /// <summary>
        /// Represents an abstract base class used for certain event contexts.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public abstract class BaseValidatingContext : BaseRequestContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="BaseValidatingContext"/> class.
            /// </summary>
            protected BaseValidatingContext([NotNull] OpenIddictValidationTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets a boolean indicating whether the request will be rejected.
            /// </summary>
            public bool IsRejected { get; protected set; }

            /// <summary>
            /// Gets or sets the "error" parameter returned to the client application.
            /// </summary>
            public string Error { get; private set; }

            /// <summary>
            /// Gets or sets the "error_description" parameter returned to the client application.
            /// </summary>
            public string ErrorDescription { get; private set; }

            /// <summary>
            /// Gets or sets the "error_uri" parameter returned to the client application.
            /// </summary>
            public string ErrorUri { get; private set; }

            /// <summary>
            /// Rejects the request.
            /// </summary>
            public virtual void Reject() => IsRejected = true;

            /// <summary>
            /// Rejects the request.
            /// </summary>
            /// <param name="error">The "error" parameter returned to the client application.</param>
            public virtual void Reject(string error)
            {
                Error = error;

                Reject();
            }

            /// <summary>
            /// Rejects the request.
            /// </summary>
            /// <param name="error">The "error" parameter returned to the client application.</param>
            /// <param name="description">The "error_description" parameter returned to the client application.</param>
            public virtual void Reject(string error, string description)
            {
                Error = error;
                ErrorDescription = description;

                Reject();
            }

            /// <summary>
            /// Rejects the request.
            /// </summary>
            /// <param name="error">The "error" parameter returned to the client application.</param>
            /// <param name="description">The "error_description" parameter returned to the client application.</param>
            /// <param name="uri">The "error_uri" parameter returned to the client application.</param>
            public virtual void Reject(string error, string description, string uri)
            {
                Error = error;
                ErrorDescription = description;
                ErrorUri = uri;

                Reject();
            }
        }

        /// <summary>
        /// Represents an event called when processing an incoming request.
        /// </summary>
        public class ProcessRequestContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ProcessRequestContext"/> class.
            /// </summary>
            public ProcessRequestContext([NotNull] OpenIddictValidationTransaction transaction)
                : base(transaction)
            {
            }
        }

        /// <summary>
        /// Represents an event called when processing an errored response.
        /// </summary>
        public class ProcessErrorContext : BaseRequestContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ProcessErrorContext"/> class.
            /// </summary>
            public ProcessErrorContext([NotNull] OpenIddictValidationTransaction transaction)
                : base(transaction)
            {
            }
        }

        /// <summary>
        /// Represents an event called when processing an authentication operation.
        /// </summary>
        public class ProcessAuthenticationContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ProcessAuthenticationContext"/> class.
            /// </summary>
            public ProcessAuthenticationContext([NotNull] OpenIddictValidationTransaction transaction)
                : base(transaction)
                => TokenValidationParameters = transaction.Options.TokenValidationParameters.Clone();

            /// <summary>
            /// Gets the token validation parameters used for the current request.
            /// </summary>
            public TokenValidationParameters TokenValidationParameters { get; }

            /// <summary>
            /// Gets or sets the security principal.
            /// </summary>
            public ClaimsPrincipal Principal { get; set; }
        }

        /// <summary>
        /// Represents an event called when processing a challenge response.
        /// </summary>
        public class ProcessChallengeContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ProcessChallengeContext"/> class.
            /// </summary>
            public ProcessChallengeContext([NotNull] OpenIddictValidationTransaction transaction)
                : base(transaction)
            {
            }
        }
    }
}
