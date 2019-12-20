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
using OpenIddict.Abstractions;

namespace OpenIddict.Server
{
    public static partial class OpenIddictServerEvents
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
            protected BaseContext([NotNull] OpenIddictServerTransaction transaction)
                => Transaction = transaction ?? throw new ArgumentNullException(nameof(transaction));

            /// <summary>
            /// Gets the environment associated with the current request being processed.
            /// </summary>
            public OpenIddictServerTransaction Transaction { get; }

            /// <summary>
            /// Gets or sets the issuer address associated with the current transaction, if available.
            /// </summary>
            public Uri Issuer
            {
                get => Transaction.Issuer;
                set => Transaction.Issuer = value;
            }

            /// <summary>
            /// Gets or sets the endpoint type that handled the request, if applicable.
            /// </summary>
            public OpenIddictServerEndpointType EndpointType
            {
                get => Transaction.EndpointType;
                set => Transaction.EndpointType = value;
            }

            /// <summary>
            /// Gets the logger responsible of logging processed operations.
            /// </summary>
            public ILogger Logger => Transaction.Logger;

            /// <summary>
            /// Gets the OpenIddict server options.
            /// </summary>
            public OpenIddictServerOptions Options => Transaction.Options;

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
            protected BaseRequestContext([NotNull] OpenIddictServerTransaction transaction)
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
        public abstract class BaseValidatingClientContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="BaseValidatingClientContext"/> class.
            /// </summary>
            protected BaseValidatingClientContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets the "client_id" parameter for the current request.
            /// The authorization server application is responsible for
            /// validating this value to ensure it identifies a registered client.
            /// </summary>
            public string ClientId => (string) Request[OpenIddictConstants.Parameters.ClientId];

            /// <summary>
            /// Gets the "client_secret" parameter for the current request.
            /// The authorization server application is responsible for
            /// validating this value to ensure it identifies a registered client.
            /// </summary>
            public string ClientSecret => (string) Request[OpenIddictConstants.Parameters.ClientSecret];
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
            protected BaseValidatingContext([NotNull] OpenIddictServerTransaction transaction)
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
        /// Represents an abstract base class used for certain event contexts.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public abstract class BaseValidatingTicketContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="BaseValidatingTicketContext"/> class.
            /// </summary>
            protected BaseValidatingTicketContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets or sets the security principal.
            /// </summary>
            public ClaimsPrincipal Principal { get; set; }

            /// <summary>
            /// Gets the client identifier, or <c>null</c> if the client application is unknown.
            /// </summary>
            public string ClientId => Request.ClientId;

            /// <summary>
            /// Gets a boolean indicating whether the
            /// <see cref="HandleAuthentication()"/> method was called.
            /// </summary>
            public bool IsHandled { get; private set; }

            /// <summary>
            /// Marks the authentication process as handled by the application code.
            /// </summary>
            public void HandleAuthentication() => IsHandled = true;
        }

        /// <summary>
        /// Represents an event called when processing an incoming request.
        /// </summary>
        public class ProcessRequestContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ProcessRequestContext"/> class.
            /// </summary>
            public ProcessRequestContext([NotNull] OpenIddictServerTransaction transaction)
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
            public ProcessErrorContext([NotNull] OpenIddictServerTransaction transaction)
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
            public ProcessAuthenticationContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets or sets the security principal.
            /// </summary>
            public ClaimsPrincipal Principal { get; set; }

            /// <summary>
            /// Gets or sets the token to validate.
            /// </summary>
            public string Token { get; set; }

            /// <summary>
            /// Gets or sets the expected type of the token.
            /// </summary>
            public string TokenType { get; set; }
        }

        /// <summary>
        /// Represents an event called when processing a challenge response.
        /// </summary>
        public class ProcessChallengeContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ProcessChallengeContext"/> class.
            /// </summary>
            public ProcessChallengeContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }
        }

        /// <summary>
        /// Represents an event called when processing a sign-in response.
        /// </summary>
        public class ProcessSignInContext : BaseValidatingTicketContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ProcessSignInContext"/> class.
            /// </summary>
            public ProcessSignInContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets or sets a boolean indicating whether an access token
            /// should be returned to the client application.
            /// Note: overriding the value of this property is generally not
            /// recommended, except when dealing with non-standard clients.
            /// </summary>
            public bool IncludeAccessToken { get; set; }

            /// <summary>
            /// Gets or sets a boolean indicating whether an authorization code
            /// should be returned to the client application.
            /// Note: overriding the value of this property is generally not
            /// recommended, except when dealing with non-standard clients.
            /// </summary>
            public bool IncludeAuthorizationCode { get; set; }

            /// <summary>
            /// Gets or sets a boolean indicating whether a device code
            /// should be returned to the client application.
            /// Note: overriding the value of this property is generally not
            /// recommended, except when dealing with non-standard clients.
            /// </summary>
            public bool IncludeDeviceCode { get; set; }

            /// <summary>
            /// Gets or sets a boolean indicating whether an identity token
            /// should be returned to the client application.
            /// Note: overriding the value of this property is generally not
            /// recommended, except when dealing with non-standard clients.
            /// </summary>
            public bool IncludeIdentityToken { get; set; }

            /// <summary>
            /// Gets or sets a boolean indicating whether a refresh token
            /// should be returned to the client application.
            /// Note: overriding the value of this property is generally not
            /// recommended, except when dealing with non-standard clients.
            /// </summary>
            public bool IncludeRefreshToken { get; set; }

            /// <summary>
            /// Gets or sets a boolean indicating whether a user code
            /// should be returned to the client application.
            /// Note: overriding the value of this property is generally not
            /// recommended, except when dealing with non-standard clients.
            /// </summary>
            public bool IncludeUserCode { get; set; }

            /// <summary>
            /// Gets or sets the principal containing the claims that
            /// will be used to create the access token, if applicable.
            /// </summary>
            public ClaimsPrincipal AccessTokenPrincipal { get; set; }

            /// <summary>
            /// Gets or sets the principal containing the claims that
            /// will be used to create the authorization code, if applicable.
            /// </summary>
            public ClaimsPrincipal AuthorizationCodePrincipal { get; set; }

            /// <summary>
            /// Gets or sets the principal containing the claims that
            /// will be used to create the device code, if applicable.
            /// </summary>
            public ClaimsPrincipal DeviceCodePrincipal { get; set; }

            /// <summary>
            /// Gets or sets the principal containing the claims that
            /// will be used to create the identity token, if applicable.
            /// </summary>
            public ClaimsPrincipal IdentityTokenPrincipal { get; set; }

            /// <summary>
            /// Gets or sets the principal containing the claims that
            /// will be used to create the refresh token, if applicable.
            /// </summary>
            public ClaimsPrincipal RefreshTokenPrincipal { get; set; }

            /// <summary>
            /// Gets or sets the principal containing the claims that
            /// will be used to create the user code, if applicable.
            /// </summary>
            public ClaimsPrincipal UserCodePrincipal { get; set; }
        }

        /// <summary>
        /// Represents an event called when processing a sign-out response.
        /// </summary>
        public class ProcessSignOutContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ProcessSignOutContext"/> class.
            /// </summary>
            public ProcessSignOutContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }
        }
    }
}
