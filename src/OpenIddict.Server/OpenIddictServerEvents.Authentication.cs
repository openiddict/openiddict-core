/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using JetBrains.Annotations;

namespace OpenIddict.Server
{
    public static partial class OpenIddictServerEvents
    {
        /// <summary>
        /// Represents an event called for each request to the authorization endpoint to give the user code
        /// a chance to manually extract the authorization request from the ambient HTTP context.
        /// </summary>
        public class ExtractAuthorizationRequestContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ExtractAuthorizationRequestContext"/> class.
            /// </summary>
            public ExtractAuthorizationRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }
        }

        /// <summary>
        /// Represents an event called for each request to the authorization endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public class ValidateAuthorizationRequestContext : BaseValidatingContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ValidateAuthorizationRequestContext"/> class.
            /// </summary>
            public ValidateAuthorizationRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
                // Infer the redirect_uri from the value specified by the client application.
                => RedirectUri = Request?.RedirectUri;

            /// <summary>
            /// Gets the client_id specified by the client application.
            /// </summary>
            public string ClientId => Request.ClientId;

            /// <summary>
            /// Gets the redirect_uri specified by the client application.
            /// If it's not provided by the client, it must be set by
            /// the user code by calling <see cref="SetRedirectUri(string)"/>.
            /// </summary>
            public string RedirectUri { get; private set; }

            /// <summary>
            /// Populates the <see cref="RedirectUri"/> property with the specified redirect_uri.
            /// </summary>
            /// <param name="address">The redirect_uri to use when redirecting the user agent.</param>
            public void SetRedirectUri(string address)
            {
                if (string.IsNullOrEmpty(address))
                {
                    throw new ArgumentException("The redirect_uri cannot be null or empty.", nameof(address));
                }

                // Don't allow validation to alter the redirect_uri parameter extracted
                // from the request if the address was explicitly provided by the client.
                if (!string.IsNullOrEmpty(Request.RedirectUri) &&
                    !string.Equals(Request.RedirectUri, address, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "The authorization request cannot be validated because a different " +
                        "redirect_uri was specified by the client application.");
                }

                RedirectUri = address;
            }

            /// <summary>
            /// Gets or sets the security principal extracted from the id_token_hint, if available.
            /// Note: the principal may not represent the user currently logged in,
            /// so additional validation is strongly encouraged when using this property.
            /// </summary>
            public ClaimsPrincipal IdentityTokenHintPrincipal { get; set; }
        }

        /// <summary>
        /// Represents an event called for each validated authorization request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public class HandleAuthorizationRequestContext : BaseValidatingTicketContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="HandleAuthorizationRequestContext"/> class.
            /// </summary>
            public HandleAuthorizationRequestContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets or sets the security principal extracted from the id_token_hint, if available.
            /// Note: the principal may not represent the user currently logged in,
            /// so additional validation is strongly encouraged when using this property.
            /// </summary>
            public ClaimsPrincipal IdentityTokenHintPrincipal { get; set; }
        }

        /// <summary>
        /// Represents an event called before the authorization response is returned to the caller.
        /// </summary>
        public class ApplyAuthorizationResponseContext : BaseRequestContext
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ApplyAuthorizationResponseContext"/> class.
            /// </summary>
            public ApplyAuthorizationResponseContext([NotNull] OpenIddictServerTransaction transaction)
                : base(transaction)
            {
            }

            /// <summary>
            /// Gets or sets the security principal.
            /// </summary>
            public ClaimsPrincipal Principal { get; set; }

            /// <summary>
            /// Gets the access code expected to
            /// be returned to the client application.
            /// Depending on the flow, it may be null.
            /// </summary>
            public string AccessToken => Response.AccessToken;

            /// <summary>
            /// Gets the authorization code expected to
            /// be returned to the client application.
            /// Depending on the flow, it may be null.
            /// </summary>
            public string AuthorizationCode => Response.Code;

            /// <summary>
            /// Gets the error code returned to the client application.
            /// When the response indicates a successful response,
            /// this property returns <c>null</c>.
            /// </summary>
            public string Error => Response.Error;

            /// <summary>
            /// Gets or sets the callback URL the user agent will be redirected to, if applicable.
            /// Note: manually changing the value of this property is generally not recommended
            /// and extreme caution must be taken to ensure the user agent is not redirected to
            /// an untrusted address, which would result in an "open redirection" vulnerability.
            /// </summary>
            public string RedirectUri { get; set; }

            /// <summary>
            /// Gets or sets the response mode used to redirect the user agent, if applicable.
            /// Note: manually changing the value of this property is generally not recommended.
            /// </summary>
            public string ResponseMode { get; set; }
        }
    }
}
