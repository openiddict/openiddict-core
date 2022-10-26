/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

namespace OpenIddict.Server;

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
        public ExtractAuthorizationRequestContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request or <see langword="null"/> if it was extracted yet.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
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
        public ValidateAuthorizationRequestContext(OpenIddictServerTransaction transaction)
            : base(transaction)
            // Infer the redirect_uri from the value specified by the client application.
            => RedirectUri = Request?.RedirectUri;

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        public OpenIddictRequest Request
        {
            get => Transaction.Request!;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets the client_id specified by the client application.
        /// </summary>
        public string? ClientId => Request?.ClientId;

        /// <summary>
        /// Gets the redirect_uri specified by the client application.
        /// If it's not provided by the client, it must be set by
        /// the user code by calling <see cref="SetRedirectUri(string)"/>.
        /// </summary>
        [StringSyntax(StringSyntaxAttribute.Uri)]
        public string? RedirectUri { get; private set; }

        /// <summary>
        /// Gets or sets the security principal extracted
        /// from the identity token hint, if applicable.
        /// </summary>
        public ClaimsPrincipal? IdentityTokenHintPrincipal { get; set; }

        /// <summary>
        /// Populates the <see cref="RedirectUri"/> property with the specified redirect_uri.
        /// </summary>
        /// <param name="address">The redirect_uri to use when redirecting the user agent.</param>
        public void SetRedirectUri([StringSyntax(StringSyntaxAttribute.Uri)] string address)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0100), nameof(address));
            }

            // Don't allow validation to alter the redirect_uri parameter extracted
            // from the request if the address was explicitly provided by the client.
            if (!string.IsNullOrEmpty(Request?.RedirectUri) &&
                !string.Equals(Request.RedirectUri, address, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0101));
            }

            RedirectUri = address;
        }
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
        public HandleAuthorizationRequestContext(OpenIddictServerTransaction transaction)
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
        /// Gets or sets the security principal extracted
        /// from the identity token hint, if applicable.
        /// </summary>
        public ClaimsPrincipal? IdentityTokenHintPrincipal { get; set; }

        /// <summary>
        /// Gets the additional parameters returned to the client application.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Parameters { get; private set; }
            = new(StringComparer.Ordinal);

        /// <summary>
        /// Allows OpenIddict to return a sign-in response using the specified principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        public void SignIn(ClaimsPrincipal principal) => Principal = principal;

        /// <summary>
        /// Allows OpenIddict to return a sign-in response using the specified principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="parameters">The additional parameters returned to the client application.</param>
        public void SignIn(ClaimsPrincipal principal, IDictionary<string, OpenIddictParameter> parameters)
        {
            Principal = principal;
            Parameters = new(parameters, StringComparer.Ordinal);
        }
    }

    /// <summary>
    /// Represents an event called before the authorization response is returned to the caller.
    /// </summary>
    public class ApplyAuthorizationResponseContext : BaseRequestContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyAuthorizationResponseContext"/> class.
        /// </summary>
        public ApplyAuthorizationResponseContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request, or <see langword="null"/> if it couldn't be extracted.
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
        /// Gets the access code expected to
        /// be returned to the client application.
        /// Depending on the flow, it may be null.
        /// </summary>
        public string? AccessToken => Response?.AccessToken;

        /// <summary>
        /// Gets the authorization code expected to
        /// be returned to the client application.
        /// Depending on the flow, it may be null.
        /// </summary>
        public string? AuthorizationCode => Response?.Code;

        /// <summary>
        /// Gets the error code returned to the client application.
        /// When the response indicates a successful response,
        /// this property returns <see langword="null"/>.
        /// </summary>
        public string? Error => Response?.Error;

        /// <summary>
        /// Gets or sets the callback URL the user agent will be redirected to, if applicable.
        /// Note: manually changing the value of this property is generally not recommended
        /// and extreme caution must be taken to ensure the user agent is not redirected to
        /// an untrusted address, which would result in an "open redirection" vulnerability.
        /// </summary>
        public string? RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the response mode used to redirect the user agent, if applicable.
        /// Note: manually changing the value of this property is generally not recommended.
        /// </summary>
        public string? ResponseMode { get; set; }
    }
}
