/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;

namespace OpenIddict.Server;

public static partial class OpenIddictServerEvents
{
    /// <summary>
    /// Represents an event called for each request to the device authorization endpoint to give the
    /// user code a chance to manually extract the device request from the ambient HTTP context.
    /// </summary>
    public sealed class ExtractDeviceAuthorizationRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractDeviceAuthorizationRequestContext"/> class.
        /// </summary>
        public ExtractDeviceAuthorizationRequestContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request, or <see langword="null"/> if it wasn't extracted yet.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }
    }

    /// <summary>
    /// Represents an event called for each request to the device authorization endpoint
    /// to determine if the request is valid and should continue to be processed.
    /// </summary>
    public sealed class ValidateDeviceAuthorizationRequestContext : BaseValidatingClientContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidateDeviceAuthorizationRequestContext"/> class.
        /// </summary>
        public ValidateDeviceAuthorizationRequestContext(OpenIddictServerTransaction transaction)
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
    /// Represents an event called for each validated device authorization request
    /// to allow the user code to decide how the request should be handled.
    /// </summary>
    public sealed class HandleDeviceAuthorizationRequestContext : BaseValidatingTicketContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleDeviceAuthorizationRequestContext"/> class.
        /// </summary>
        public HandleDeviceAuthorizationRequestContext(OpenIddictServerTransaction transaction)
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
    /// Represents an event called before the device authorization response is returned to the caller.
    /// </summary>
    public sealed class ApplyDeviceAuthorizationResponseContext : BaseRequestContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyDeviceAuthorizationResponseContext"/> class.
        /// </summary>
        public ApplyDeviceAuthorizationResponseContext(OpenIddictServerTransaction transaction)
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
        /// Gets the error code returned to the client application.
        /// When the response indicates a successful response,
        /// this property returns <see langword="null"/>.
        /// </summary>
        public string? Error => Response.Error;
    }

    /// <summary>
    /// Represents an event called for each request to the end-user verification endpoint to give the user code
    /// a chance to manually extract the end-user verification request from the ambient HTTP context.
    /// </summary>
    public sealed class ExtractEndUserVerificationRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractEndUserVerificationRequestContext"/> class.
        /// </summary>
        public ExtractEndUserVerificationRequestContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request, or <see langword="null"/> if it wasn't extracted yet.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }
    }

    /// <summary>
    /// Represents an event called for each request to the end-user verification endpoint
    /// to determine if the request is valid and should continue to be processed.
    /// </summary>
    public sealed class ValidateEndUserVerificationRequestContext : BaseValidatingClientContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidateEndUserVerificationRequestContext"/> class.
        /// </summary>
        public ValidateEndUserVerificationRequestContext(OpenIddictServerTransaction transaction)
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
        /// Gets or sets the security principal extracted from the user code, if applicable.
        /// </summary>
        public ClaimsPrincipal? Principal { get; set; }
    }

    /// <summary>
    /// Represents an event called for each validated end-user verification request
    /// to allow the user code to decide how the request should be handled.
    /// </summary>
    public sealed class HandleEndUserVerificationRequestContext : BaseValidatingTicketContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleEndUserVerificationRequestContext"/> class.
        /// </summary>
        public HandleEndUserVerificationRequestContext(OpenIddictServerTransaction transaction)
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
        /// Gets or sets the security principal extracted from the user code, if applicable.
        /// </summary>
        public ClaimsPrincipal? UserCodePrincipal { get; set; }

        /// <summary>
        /// Gets the additional parameters returned to the caller.
        /// </summary>
        /// <remarks>
        /// Note: by default, this property is not used as empty responses are typically
        /// returned for end-user verification requests. To return a different response, a
        /// custom event handler must be registered to handle end-user verification responses.
        /// </remarks>
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
    /// Represents an event called before the end-user verification response is returned to the caller.
    /// </summary>
    public sealed class ApplyEndUserVerificationResponseContext : BaseRequestContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyEndUserVerificationResponseContext"/> class.
        /// </summary>
        public ApplyEndUserVerificationResponseContext(OpenIddictServerTransaction transaction)
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
        /// Gets the error code returned to the client application.
        /// When the response indicates a successful response,
        /// this property returns <see langword="null"/>.
        /// </summary>
        public string? Error => Response.Error;
    }
}
