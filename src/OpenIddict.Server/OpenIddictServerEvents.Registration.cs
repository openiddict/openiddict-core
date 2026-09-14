/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using System.Text.Json;

namespace OpenIddict.Server;

public static partial class OpenIddictServerEvents
{
    /// <summary>
    /// Resolves the type of a registration operation from the HTTP method used by the client (RFC 7591 and RFC 7592).
    /// </summary>
    internal static OpenIddictServerRegistrationRequestType GetRegistrationRequestType(string? method) => method switch
    {
        _ when string.Equals(method, "POST",   StringComparison.OrdinalIgnoreCase) => OpenIddictServerRegistrationRequestType.Registration,
        _ when string.Equals(method, "GET",    StringComparison.OrdinalIgnoreCase) => OpenIddictServerRegistrationRequestType.Read,
        _ when string.Equals(method, "PUT",    StringComparison.OrdinalIgnoreCase) => OpenIddictServerRegistrationRequestType.Update,
        _ when string.Equals(method, "DELETE", StringComparison.OrdinalIgnoreCase) => OpenIddictServerRegistrationRequestType.Deletion,

        _ => OpenIddictServerRegistrationRequestType.Unknown
    };

    /// <summary>
    /// Represents an event called for each request to the registration endpoint to give the user code
    /// a chance to manually extract the registration request from the ambient HTTP context.
    /// </summary>
    public sealed class ExtractRegistrationRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractRegistrationRequestContext"/> class.
        /// </summary>
        public ExtractRegistrationRequestContext(OpenIddictServerTransaction transaction)
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

        /// <summary>
        /// Gets the type of the registration operation, resolved from the HTTP method.
        /// </summary>
        public OpenIddictServerRegistrationRequestType RequestType
            => GetRegistrationRequestType(Transaction.RequestMethod);
    }

    /// <summary>
    /// Represents an event called for each request to the registration endpoint to determine if the request
    /// is valid and should continue to be processed. Custom handlers can be used to enforce additional
    /// registration policies (e.g to approve or reject a registration based on the client metadata).
    /// </summary>
    public sealed class ValidateRegistrationRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidateRegistrationRequestContext"/> class.
        /// </summary>
        public ValidateRegistrationRequestContext(OpenIddictServerTransaction transaction)
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
        /// Gets the type of the registration operation, resolved from the HTTP method.
        /// </summary>
        public OpenIddictServerRegistrationRequestType RequestType
            => GetRegistrationRequestType(Transaction.RequestMethod);

        /// <summary>
        /// Gets the client identifier targeted by the client configuration endpoint (RFC 7592), if applicable.
        /// </summary>
        public string? ClientId => RequestType is OpenIddictServerRegistrationRequestType.Registration
            ? null : Transaction.Request?.ClientId;

        /// <summary>
        /// Gets or sets the security principal extracted from the initial access token, if applicable.
        /// </summary>
        /// <remarks>
        /// Note: custom handlers executed before the built-in handlers can set this property
        /// to accept initial access tokens that are not issued by this authorization server.
        /// </remarks>
        public ClaimsPrincipal? InitialAccessTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the token entry representing the registration access token, if applicable.
        /// </summary>
        public object? RegistrationAccessToken { get; set; }

        /// <summary>
        /// Gets or sets the security principal extracted from the software statement, if applicable.
        /// </summary>
        public ClaimsPrincipal? SoftwareStatementPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the application managed using the client configuration endpoint, if applicable.
        /// </summary>
        public object? Application { get; set; }

        /// <summary>
        /// Gets or sets the client authentication method resolved from the client metadata.
        /// </summary>
        public string? TokenEndpointAuthenticationMethod { get; set; }

        /// <summary>
        /// Gets the grant types resolved from the client metadata.
        /// </summary>
        public HashSet<string> GrantTypes { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets the response types resolved from the client metadata.
        /// </summary>
        public HashSet<string> ResponseTypes { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets the scopes resolved from the client metadata.
        /// </summary>
        public HashSet<string> Scopes { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets the client metadata accepted by the authorization server. Unrecognized
        /// metadata are ignored, as required by RFC 7591, section 2, and not included.
        /// </summary>
        public Dictionary<string, JsonElement> Metadata { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the descriptor representing the client application that will be created or updated.
        /// Custom handlers executed after the built-in handlers can inspect or amend it (e.g to restrict
        /// the permissions granted to the client application) or reject the request.
        /// </summary>
        public OpenIddictApplicationDescriptor Descriptor { get; set; } = new();
    }

    /// <summary>
    /// Represents an event called for each validated registration request
    /// to allow the user code to decide how the request should be handled.
    /// </summary>
    public sealed class HandleRegistrationRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleRegistrationRequestContext"/> class.
        /// </summary>
        public HandleRegistrationRequestContext(OpenIddictServerTransaction transaction)
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
        /// Gets the type of the registration operation, resolved from the HTTP method.
        /// </summary>
        public OpenIddictServerRegistrationRequestType RequestType
            => GetRegistrationRequestType(Transaction.RequestMethod);

        /// <summary>
        /// Gets or sets the application read, updated or deleted by this request, if applicable.
        /// </summary>
        public object? Application { get; set; }

        /// <summary>
        /// Gets or sets the descriptor representing the client application that will be created or updated.
        /// </summary>
        public OpenIddictApplicationDescriptor Descriptor { get; set; } = new();

        /// <summary>
        /// Gets the additional parameters returned to the client application.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Parameters { get; } = new(StringComparer.Ordinal);
    }

    /// <summary>
    /// Represents an event called before the registration response is returned to the caller.
    /// </summary>
    public sealed class ApplyRegistrationResponseContext : BaseRequestContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyRegistrationResponseContext"/> class.
        /// </summary>
        public ApplyRegistrationResponseContext(OpenIddictServerTransaction transaction)
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
        /// Gets the type of the registration operation, resolved from the HTTP method.
        /// </summary>
        public OpenIddictServerRegistrationRequestType RequestType
            => GetRegistrationRequestType(Transaction.RequestMethod);

        /// <summary>
        /// Gets the error code returned to the client application.
        /// When the response indicates a successful response,
        /// this property returns <see langword="null"/>.
        /// </summary>
        public string? Error => Response.Error;
    }
}
