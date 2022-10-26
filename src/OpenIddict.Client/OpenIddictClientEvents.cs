/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Client;

public static partial class OpenIddictClientEvents
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
        protected BaseContext(OpenIddictClientTransaction transaction)
            => Transaction = transaction ?? throw new ArgumentNullException(nameof(transaction));

        /// <summary>
        /// Gets the environment associated with the current request being processed.
        /// </summary>
        public OpenIddictClientTransaction Transaction { get; }

        /// <summary>
        /// Gets or sets the endpoint type that handled the request, if applicable.
        /// </summary>
        public OpenIddictClientEndpointType EndpointType
        {
            get => Transaction.EndpointType;
            set => Transaction.EndpointType = value;
        }

        /// <summary>
        /// Gets the logger responsible for logging processed operations.
        /// </summary>
        public ILogger Logger => Transaction.Logger;

        /// <summary>
        /// Gets the OpenIddict client options.
        /// </summary>
        public OpenIddictClientOptions Options => Transaction.Options;

        /// <summary>
        /// Gets or sets the issuer used for the current request.
        /// </summary>
        public Uri? Issuer
        {
            get => Transaction.Issuer;
            set => Transaction.Issuer = value;
        }

        /// <summary>
        /// Gets or sets the server configuration used for the current request.
        /// </summary>
        public OpenIddictConfiguration Configuration
        {
            get => Transaction.Configuration;
            set => Transaction.Configuration = value;
        }

        /// <summary>
        /// Gets or sets the client registration used for the current request.
        /// </summary>
        public OpenIddictClientRegistration Registration
        {
            get => Transaction.Registration;
            set => Transaction.Registration = value;
        }
    }

    /// <summary>
    /// Represents an abstract base class used for certain event contexts.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public abstract class BaseRequestContext : BaseContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="BaseRequestContext"/> class.
        /// </summary>
        protected BaseRequestContext(OpenIddictClientTransaction transaction)
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
    public abstract class BaseExternalContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="BaseRequestContext"/> class.
        /// </summary>
        protected BaseExternalContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the address of the external endpoint to communicate with.
        /// </summary>
        public Uri? Address { get; set; }
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
        protected BaseValidatingContext(OpenIddictClientTransaction transaction)
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
        public string? Error { get; private set; }

        /// <summary>
        /// Gets or sets the "error_description" parameter returned to the client application.
        /// </summary>
        public string? ErrorDescription { get; private set; }

        /// <summary>
        /// Gets or sets the "error_uri" parameter returned to the client application.
        /// </summary>
        public string? ErrorUri { get; private set; }

        /// <summary>
        /// Rejects the request.
        /// </summary>
        /// <param name="error">The "error" parameter returned to the client application.</param>
        /// <param name="description">The "error_description" parameter returned to the client application.</param>
        /// <param name="uri">The "error_uri" parameter returned to the client application.</param>
        public virtual void Reject(string? error = null, string? description = null, string? uri = null)
        {
            Error = error;
            ErrorDescription = description;
            ErrorUri = uri;

            IsRejected = true;
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
        protected BaseValidatingTicketContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the security principal.
        /// </summary>
        public ClaimsPrincipal? Principal { get; set; }
    }

    /// <summary>
    /// Represents an event called when processing an incoming request.
    /// </summary>
    public class ProcessRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessRequestContext"/> class.
        /// </summary>
        public ProcessRequestContext(OpenIddictClientTransaction transaction)
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
        public ProcessErrorContext(OpenIddictClientTransaction transaction)
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
        /// Gets or sets the error returned to the caller.
        /// </summary>
        public string? Error { get; set; }

        /// <summary>
        /// Gets or sets the error description returned to the caller.
        /// </summary>
        public string? ErrorDescription { get; set; }

        /// <summary>
        /// Gets or sets the error URL returned to the caller.
        /// </summary>
        public string? ErrorUri { get; set; }

        /// <summary>
        /// Gets the additional parameters returned to the caller.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Parameters { get; } = new(StringComparer.Ordinal);
    }

    /// <summary>
    /// Represents an event called when processing an authentication operation.
    /// </summary>
    public class ProcessAuthenticationContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessAuthenticationContext"/> class.
        /// </summary>
        public ProcessAuthenticationContext(OpenIddictClientTransaction transaction)
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
        /// Gets or sets the grant type used for the authentication demand, if applicable.
        /// </summary>
        public string? GrantType { get; set; }

        /// <summary>
        /// Gets or sets the response type used for the authentication demand, if applicable.
        /// </summary>
        public string? ResponseType { get; set; }

        /// <summary>
        /// Gets or sets the address of the token endpoint, if applicable.
        /// </summary>
        public Uri? TokenEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the address of the userinfo endpoint, if applicable.
        /// </summary>
        public Uri? UserinfoEndpoint { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a token request should be sent.
        /// </summary>
        public bool SendTokenRequest { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a token request should be sent.
        /// </summary>
        public bool SendUserinfoRequest { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an authorization
        /// code should be extracted from the current context.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ExtractAuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a backchannel
        /// access token should be extracted from the current context.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ExtractBackchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a backchannel
        /// identity token should be extracted from the current context.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ExtractBackchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a frontchannel
        /// access token should be extracted from the current context.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ExtractFrontchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a frontchannel
        /// identity token should be extracted from the current context.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ExtractFrontchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a refresh
        /// token should be extracted from the current context.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ExtractRefreshToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a state
        /// token should be extracted from the current context.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ExtractStateToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a userinfo
        /// token should be extracted from the current context.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ExtractUserinfoToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an authorization
        /// code must be resolved for the authentication to be considered valid.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool RequireAuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a backchannel access
        /// token must be resolved for the authentication to be considered valid.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool RequireBackchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a backchannel identity
        /// token must be resolved for the authentication to be considered valid.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool RequireBackchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a frontchannel identity
        /// token must be resolved for the authentication to be considered valid.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool RequireFrontchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a frontchannel identity
        /// token must be resolved for the authentication to be considered valid.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool RequireFrontchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a refresh token
        /// must be resolved for the authentication to be considered valid.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool RequireRefreshToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a state token
        /// must be resolved for the authentication to be considered valid.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool RequireStateToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a userinfo token
        /// must be resolved for the authentication to be considered valid.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool RequireUserinfoToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the authorization
        /// code extracted from the current context should be validated.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ValidateAuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the backchannel access
        /// token extracted from the current context should be validated.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ValidateBackchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the backchannel identity
        /// token extracted from the current context should be validated.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ValidateBackchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the frontchannel access
        /// token extracted from the current context should be validated.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ValidateFrontchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the frontchannel identity
        /// token extracted from the current context should be validated.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ValidateFrontchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the refresh token
        /// extracted from the current context should be validated.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ValidateRefreshToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the state token
        /// extracted from the current context should be validated.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ValidateStateToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the userinfo token
        /// extracted from the current context should be validated.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool ValidateUserinfoToken { get; set; }

        /// <summary>
        /// Gets or sets the authorization code to validate, if applicable.
        /// </summary>
        public string? AuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets the backchannel access token to validate, if applicable.
        /// </summary>
        public string? BackchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets the backchannel identity token to validate, if applicable.
        /// </summary>
        public string? BackchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets the frontchannel access token to validate, if applicable.
        /// </summary>
        public string? FrontchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets the frontchannel identity token to validate, if applicable.
        /// </summary>
        public string? FrontchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets the refresh token to validate, if applicable.
        /// </summary>
        public string? RefreshToken { get; set; }

        /// <summary>
        /// Gets or sets the username to send to the server, if applicable.
        /// </summary>
        public string? Username { get; set; }

        /// <summary>
        /// Gets or sets the password to send to the server, if applicable.
        /// </summary>
        public string? Password { get; set; }

        /// <summary>
        /// Gets or sets the frontchannel state token to validate, if applicable.
        /// </summary>
        public string? StateToken { get; set; }

        /// <summary>
        /// Gets or sets the userinfo token to validate, if applicable.
        /// </summary>
        public string? UserinfoToken { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the authorization code, if applicable.
        /// </summary>
        public ClaimsPrincipal? AuthorizationCodePrincipal { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the backchannel access token, if applicable.
        /// </summary>
        public ClaimsPrincipal? BackchannelAccessTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the backchannel identity token, if applicable.
        /// </summary>
        public ClaimsPrincipal? BackchannelIdentityTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the frontchannel access token, if applicable.
        /// </summary>
        public ClaimsPrincipal? FrontchannelAccessTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the frontchannel identity token, if applicable.
        /// </summary>
        public ClaimsPrincipal? FrontchannelIdentityTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the refresh token, if applicable.
        /// </summary>
        public ClaimsPrincipal? RefreshTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the state token, if applicable.
        /// </summary>
        public ClaimsPrincipal? StateTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the userinfo token, if applicable.
        /// </summary>
        public ClaimsPrincipal? UserinfoTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the request sent to the token endpoint, if applicable.
        /// </summary>
        public OpenIddictRequest? TokenRequest { get; set; }

        /// <summary>
        /// Gets or sets the response returned by the token endpoint, if applicable.
        /// </summary>
        public OpenIddictResponse? TokenResponse { get; set; }

        /// <summary>
        /// Gets or sets the request sent to the userinfo endpoint, if applicable.
        /// </summary>
        public OpenIddictRequest? UserinfoRequest { get; set; }

        /// <summary>
        /// Gets or sets the response returned by the userinfo endpoint, if applicable.
        /// </summary>
        public OpenIddictResponse? UserinfoResponse { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a client assertion
        /// token should be generated (and optionally included in the request).
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool GenerateClientAssertionToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated client
        /// assertion token should be included as part of the request.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool IncludeClientAssertionToken { get; set; }

        /// <summary>
        /// Gets or sets the generated client assertion token, if applicable.
        /// The client assertion token will only be returned if
        /// <see cref="IncludeClientAssertionToken"/> is set to <see langword="true"/>.
        /// </summary>
        public string? ClientAssertionToken { get; set; }

        /// <summary>
        /// Gets or sets type of the generated client assertion token, if applicable.
        /// The client assertion token type will only be returned if
        /// <see cref="IncludeClientAssertionToken"/> is set to <see langword="true"/>.
        /// </summary>
        public string? ClientAssertionTokenType { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that will be
        /// used to create the client assertion token, if applicable.
        /// </summary>
        public ClaimsPrincipal? ClientAssertionTokenPrincipal { get; set; }
    }

    /// <summary>
    /// Represents an event called when processing a challenge response.
    /// </summary>
    public class ProcessChallengeContext : BaseValidatingTicketContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessChallengeContext"/> class.
        /// </summary>
        public ProcessChallengeContext(OpenIddictClientTransaction transaction)
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
        /// Gets the user-defined authentication properties, if available.
        /// </summary>
        public Dictionary<string, string?> Properties { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the name of the provider that will be
        /// used to resolve the issuer identity, if applicable.
        /// </summary>
        public string? ProviderName { get; set; }

        /// <summary>
        /// Gets the additional parameters returned to the caller.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Parameters { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the client identifier that will be used for the challenge demand.
        /// </summary>
        public string? ClientId { get; set; }

        /// <summary>
        /// Gets or sets the grant type that will be used for the challenge demand.
        /// </summary>
        public string? GrantType { get; set; }

        /// <summary>
        /// Gets or sets the response mode that will be
        /// used for the challenge demand, if applicable.
        /// </summary>
        public string? ResponseMode { get; set; }

        /// <summary>
        /// Gets or sets the response type that will be
        /// used for the challenge demand, if applicable.
        /// </summary>
        public string? ResponseType { get; set; }

        /// <summary>
        /// Gets or sets the redirection endpoint that will
        /// be used for the challenge demand, if applicable.
        /// </summary>
        [StringSyntax(StringSyntaxAttribute.Uri)]
        public string? RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the code challenge that will
        /// be used for the challenge demand, if applicable.
        /// </summary>
        public string? CodeChallenge { get; set; }

        /// <summary>
        /// Gets or sets the code challenge method that will
        /// be used for the challenge demand, if applicable.
        /// </summary>
        public string? CodeChallengeMethod { get; set; }

        /// <summary>
        /// Gets or sets the code verifier that will be stored in the state token, if applicable.
        /// </summary>
        public string? CodeVerifier { get; set; }

        /// <summary>
        /// Gets or sets the nonce that will be used for the challenge demand, if applicable.
        /// </summary>
        public string? Nonce { get; set; }

        /// <summary>
        /// Gets or sets the request forgery protection that will be stored in the state token, if applicable.
        /// Note: this value MUST NOT be user-defined or extracted from any request and MUST be random
        /// (generated by a random number generator suitable for cryptographic operations).
        /// </summary>
        public string? RequestForgeryProtection { get; set; }

        /// <summary>
        /// Gets or sets the optional return URL that will be stored in the state token, if applicable.
        /// </summary>
        [StringSyntax(StringSyntaxAttribute.Uri)]
        public string? TargetLinkUri { get; set; }

        /// <summary>
        /// Gets or sets the optional identity token hint that will
        /// be sent to the authorization server, if applicable.
        /// </summary>
        public string? IdentityTokenHint { get; set; }

        /// <summary>
        /// Gets or sets the optional login hint that will be sent to the authorization server, if applicable.
        /// </summary>
        public string? LoginHint { get; set; }

        /// <summary>
        /// Gets the set of scopes that will be requested to the authorization server.
        /// </summary>
        public HashSet<string> Scopes { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets a boolean indicating whether a state token
        /// should be generated (and optionally included in the request).
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool GenerateStateToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated
        /// state token should be included as part of the request.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool IncludeStateToken { get; set; }

        /// <summary>
        /// Gets or sets the generated state token, if applicable.
        /// The state token will only be returned if
        /// <see cref="IncludeStateToken"/> is set to <see langword="true"/>.
        /// </summary>
        public string? StateToken { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that
        /// will be used to create the state token, if applicable.
        /// </summary>
        public ClaimsPrincipal? StateTokenPrincipal { get; set; }
    }

    /// <summary>
    /// Represents an event called when processing a sign-out response.
    /// </summary>
    public class ProcessSignOutContext : BaseValidatingTicketContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessSignOutContext"/> class.
        /// </summary>
        public ProcessSignOutContext(OpenIddictClientTransaction transaction)
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
        /// Gets the user-defined authentication properties, if available.
        /// </summary>
        public Dictionary<string, string?> Properties { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the name of the provider that will be
        /// used to resolve the issuer identity, if applicable.
        /// </summary>
        public string? ProviderName { get; set; }

        /// <summary>
        /// Gets or sets the client identifier that will be used for the sign-out demand.
        /// </summary>
        public string? ClientId { get; set; }

        /// <summary>
        /// Gets or sets the post-logout redirection endpoint that
        /// will be used for the sign-out demand, if applicable.
        /// </summary>
        [StringSyntax(StringSyntaxAttribute.Uri)]
        public string? PostLogoutRedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the optional identity token hint that will
        /// be sent to the authorization server, if applicable.
        /// </summary>
        public string? IdentityTokenHint { get; set; }

        /// <summary>
        /// Gets or sets the optional login hint that will be sent to the authorization server, if applicable.
        /// </summary>
        public string? LoginHint { get; set; }

        /// <summary>
        /// Gets or sets the optional return URL that will be stored in the state token, if applicable.
        /// </summary>
        public string? TargetLinkUri { get; set; }

        /// <summary>
        /// Gets or sets the request forgery protection that will be stored in the state token, if applicable.
        /// Note: this value MUST NOT be user-defined or extracted from any request and MUST be random
        /// (generated by a random number generator suitable for cryptographic operations).
        /// </summary>
        public string? RequestForgeryProtection { get; set; }

        /// <summary>
        /// Gets the additional parameters returned to the caller.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Parameters { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets a boolean indicating whether a state token
        /// should be generated (and optionally included in the request).
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool GenerateStateToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated
        /// state token should be included as part of the request.
        /// Note: overriding the value of this property is generally not
        /// recommended, except when dealing with non-standard clients.
        /// </summary>
        public bool IncludeStateToken { get; set; }

        /// <summary>
        /// Gets or sets the generated state token, if applicable.
        /// The state token will only be returned if
        /// <see cref="IncludeStateToken"/> is set to <see langword="true"/>.
        /// </summary>
        public string? StateToken { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that
        /// will be used to create the state token, if applicable.
        /// </summary>
        public ClaimsPrincipal? StateTokenPrincipal { get; set; }
    }
}
