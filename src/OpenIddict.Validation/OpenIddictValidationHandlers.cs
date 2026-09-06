/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Text;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.Validation;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictValidationHandlers
{
    public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } =
    [
        /*
         * Authentication processing:
         */
        EvaluateValidatedTokens.Descriptor,
        ValidateRequiredTokens.Descriptor,
        ResolveServerConfiguration.Descriptor,
        EvaluateIntrospectionRequest.Descriptor,
        AttachIntrospectionEndpointClientAuthenticationMethod.Descriptor,
        AttachIntrospectionEndpointClientCertificate.Descriptor,
        ResolveIntrospectionEndpoint.Descriptor,
        AttachIntrospectionRequestParameters.Descriptor,
        EvaluateGeneratedClientAssertion.Descriptor,
        PrepareClientAssertionPrincipal.Descriptor,
        GenerateClientAssertion.Descriptor,
        AttachIntrospectionRequestClientCredentials.Descriptor,
        SendIntrospectionRequest.Descriptor,
        ValidateIntrospectedTokenUsage.Descriptor,
        ValidateIntrospectedTokenAudiences.Descriptor,
        ValidateIntrospectedTokenProofOfPossession.Descriptor,
        ValidateAccessToken.Descriptor,

        /*
         * Challenge processing:
         */
        AttachDefaultChallengeError.Descriptor,
        AttachCustomChallengeParameters.Descriptor,

        /*
         * Error processing:
         */
        AttachErrorParameters.Descriptor,
        AttachCustomErrorParameters.Descriptor,

        .. Discovery.DefaultHandlers,
        .. Introspection.DefaultHandlers,
        .. Protection.DefaultHandlers
    ];

    /// <summary>
    /// Contains the logic responsible for selecting the token types that should be validated.
    /// </summary>
    public sealed class EvaluateValidatedTokens : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<EvaluateValidatedTokens>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            (context.ExtractAccessToken,
             context.RequireAccessToken,
             context.ValidateAccessToken,
             context.RejectAccessToken) = context.EndpointType switch
            {
                // When introspection is used, ask the server to validate the token.
                OpenIddictValidationEndpointType.Unknown
                    when context.Options.ValidationType is OpenIddictValidationType.Introspection
                    => (true, true, false, true),

                // Otherwise, always validate it locally.
                OpenIddictValidationEndpointType.Unknown => (true, true, true, true),

                _ => (false, false, false, false)
            };

            // Note: unlike the equivalent event in the server stack, authentication can be triggered for
            // arbitrary requests (typically, API endpoints that are not owned by the validation stack).
            // As such, the token is not directly resolved from the request, that may be null at this stage.
            // Instead, the token is expected to be populated by one or multiple handlers provided by the host.

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting authentication demands that lack required tokens.
    /// </summary>
    public sealed class ValidateRequiredTokens : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ValidateRequiredTokens>()
                // Note: this handler is registered with a high gap to allow handlers
                // that do token extraction to be executed before this handler runs.
                .SetOrder(EvaluateValidatedTokens.Descriptor.Order + 50_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            if (context.RequireAccessToken && string.IsNullOrEmpty(context.AccessToken))
            {
                context.Reject(
                    error: Errors.MissingToken,
                    description: SR.GetResourceString(SR.ID2000),
                    uri: SR.FormatID8000(SR.ID2000));

                return ValueTask.CompletedTask;
            }

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the server configuration.
    /// </summary>
    public sealed class ResolveServerConfiguration : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ResolveServerConfiguration>()
                .SetOrder(ValidateRequiredTokens.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            try
            {
                // Resolve and attach the server configuration to the context if none has been set already.
                context.Configuration ??= await context.Options.ConfigurationManager
                    .GetConfigurationAsync(context.CancellationToken)
                    .WaitAsync(context.CancellationToken)
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception) &&
                exception is not OperationCanceledException)
            {
                context.Logger.LogError(6219, exception, SR.GetResourceString(SR.ID6219));

                context.Reject(
                    error: Errors.ServerError,
                    description: SR.GetResourceString(SR.ID2170),
                    uri: SR.FormatID8000(SR.ID2170));

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for determining whether an introspection request should be sent.
    /// </summary>
    public sealed class EvaluateIntrospectionRequest : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<EvaluateIntrospectionRequest>()
                .SetOrder(ResolveServerConfiguration.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            context.SendIntrospectionRequest = context.Options.ValidationType is OpenIddictValidationType.Introspection;

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for negotiating the best introspection endpoint client
    /// authentication method supported by both the client and the authorization server.
    /// </summary>
    public sealed class AttachIntrospectionEndpointClientAuthenticationMethod : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireIntrospectionRequest>()
                .UseSingletonHandler<AttachIntrospectionEndpointClientAuthenticationMethod>()
                .SetOrder(EvaluateIntrospectionRequest.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // If an explicit client authentication method was attached, don't overwrite it.
            if (!string.IsNullOrEmpty(context.IntrospectionEndpointClientAuthenticationMethod))
            {
                return ValueTask.CompletedTask;
            }

            context.IntrospectionEndpointClientAuthenticationMethod = (
                // Note: if client authentication methods are explicitly listed in the validation options, only use
                // the client authentication methods that are both listed and enabled in the global client options.
                // Otherwise, always default to the client authentication methods that have been enabled globally.
                Client: context.Options.ClientAuthenticationMethods,
                Server: context.Configuration.IntrospectionEndpointAuthMethodsSupported) switch
            {
                // If a TLS client authentication certificate could be resolved and both the
                // client and the server explicitly support tls_client_auth, always prefer it.
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    client.Contains(ClientAuthenticationMethods.TlsClientAuth) &&
                    server.Contains(ClientAuthenticationMethods.TlsClientAuth) &&
                    (context.Configuration.MtlsIntrospectionEndpoint ?? context.Configuration.IntrospectionEndpoint) is Uri endpoint &&
                    context.IntrospectionEndpointClientCertificate is X509Certificate2 certificate &&
                    OpenIddictHelpers.IsClientAuthenticationCertificate(certificate) &&
                   !OpenIddictHelpers.IsSelfIssuedCertificate(certificate)
                    => ClientAuthenticationMethods.TlsClientAuth,

                ({ Count: > 0 } client, { Count: > 0 } server) when
                    client.Contains(ClientAuthenticationMethods.TlsClientAuth) &&
                    server.Contains(ClientAuthenticationMethods.TlsClientAuth) &&
                    (context.Configuration.MtlsIntrospectionEndpoint ?? context.Configuration.IntrospectionEndpoint) is Uri endpoint &&
                    context.IntrospectionEndpointClientCertificate is null &&
                    context.Options.SigningCredentials.Exists(static credentials =>
                        credentials.Key is X509SecurityKey { Certificate: X509Certificate2 certificate } &&
                        OpenIddictHelpers.IsClientAuthenticationCertificate(certificate) &&
                       !OpenIddictHelpers.IsSelfIssuedCertificate(certificate))
                    => ClientAuthenticationMethods.TlsClientAuth,

                // If a self-signed TLS client authentication certificate could be resolved and both
                // the client and the server explicitly support self_signed_tls_client_auth, use it.
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    client.Contains(ClientAuthenticationMethods.SelfSignedTlsClientAuth) &&
                    server.Contains(ClientAuthenticationMethods.SelfSignedTlsClientAuth) &&
                    (context.Configuration.MtlsIntrospectionEndpoint ?? context.Configuration.IntrospectionEndpoint) is Uri endpoint &&
                    context.IntrospectionEndpointClientCertificate is X509Certificate2 certificate &&
                    OpenIddictHelpers.IsClientAuthenticationCertificate(certificate) &&
                    OpenIddictHelpers.IsSelfIssuedCertificate(certificate)
                    => ClientAuthenticationMethods.SelfSignedTlsClientAuth,

                ({ Count: > 0 } client, { Count: > 0 } server) when
                    client.Contains(ClientAuthenticationMethods.SelfSignedTlsClientAuth) &&
                    server.Contains(ClientAuthenticationMethods.SelfSignedTlsClientAuth) &&
                    (context.Configuration.MtlsIntrospectionEndpoint ?? context.Configuration.IntrospectionEndpoint) is Uri endpoint &&
                    context.IntrospectionEndpointClientCertificate is null &&
                    context.Options.SigningCredentials.Exists(static credentials =>
                        credentials.Key is X509SecurityKey { Certificate: X509Certificate2 certificate } &&
                        OpenIddictHelpers.IsClientAuthenticationCertificate(certificate) &&
                        OpenIddictHelpers.IsSelfIssuedCertificate(certificate))
                    => ClientAuthenticationMethods.SelfSignedTlsClientAuth,

                // If at least one asymmetric signing key was attached to the validation options
                // and both the client and the server explicitly support private_key_jwt, use it.
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    client.Contains(ClientAuthenticationMethods.PrivateKeyJwt) &&
                    server.Contains(ClientAuthenticationMethods.PrivateKeyJwt) &&
                    context.Options.SigningCredentials.Exists(static credentials => credentials.Key is AsymmetricSecurityKey)
                    => ClientAuthenticationMethods.PrivateKeyJwt,

                // If a client secret was attached to the validation options and both the client and
                // the server explicitly support client_secret_post, prefer it to basic authentication.
                ({ Count: > 0 } client, { Count: > 0 } server) when !string.IsNullOrEmpty(context.Options.ClientSecret) &&
                    client.Contains(ClientAuthenticationMethods.ClientSecretPost) &&
                    server.Contains(ClientAuthenticationMethods.ClientSecretPost)
                    => ClientAuthenticationMethods.ClientSecretPost,

                // The OAuth 2.0 specification recommends sending the client credentials using basic authentication.
                // However, this authentication method is known to have severe compatibility/interoperability issues:
                //
                //   - While restricted to clients that have been given a secret (i.e confidential clients) by the
                //     specification, basic authentication is also sometimes required by server implementations for
                //     public clients that don't have a client secret: in this case, an empty password is used and
                //     the client identifier is sent alone in the Authorization header (instead of being sent using
                //     the standard "client_id" parameter present in the request body).
                //
                //   - While the OAuth 2.0 specification requires that the client credentials be formURL-encoded
                //     before being base64-encoded, many implementations are known to implement a non-standard
                //     encoding scheme, where neither the client_id nor the client_secret are formURL-encoded.
                //
                // To guarantee that the OpenIddict implementation can be used with most servers implementions,
                // basic authentication is only used when a client secret is present and the server configuration
                // doesn't list any supported client authentication method or doesn't support client_secret_post.
                //
                // If client_secret_post is not listed or if the server returned an empty methods list,
                // client_secret_basic is always used, as it MUST be implemented by all OAuth 2.0 servers.
                //
                // See https://tools.ietf.org/html/rfc8414#section-2
                // and https://tools.ietf.org/html/rfc6749#section-2.3.1 for more information.
                ({ Count: > 0 } client, { Count: > 0 } server) when !string.IsNullOrEmpty(context.Options.ClientSecret) &&
                    client.Contains(ClientAuthenticationMethods.ClientSecretBasic) &&
                    server.Contains(ClientAuthenticationMethods.ClientSecretBasic)
                    => ClientAuthenticationMethods.ClientSecretBasic,

                ({ Count: > 0 } client, { Count: 0 }) when !string.IsNullOrEmpty(context.Options.ClientSecret) &&
                    client.Contains(ClientAuthenticationMethods.ClientSecretBasic)
                    => ClientAuthenticationMethods.ClientSecretBasic,

                _ => null
            };

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the client certificate used for
    /// the introspection endpoint to the authentication context, if applicable.
    /// </summary>
    public sealed class AttachIntrospectionEndpointClientCertificate : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<AttachIntrospectionEndpointClientCertificate>()
                .SetOrder(AttachIntrospectionEndpointClientAuthenticationMethod.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // If a certificate-based client authentication method was negotiated and
            // no certificate was explicitly attached by the application, try to find a
            // valid certificate in the client registration and attach it to the context.
            context.IntrospectionEndpointClientCertificate ??= context.IntrospectionEndpointClientAuthenticationMethod switch
            {
                ClientAuthenticationMethods.TlsClientAuth => context.Options.SigningCredentials
                    .Select(static credentials => (credentials.Key as X509SecurityKey)?.Certificate)
                    .FirstOrDefault(static certificate => certificate is not null &&
                        OpenIddictHelpers.IsClientAuthenticationCertificate(certificate) &&
                       !OpenIddictHelpers.IsSelfIssuedCertificate(certificate))
                        ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0512)),

                ClientAuthenticationMethods.SelfSignedTlsClientAuth => context.Options.SigningCredentials
                    .Select(static credentials => (credentials.Key as X509SecurityKey)?.Certificate)
                    .FirstOrDefault(static certificate => certificate is not null &&
                        OpenIddictHelpers.IsClientAuthenticationCertificate(certificate) &&
                        OpenIddictHelpers.IsSelfIssuedCertificate(certificate))
                        ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0512)),

                _ => null
            };

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the URI of the introspection endpoint.
    /// </summary>
    public sealed class ResolveIntrospectionEndpoint : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireIntrospectionRequest>()
                .UseSingletonHandler<ResolveIntrospectionEndpoint>()
                .SetOrder(AttachIntrospectionEndpointClientCertificate.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            context.IntrospectionEndpoint ??= context.IntrospectionEndpointClientAuthenticationMethod switch
            {
                // If a TLS client authentication certificate is going to be used, always favor the mTLS alias if available.
                ClientAuthenticationMethods.SelfSignedTlsClientAuth or ClientAuthenticationMethods.TlsClientAuth
                    when context.Configuration.MtlsIntrospectionEndpoint is { IsAbsoluteUri: true } uri &&
                    !OpenIddictHelpers.IsImplicitFileUri(uri) => uri,

                // Otherwise, use the non-mTLS-specific endpoint.
                _ when context.Configuration.IntrospectionEndpoint is { IsAbsoluteUri: true } uri &&
                    !OpenIddictHelpers.IsImplicitFileUri(uri) => uri,

                _ => null
            };

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the parameters to the introspection request, if applicable.
    /// </summary>
    public sealed class AttachIntrospectionRequestParameters : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireIntrospectionRequest>()
                .UseSingletonHandler<AttachIntrospectionRequestParameters>()
                .SetOrder(ResolveIntrospectionEndpoint.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // Attach a new request instance if necessary.
            context.IntrospectionRequest ??= new OpenIddictRequest();

            context.IntrospectionRequest.Token = context.AccessToken;
            context.IntrospectionRequest.TokenTypeHint = TokenTypeHints.AccessToken;

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for selecting the token types that should
    /// be generated and optionally sent as part of the authentication demand.
    /// </summary>
    public sealed class EvaluateGeneratedClientAssertion : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireIntrospectionRequest>()
                .UseSingletonHandler<EvaluateGeneratedClientAssertion>()
                .SetOrder(AttachIntrospectionRequestParameters.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            (context.GenerateClientAssertion,
             context.IncludeClientAssertion) = context.IntrospectionEndpointClientAuthenticationMethod switch
            {
                // If the private_key_jwt client authentication method could be negotiated,
                // generate a client assertion that will be used to authenticate the client.
                ClientAuthenticationMethods.PrivateKeyJwt => (true, true),

                _ => (false, false)
            };

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the client assertion, if one is going to be sent.
    /// </summary>
    public sealed class PrepareClientAssertionPrincipal : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireClientAssertionGenerated>()
                .UseSingletonHandler<PrepareClientAssertionPrincipal>()
                .SetOrder(EvaluateGeneratedClientAssertion.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(context.Configuration.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));

            // Create a new principal that will be used to store the client assertion claims.
            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role));

            principal.SetCreationDate(context.Options.TimeProvider.GetUtcNow());

            var lifetime = context.Options.ClientAssertionLifetime;
            if (lifetime is not null)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Important: the initial Assertion Framework for OAuth 2.0 Client Authentication specifications
            // initially encouraged supporting using the token endpoint URI as the client assertion audience,
            // even for introspection requests. It was determined in 2025 that doing so may result in
            // impersonation attacks as the token endpoint URI is not a guarded value. To mitigate that,
            // OpenIddict always uses the issuer identity as the client assertion audience, as recommended
            // by the https://www.ietf.org/archive/id/draft-ietf-oauth-rfc7523bis-01.html#section-2 draft.
            principal.SetAudiences(context.Configuration.Issuer.OriginalString);

            // Use the client_id as both the subject and the issuer, as required by the specifications.
            principal.SetClaim(Claims.Private.Issuer, context.Options.ClientId)
                     .SetClaim(Claims.Subject, context.Options.ClientId);

            // Use a random GUID as the JWT unique identifier.
            principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString());

            context.ClientAssertionPrincipal = principal;

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating a client
    /// assertion for the current authentication operation.
    /// </summary>
    public sealed class GenerateClientAssertion : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictValidationDispatcher _dispatcher;

        public GenerateClientAssertion(IOpenIddictValidationDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireClientAssertionGenerated>()
                .UseSingletonHandler<GenerateClientAssertion>()
                .SetOrder(PrepareClientAssertionPrincipal.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            var notification = new GenerateTokenContext(context.Transaction)
            {
                CreateTokenEntry = false,
                IsReferenceToken = false,
                PersistTokenPayload = false,
                Principal = context.ClientAssertionPrincipal!,
                TokenFormat = TokenFormats.Private.JsonWebToken,
                TokenType = TokenTypeIdentifiers.Private.ClientAssertion
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.ClientAssertion = notification.Token;
            context.ClientAssertionType = notification.TokenFormat switch
            {
                TokenFormats.Private.JsonWebToken => ClientAssertionTypes.JwtBearer,
                TokenFormats.Private.Saml2        => ClientAssertionTypes.Saml2Bearer,

                _ => null
            };
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the client credentials to the introspection request, if applicable.
    /// </summary>
    public sealed class AttachIntrospectionRequestClientCredentials : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireIntrospectionRequest>()
                .UseSingletonHandler<AttachIntrospectionRequestClientCredentials>()
                .SetOrder(GenerateClientAssertion.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(context.IntrospectionRequest is not null, SR.GetResourceString(SR.ID4008));

            // Always attach the client_id to the request, even if an assertion is sent or mTLS is used.
            context.IntrospectionRequest.ClientId = context.Options.ClientId;

            // Note: client authentication methods are mutually exclusive so the client_assertion
            // and client_secret parameters MUST never be sent at the same time. For more information,
            // see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.
            if (context.IncludeClientAssertion)
            {
                context.IntrospectionRequest.ClientAssertion = context.ClientAssertion;
                context.IntrospectionRequest.ClientAssertionType = context.ClientAssertionType;
            }

            else if (context.IntrospectionEndpointClientAuthenticationMethod is
                ClientAuthenticationMethods.ClientSecretBasic or
                ClientAuthenticationMethods.ClientSecretPost)
            {
                context.IntrospectionRequest.ClientSecret = context.Options.ClientSecret;
            }

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for sending the introspection request, if applicable.
    /// </summary>
    public sealed class SendIntrospectionRequest : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictValidationService _service;

        public SendIntrospectionRequest(OpenIddictValidationService service)
            => _service = service ?? throw new ArgumentNullException(nameof(service));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireIntrospectionRequest>()
                .UseSingletonHandler<SendIntrospectionRequest>()
                .SetOrder(AttachIntrospectionRequestClientCredentials.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(context.IntrospectionRequest is not null, SR.GetResourceString(SR.ID4008));

            // Ensure the introspection endpoint is present and is a valid absolute URI.
            if (context.IntrospectionEndpoint is not { IsAbsoluteUri: true } ||
                OpenIddictHelpers.IsImplicitFileUri(context.IntrospectionEndpoint))
            {
                throw new InvalidOperationException(SR.FormatID0301(Metadata.IntrospectionEndpoint));
            }

            var certificate = context.IntrospectionEndpointClientAuthenticationMethod switch
            {
                ClientAuthenticationMethods.TlsClientAuth when context.IntrospectionEndpointClientCertificate is not null =>
                    OpenIddictHelpers.IsSelfIssuedCertificate(context.IntrospectionEndpointClientCertificate)
                        ? throw new InvalidOperationException(SR.GetResourceString(SR.ID0513))
                        : context.IntrospectionEndpointClientCertificate,

                ClientAuthenticationMethods.SelfSignedTlsClientAuth when context.IntrospectionEndpointClientCertificate is not null =>
                    OpenIddictHelpers.IsSelfIssuedCertificate(context.IntrospectionEndpointClientCertificate)
                        ? context.IntrospectionEndpointClientCertificate
                        : throw new InvalidOperationException(SR.GetResourceString(SR.ID0513)),

                _ => null
            };

            try
            {
                (context.IntrospectionResponse, context.AccessTokenPrincipal) =
                    await _service.SendIntrospectionRequestAsync(
                        context.Configuration, context.IntrospectionRequest, context.IntrospectionEndpoint,
                        context.IntrospectionEndpointClientAuthenticationMethod, certificate, context.CancellationToken);
            }

            catch (ProtocolException exception)
            {
                context.Logger.LogDebug(6155, exception, SR.GetResourceString(SR.ID6155));

                context.Reject(
                    error: exception.Error,
                    description: exception.ErrorDescription,
                    uri: exception.ErrorUri);

                return;
            }

            context.Logger.LogTrace(6154, SR.GetResourceString(SR.ID6154), context.AccessToken, context.AccessTokenPrincipal.Claims);
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the usage of the introspected token returned by the server, if applicable.
    /// </summary>
    public sealed class ValidateIntrospectedTokenUsage : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireIntrospectionRequest>()
                .UseSingletonHandler<ValidateIntrospectedTokenUsage>()
                .SetOrder(SendIntrospectionRequest.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(context.AccessTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // OpenIddict-based authorization servers always return the actual token type using
            // the special "token_usage" claim, that helps resource servers determine whether the
            // introspected token is one of the expected types and prevents token substitution attacks.
            //
            // If a "token_usage" claim can be extracted from the principal, use it to determine whether
            // the token details returned by the authorization server correspond to an access token.
            var usage = context.AccessTokenPrincipal.GetClaim(Claims.TokenUsage);
            if (!string.IsNullOrEmpty(usage) &&
                !string.Equals(usage, "access_token", StringComparison.OrdinalIgnoreCase))
            {
                context.Reject(
                    error: Errors.InvalidToken,
                    description: SR.GetResourceString(SR.ID2110),
                    uri: SR.FormatID8000(SR.ID2110));

                return ValueTask.CompletedTask;
            }

            context.AccessTokenPrincipal.SetTokenType(TokenTypeIdentifiers.AccessToken);

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the audiences of the introspected token returned by the server, if applicable.
    /// </summary>
    public sealed class ValidateIntrospectedTokenAudiences : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireIntrospectionRequest>()
                .UseSingletonHandler<ValidateIntrospectedTokenAudiences>()
                .SetOrder(ValidateIntrospectedTokenUsage.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(context.AccessTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // In theory, authorization servers are expected to return an error (or an active=false response)
            // when the caller is not allowed to introspect the token (e.g because it's not a valid audience
            // or authorized party). Unfortunately, some servers are known to have a relaxed validation policy.
            //
            // To ensure the token can be used with this resource server, a second pass is manually performed here.

            // If no explicit audience has been configured, skip the audience validation.
            if (context.Options.Audiences.Count is 0)
            {
                return ValueTask.CompletedTask;
            }

            // If the access token doesn't have any audience attached, return an error.
            var audiences = context.AccessTokenPrincipal.GetAudiences();
            if (audiences.IsDefaultOrEmpty)
            {
                context.Logger.LogInformation(6157, SR.GetResourceString(SR.ID6157));

                context.Reject(
                    error: Errors.InvalidToken,
                    description: SR.GetResourceString(SR.ID2093),
                    uri: SR.FormatID8000(SR.ID2093));

                return ValueTask.CompletedTask;
            }

            // If the access token doesn't include any registered audience, return an error.
            if (!OpenIddictHelpers.IncludesAnyFromSet(audiences, context.Options.Audiences))
            {
                context.Logger.LogInformation(6158, SR.GetResourceString(SR.ID6158));

                context.Reject(
                    error: Errors.InvalidToken,
                    description: SR.GetResourceString(SR.ID2094),
                    uri: SR.FormatID8000(SR.ID2094));

                return ValueTask.CompletedTask;
            }

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the proof of possession
    /// of the introspected token returned by the server, if applicable.
    /// </summary>
    public sealed class ValidateIntrospectedTokenProofOfPossession : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireIntrospectionRequest>()
                .UseSingletonHandler<ValidateIntrospectedTokenProofOfPossession>()
                .SetOrder(ValidateIntrospectedTokenAudiences.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(context.AccessTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Try to resolve the confirmation claim from the principal. If no such claim can be found,
            // this indicates that the token is a bearer token and doesn't require a proof of possession.
            var confirmation = context.AccessTokenPrincipal.GetClaim(Claims.Confirmation);
            if (string.IsNullOrEmpty(confirmation))
            {
                return ValueTask.CompletedTask;
            }

            if (JsonObject.Parse(confirmation) is not JsonObject node)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID2199));
            }

            if (node.ContainsKey(JsonWebKeyParameterNames.X5tS256))
            {
                var thumbprint = (string?) node[JsonWebKeyParameterNames.X5tS256];
                if (string.IsNullOrEmpty(thumbprint))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID2200));
                }

                // If no client certificate was provided, return an error as no
                // proof-of-possession can be validated without the client certificate.
                if (context.Transaction.RemoteCertificate is not X509Certificate2 certificate)
                {
                    context.Logger.LogInformation(6282, SR.GetResourceString(SR.ID6282));

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2203),
                        uri: SR.FormatID8000(SR.ID2203));

                    return ValueTask.CompletedTask;
                }

                // If the thumbprint of the certificate doesn't match the hash
                // resolved from the confirmation claim, return an error.
                var hash = Base64Url.EncodeToString(certificate.GetCertHash(HashAlgorithmName.SHA256));
                if (!CryptographicOperations.FixedTimeEquals(
                    left : MemoryMarshal.AsBytes<char>(hash),
                    right: MemoryMarshal.AsBytes<char>(thumbprint)))
                {
                    context.Logger.LogInformation(6289, SR.GetResourceString(SR.ID6289));

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2204),
                        uri: SR.FormatID8000(SR.ID2204));

                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }

            throw new InvalidOperationException(SR.GetResourceString(SR.ID2196));
        }
    }

    /// <summary>
    /// Contains the logic responsible for ensuring a token was correctly resolved from the context.
    /// </summary>
    public sealed class ValidateAccessToken : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictValidationDispatcher _dispatcher;

        public ValidateAccessToken(IOpenIddictValidationDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAccessTokenValidated>()
                .UseSingletonHandler<ValidateAccessToken>()
                .SetOrder(ValidateIntrospectedTokenProofOfPossession.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            if (string.IsNullOrEmpty(context.AccessToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                // Note: by default, access tokens are not constrainted to specific presenters but must contain
                // at least one audience matching one of the values configured in the options, if applicable.
                DisableAudienceValidation = context.Options.Audiences.Count is 0,
                DisablePresenterValidation = true,
                Token = context.AccessToken,
                ValidTokenTypes = { TokenTypeIdentifiers.AccessToken }
            };

            notification.ValidAudiences.UnionWith(context.Options.Audiences);

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            if (notification.IsRejected)
            {
                if (context.RejectAccessToken)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                return;
            }

            context.AccessTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for ensuring that the challenge response contains an appropriate error.
    /// </summary>
    public sealed class AttachDefaultChallengeError : IOpenIddictValidationHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<AttachDefaultChallengeError>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // Try to retrieve the authentication context from the validation transaction and use
            // the error details returned during the authentication processing, if available.
            // If no error is attached to the authentication context, this likely means that
            // the request was rejected very early without even checking the access token or was
            // rejected due to a lack of permission. In this case, return an insufficient_access error
            // to inform the client that the user is not allowed to perform the requested action.

            var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                typeof(ProcessAuthenticationContext).FullName!);

            context.Response.Error ??= notification?.Error ?? Errors.InsufficientAccess;
            context.Response.ErrorDescription ??= notification?.ErrorDescription ?? SR.GetResourceString(SR.ID2095);
            context.Response.ErrorUri ??= notification?.ErrorUri ?? SR.FormatID8000(SR.ID2095);

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the parameters
    /// populated from user-defined handlers to the sign-out response.
    /// </summary>
    public sealed class AttachCustomChallengeParameters : IOpenIddictValidationHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<AttachCustomChallengeParameters>()
                .SetOrder(100_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            if (context.Parameters.Count is > 0)
            {
                foreach (var parameter in context.Parameters)
                {
                    context.Response.SetParameter(parameter.Key, parameter.Value);
                }
            }

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the appropriate parameters to the error response.
    /// </summary>
    public sealed class AttachErrorParameters : IOpenIddictValidationHandler<ProcessErrorContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessErrorContext>()
                .UseSingletonHandler<AttachErrorParameters>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessErrorContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            context.Response.Error = context.Error;
            context.Response.ErrorDescription = context.ErrorDescription;
            context.Response.ErrorUri = context.ErrorUri;

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the parameters
    /// populated from user-defined handlers to the error response.
    /// </summary>
    public sealed class AttachCustomErrorParameters : IOpenIddictValidationHandler<ProcessErrorContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessErrorContext>()
                .UseSingletonHandler<AttachCustomErrorParameters>()
                .SetOrder(100_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessErrorContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            if (context.Parameters.Count is > 0)
            {
                foreach (var parameter in context.Parameters)
                {
                    context.Response.SetParameter(parameter.Key, parameter.Value);
                }
            }

            return ValueTask.CompletedTask;
        }
    }
}
