/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Extensions;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.Validation;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictValidationHandlers
{
    public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
        /*
         * Authentication processing:
         */
        EvaluateValidatedTokens.Descriptor,
        ValidateRequiredTokens.Descriptor,
        ResolveServerConfiguration.Descriptor,
        ResolveIntrospectionEndpoint.Descriptor,
        EvaluateIntrospectionRequest.Descriptor,
        AttachIntrospectionRequestParameters.Descriptor,
        EvaluateGeneratedClientAssertion.Descriptor,
        PrepareClientAssertionPrincipal.Descriptor,
        GenerateClientAssertion.Descriptor,
        AttachIntrospectionRequestClientCredentials.Descriptor,
        SendIntrospectionRequest.Descriptor,
        ValidateIntrospectedTokenUsage.Descriptor,
        ValidateIntrospectedTokenAudiences.Descriptor,
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
    ]);

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
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

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

            return default;
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
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.RequireAccessToken && string.IsNullOrEmpty(context.AccessToken))
            {
                context.Reject(
                    error: Errors.MissingToken,
                    description: SR.GetResourceString(SR.ID2000),
                    uri: SR.FormatID8000(SR.ID2000));

                return default;
            }

            return default;
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
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            try
            {
                // Resolve and attach the server configuration to the context if none has been set already.
                context.Configuration ??= await context.Options.ConfigurationManager
                    .GetConfigurationAsync(context.CancellationToken)
                    .WaitAsync(context.CancellationToken) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception) &&
                exception is not OperationCanceledException)
            {
                context.Logger.LogError(exception, SR.GetResourceString(SR.ID6219));

                context.Reject(
                    error: Errors.ServerError,
                    description: SR.GetResourceString(SR.ID2170),
                    uri: SR.FormatID8000(SR.ID2170));

                return;
            }
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
                .UseSingletonHandler<ResolveIntrospectionEndpoint>()
                .SetOrder(ResolveServerConfiguration.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // If the URI of the introspection endpoint wasn't explicitly set
            // at this stage, try to extract it from the server configuration.
            context.IntrospectionEndpoint ??= context.Configuration.IntrospectionEndpoint switch
            {
                { IsAbsoluteUri: true } uri when !OpenIddictHelpers.IsImplicitFileUri(uri) => uri,

                _ => null
            };

            return default;
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
                .SetOrder(ResolveIntrospectionEndpoint.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.SendIntrospectionRequest = context.Options.ValidationType is OpenIddictValidationType.Introspection;

            return default;
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
                .SetOrder(EvaluateIntrospectionRequest.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Attach a new request instance if necessary.
            context.IntrospectionRequest ??= new OpenIddictRequest();

            context.IntrospectionRequest.Token = context.AccessToken;
            context.IntrospectionRequest.TokenTypeHint = TokenTypeHints.AccessToken;

            return default;
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
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            (context.GenerateClientAssertion,
             context.IncludeClientAssertion) = context.Options.SigningCredentials.Count switch
            {
                // If a introspection request is going to be sent and if at least one signing key
                // was attached to the validation options, generate and include a client assertion
                // token if the configuration indicates the server supports private_key_jwt.
                > 0 when context.Configuration.IntrospectionEndpointAuthMethodsSupported.Contains(
                    ClientAuthenticationMethods.PrivateKeyJwt) => (true, true),

                _ => (false, false)
            };

            return default;
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
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Configuration.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));

            // Create a new principal that will be used to store the client assertion claims.
            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role));

            principal.SetCreationDate(
#if SUPPORTS_TIME_PROVIDER
                context.Options.TimeProvider?.GetUtcNow() ??
#endif
                DateTimeOffset.UtcNow);

            var lifetime = context.Options.ClientAssertionLifetime;
            if (lifetime.HasValue)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Use the issuer URI as the audience. Applications that need to
            // use a different value can register a custom event handler.
            principal.SetAudiences(context.Configuration.Issuer.OriginalString);

            // Use the client_id as both the subject and the issuer, as required by the specifications.
            principal.SetClaim(Claims.Private.Issuer, context.Options.ClientId)
                     .SetClaim(Claims.Subject, context.Options.ClientId);

            // Use a random GUID as the JWT unique identifier.
            principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString());

            context.ClientAssertionPrincipal = principal;

            return default;
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
                .UseScopedHandler<GenerateClientAssertion>()
                .SetOrder(PrepareClientAssertionPrincipal.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                CreateTokenEntry = false,
                IsReferenceToken = false,
                PersistTokenPayload = false,
                Principal = context.ClientAssertionPrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.ClientAssertion
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
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
                TokenFormats.Jwt   => ClientAssertionTypes.JwtBearer,
                TokenFormats.Saml2 => ClientAssertionTypes.Saml2Bearer,

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
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.IntrospectionRequest is not null, SR.GetResourceString(SR.ID4008));

            // Always attach the client_id to the request, even if an assertion is sent.
            context.IntrospectionRequest.ClientId = context.Options.ClientId;

            // Note: client authentication methods are mutually exclusive so the client_assertion
            // and client_secret parameters MUST never be sent at the same time. For more information,
            // see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.
            if (context.IncludeClientAssertion)
            {
                context.IntrospectionRequest.ClientAssertion = context.ClientAssertion;
                context.IntrospectionRequest.ClientAssertionType = context.ClientAssertionType;
            }

            // Note: the client_secret may be null at this point (e.g for a public
            // client or if a custom authentication method is used by the application).
            else
            {
                context.IntrospectionRequest.ClientSecret = context.Options.ClientSecret;
            }

            return default;
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
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.IntrospectionRequest is not null, SR.GetResourceString(SR.ID4008));

            // Ensure the introspection endpoint is present and is a valid absolute URI.
            if (context.IntrospectionEndpoint is not { IsAbsoluteUri: true } ||
                OpenIddictHelpers.IsImplicitFileUri(context.IntrospectionEndpoint))
            {
                throw new InvalidOperationException(SR.FormatID0301(Metadata.IntrospectionEndpoint));
            }

            try
            {
                (context.IntrospectionResponse, context.AccessTokenPrincipal) =
                    await _service.SendIntrospectionRequestAsync(
                        context.Configuration, context.IntrospectionRequest,
                        context.IntrospectionEndpoint, context.CancellationToken);
            }

            catch (ProtocolException exception)
            {
                context.Logger.LogDebug(exception, SR.GetResourceString(SR.ID6155));

                context.Reject(
                    error: exception.Error,
                    description: exception.ErrorDescription,
                    uri: exception.ErrorUri);

                return;
            }

            context.Logger.LogTrace(SR.GetResourceString(SR.ID6154), context.AccessToken, context.AccessTokenPrincipal.Claims);
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
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.AccessTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // OpenIddict-based authorization servers always return the actual token type using
            // the special "token_usage" claim, that helps resource servers determine whether the
            // introspected token is one of the expected types and prevents token substitution attacks.
            //
            // If a "token_usage" claim can be extracted from the principal, use it to determine whether
            // the token details returned by the authorization server correspond to an access token.
            var usage = context.AccessTokenPrincipal.GetClaim(Claims.TokenUsage);
            if (!string.IsNullOrEmpty(usage) && usage is not TokenTypeHints.AccessToken)
            {
                context.Reject(
                    error: Errors.InvalidToken,
                    description: SR.GetResourceString(SR.ID2110),
                    uri: SR.FormatID8000(SR.ID2110));

                return default;
            }

            // Note: if no token usage could be resolved, the token is assumed to be an access token.
            context.AccessTokenPrincipal = context.AccessTokenPrincipal.SetTokenType(usage ?? TokenTypeHints.AccessToken);

            return default;
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
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.AccessTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // In theory, authorization servers are expected to return an error (or an active=false response)
            // when the caller is not allowed to introspect the token (e.g because it's not a valid audience
            // or authorized party). Unfortunately, some servers are known to have a relaxed validation policy.
            //
            // To ensure the token can be used with this resource server, a second pass is manually performed here.

            // If no explicit audience has been configured, skip the audience validation.
            if (context.Options.Audiences.Count is 0)
            {
                return default;
            }

            // If the access token doesn't have any audience attached, return an error.
            var audiences = context.AccessTokenPrincipal.GetAudiences();
            if (audiences.IsDefaultOrEmpty)
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6157));

                context.Reject(
                    error: Errors.InvalidToken,
                    description: SR.GetResourceString(SR.ID2093),
                    uri: SR.FormatID8000(SR.ID2093));

                return default;
            }

            // If the access token doesn't include any registered audience, return an error.
            if (!audiences.Intersect(context.Options.Audiences, StringComparer.Ordinal).Any())
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6158));

                context.Reject(
                    error: Errors.InvalidToken,
                    description: SR.GetResourceString(SR.ID2094),
                    uri: SR.FormatID8000(SR.ID2094));

                return default;
            }

            return default;
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
                .UseScopedHandler<ValidateAccessToken>()
                .SetOrder(ValidateIntrospectedTokenUsage.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (string.IsNullOrEmpty(context.AccessToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.AccessToken,
                ValidTokenTypes = { TokenTypeHints.AccessToken }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
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
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

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

            return default;
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
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.Parameters.Count > 0)
            {
                foreach (var parameter in context.Parameters)
                {
                    context.Response.SetParameter(parameter.Key, parameter.Value);
                }
            }

            return default;
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
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.Response.Error = context.Error;
            context.Response.ErrorDescription = context.ErrorDescription;
            context.Response.ErrorUri = context.ErrorUri;

            return default;
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
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.Parameters.Count > 0)
            {
                foreach (var parameter in context.Parameters)
                {
                    context.Response.SetParameter(parameter.Key, parameter.Value);
                }
            }

            return default;
        }
    }
}
