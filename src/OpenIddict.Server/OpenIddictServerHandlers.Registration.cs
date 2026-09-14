/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Text;
using System.Collections.Immutable;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server;

public static partial class OpenIddictServerHandlers
{
    public static class Registration
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Registration request top-level processing:
             */
            ExtractRegistrationRequest.Descriptor,
            ValidateRegistrationRequest.Descriptor,
            HandleRegistrationRequest.Descriptor,
            ApplyRegistrationResponse<ProcessChallengeContext>.Descriptor,
            ApplyRegistrationResponse<ProcessErrorContext>.Descriptor,
            ApplyRegistrationResponse<ProcessRequestContext>.Descriptor,

            /*
             * Registration request validation:
             */
            ValidateRequestType.Descriptor,
            ValidateInitialAccessToken.Descriptor,
            ValidateRegistrationAccessToken.Descriptor,
            ValidateSoftwareStatement.Descriptor,
            ValidateUpdatedMetadata.Descriptor,
            ValidateClientMetadata.Descriptor,
            ValidateScopes.Descriptor,
            AttachApplicationDescriptor.Descriptor,

            /*
             * Registration request handling:
             */
            AttachApplication.Descriptor,

            /*
             * Sign-in processing:
             */
            ProcessRegistrationOperation.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for extracting registration requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ExtractRegistrationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ExtractRegistrationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireRegistrationRequest>()
                    .UseSingletonHandler<ExtractRegistrationRequest>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ExtractRegistrationRequestContext(context.Transaction);
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

                if (notification.Request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0805));
                }

                context.Logger.LogInformation(6600, SR.GetResourceString(SR.ID6600), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating registration requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ValidateRegistrationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateRegistrationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireRegistrationRequest>()
                    .UseSingletonHandler<ValidateRegistrationRequest>()
                    .SetOrder(ExtractRegistrationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ValidateRegistrationRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                // Store the context object in the transaction so it can be later retrieved by handlers
                // that want to access the resolved descriptor without triggering a new validation.
                context.Transaction.SetProperty(typeof(ValidateRegistrationRequestContext).FullName!, notification);

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

                context.Logger.LogInformation(6601, SR.GetResourceString(SR.ID6601));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling registration requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class HandleRegistrationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public HandleRegistrationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireRegistrationRequest>()
                    .UseSingletonHandler<HandleRegistrationRequest>()
                    .SetOrder(ValidateRegistrationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new HandleRegistrationRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                // Store the context object in the transaction so it can be later retrieved by the sign-in
                // handlers (e.g when the pass-through mode is used and the request is approved later).
                context.Transaction.SetProperty(typeof(HandleRegistrationRequestContext).FullName!, notification);

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

                // Registration operations are persisted by a sign-in handler: this allows applications
                // using the pass-through mode to approve registration requests by triggering a sign-in
                // operation (with an empty principal) and reject them by triggering a challenge.
                var @event = new ProcessSignInContext(context.Transaction)
                {
                    Principal = new ClaimsPrincipal(new ClaimsIdentity()),
                    Response = new OpenIddictResponse()
                };

                await _dispatcher.DispatchAsync(@event);

                if (@event.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (@event.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (@event.IsRejected)
                {
                    context.Reject(
                        error: @event.Error ?? Errors.InvalidClientMetadata,
                        description: @event.ErrorDescription,
                        uri: @event.ErrorUri);
                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing registration responses and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyRegistrationResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ApplyRegistrationResponse(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireRegistrationRequest>()
                    .UseSingletonHandler<ApplyRegistrationResponse<TContext>>()
                    .SetOrder(500_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ApplyRegistrationResponseContext(context.Transaction);
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

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0806));
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting registration requests using an unsupported
        /// HTTP method or that don't specify the client identifier when required (RFC 7592).
        /// </summary>
        public sealed class ValidateRequestType : IOpenIddictServerHandler<ValidateRegistrationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRegistrationRequestContext>()
                    .UseSingletonHandler<ValidateRequestType>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateRegistrationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.RequestType is OpenIddictServerRegistrationRequestType.Unknown)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2084),
                        uri: SR.FormatID8000(SR.ID2084));

                    return ValueTask.CompletedTask;
                }

                // Requests sent to the client configuration endpoint MUST identify the client.
                //
                // See https://datatracker.ietf.org/doc/html/rfc7592#section-2 for more information.
                if (context.RequestType is not OpenIddictServerRegistrationRequestType.Registration &&
                    string.IsNullOrEmpty(context.ClientId))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029(Parameters.ClientId),
                        uri: SR.FormatID8000(SR.ID2029));

                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the initial access token attached to registration requests.
        /// </summary>
        public sealed class ValidateInitialAccessToken : IOpenIddictServerHandler<ValidateRegistrationRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateInitialAccessToken(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRegistrationRequestContext>()
                    .UseSingletonHandler<ValidateInitialAccessToken>()
                    .SetOrder(ValidateRequestType.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateRegistrationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.RequestType is not OpenIddictServerRegistrationRequestType.Registration)
                {
                    return;
                }

                // Note: custom handlers executed before this handler can attach a principal
                // to accept initial access tokens that were not issued by this server.
                if (context.InitialAccessTokenPrincipal is null && !string.IsNullOrEmpty(context.Request.AccessToken))
                {
                    var notification = new ProcessAuthenticationContext(context.Transaction);
                    await _dispatcher.DispatchAsync(notification);

                    // Store the context object in the transaction so it can be later retrieved by handlers
                    // that want to access the authentication result without triggering a new authentication flow.
                    context.Transaction.SetProperty(typeof(ProcessAuthenticationContext).FullName!, notification);

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
                            error: notification.Error ?? Errors.InvalidToken,
                            description: notification.ErrorDescription,
                            uri: notification.ErrorUri);
                        return;
                    }

                    context.InitialAccessTokenPrincipal = notification.AccessTokenPrincipal;
                }

                // Unless open registration was explicitly enabled, an initial access token is required.
                //
                // See https://datatracker.ietf.org/doc/html/rfc7591#section-3 for more information.
                if (context.InitialAccessTokenPrincipal is null)
                {
                    if (context.Options.AllowAnonymousClientRegistration)
                    {
                        return;
                    }

                    context.Logger.LogInformation(6603, SR.GetResourceString(SR.ID6603));

                    context.Reject(
                        error: Errors.MissingToken,
                        description: SR.GetResourceString(SR.ID2401),
                        uri: SR.FormatID8000(SR.ID2401));

                    return;
                }

                // Ensure the initial access token contains one of the dedicated scopes, if configured.
                if (context.Options.InitialAccessTokenScopes.Count is > 0 &&
                   !context.Options.InitialAccessTokenScopes.Any(context.InitialAccessTokenPrincipal.HasScope))
                {
                    context.Reject(
                        error: Errors.InsufficientScope,
                        description: SR.GetResourceString(SR.ID2402),
                        uri: SR.FormatID8000(SR.ID2402));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the registration access token
        /// attached to requests sent to the client configuration endpoint (RFC 7592).
        /// </summary>
        public sealed class ValidateRegistrationAccessToken : IOpenIddictServerHandler<ValidateRegistrationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRegistrationRequestContext>()
                    .UseSingletonHandler<ValidateRegistrationAccessToken>()
                    .SetOrder(ValidateInitialAccessToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateRegistrationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Note: custom handlers executed before this handler can attach
                // the application to use a different authentication mechanism.
                if (context.RequestType is OpenIddictServerRegistrationRequestType.Registration || context.Application is not null)
                {
                    return;
                }

                if (string.IsNullOrEmpty(context.Request.AccessToken))
                {
                    context.Reject(
                        error: Errors.MissingToken,
                        description: SR.GetResourceString(SR.ID2000),
                        uri: SR.FormatID8000(SR.ID2000));

                    return;
                }

                var tokens = context.ServiceProvider.GetService<IOpenIddictTokenManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var applications = context.ServiceProvider.GetService<IOpenIddictApplicationManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                // Note: to prevent client identifiers from being enumerated, the same invalid_token error is
                // returned whether the token is invalid or the client doesn't exist or was deleted.
                //
                // See https://datatracker.ietf.org/doc/html/rfc7592#section-2.1 for more information.
                var token = await tokens.FindByReferenceIdAsync(context.Request.AccessToken, context.CancellationToken);
                if (token is null ||
                    !await tokens.HasTypeAsync(token, TokenTypeIdentifiers.Private.RegistrationAccessToken, context.CancellationToken) ||
                    !await tokens.HasStatusAsync(token, Statuses.Valid, context.CancellationToken) ||
                    await tokens.GetExpirationDateAsync(token, context.CancellationToken) is DateTimeOffset date &&
                    date < context.Options.TimeProvider.GetUtcNow() ||
                    await tokens.GetApplicationIdAsync(token, context.CancellationToken) is not { Length: > 0 } identifier ||
                    await applications.FindByIdAsync(identifier, context.CancellationToken) is not object application ||
                    !string.Equals(await applications.GetClientIdAsync(application, context.CancellationToken), context.ClientId, StringComparison.Ordinal))
                {
                    context.Logger.LogInformation(6603, SR.GetResourceString(SR.ID6603));

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2400),
                        uri: SR.FormatID8000(SR.ID2400));

                    return;
                }

                // Ensure the client application is still allowed to manage its registration.
                if (!context.Options.IgnoreEndpointPermissions &&
                    !await applications.HasPermissionAsync(application, Permissions.Endpoints.Registration, context.CancellationToken))
                {
                    context.Reject(
                        error: Errors.InsufficientAccess,
                        description: SR.GetResourceString(SR.ID2414),
                        uri: SR.FormatID8000(SR.ID2414));

                    return;
                }

                context.Application = application;
                context.RegistrationAccessToken = token;
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the software statement attached to the client
        /// metadata and merging the claims it contains with the other metadata (RFC 7591, section 2.3).
        /// </summary>
        public sealed class ValidateSoftwareStatement : IOpenIddictServerHandler<ValidateRegistrationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRegistrationRequestContext>()
                    .UseSingletonHandler<ValidateSoftwareStatement>()
                    .SetOrder(ValidateRegistrationAccessToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateRegistrationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.RequestType is not (OpenIddictServerRegistrationRequestType.Registration or
                                                OpenIddictServerRegistrationRequestType.Update))
                {
                    return;
                }

                var statement = (string?) context.Request[ClientMetadata.SoftwareStatement];
                if (string.IsNullOrEmpty(statement))
                {
                    if (context.Options.RequireSoftwareStatement && context.SoftwareStatementPrincipal is null)
                    {
                        context.Reject(
                            error: Errors.InvalidSoftwareStatement,
                            description: SR.GetResourceString(SR.ID2411),
                            uri: SR.FormatID8000(SR.ID2411));
                    }

                    return;
                }

                var handler = new JsonWebTokenHandler();
                if (!handler.CanReadToken(statement))
                {
                    Reject(Errors.InvalidSoftwareStatement, SR.ID2409);
                    return;
                }

                // Note: custom handlers executed before this handler can attach a principal
                // to accept software statements validated using a different mechanism.
                if (context.SoftwareStatementPrincipal is null)
                {
                    if (context.Options.SoftwareStatementSigningKeys.Count is 0)
                    {
                        Reject(Errors.UnapprovedSoftwareStatement, SR.ID2410);
                        return;
                    }

                    var result = await handler.ValidateTokenAsync(statement, new TokenValidationParameters
                    {
                        IssuerSigningKeys = context.Options.SoftwareStatementSigningKeys,
                        RequireExpirationTime = false,
                        RequireSignedTokens = true,
                        TryAllIssuerSigningKeys = true,
                        ValidateAudience = false,
                        ValidateIssuer = context.Options.SoftwareStatementIssuers.Count is > 0,
                        ValidateIssuerSigningKey = false,
                        ValidateLifetime = true,
                        ValidIssuers = context.Options.SoftwareStatementIssuers
                    });

                    if (!result.IsValid)
                    {
                        context.Logger.LogInformation(6607, result.Exception, SR.GetResourceString(SR.ID6607));

                        // Software statements that are not signed by a trusted party or issued by a trusted issuer
                        // are rejected as unapproved. Other errors (e.g expired tokens) are reported as invalid.
                        //
                        // See https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2 for more information.
                        if (result.Exception is SecurityTokenSignatureKeyNotFoundException or
                                                SecurityTokenInvalidSignatureException    or
                                                SecurityTokenInvalidIssuerException)
                        {
                            Reject(Errors.UnapprovedSoftwareStatement, SR.ID2410);
                            return;
                        }

                        Reject(Errors.InvalidSoftwareStatement, SR.ID2409);
                        return;
                    }

                    context.SoftwareStatementPrincipal = new ClaimsPrincipal(result.ClaimsIdentity);
                }

                // Software statements MUST contain an issuer claim.
                //
                // See https://datatracker.ietf.org/doc/html/rfc7591#section-2.3 for more information.
                var token = handler.ReadJsonWebToken(statement);
                if (string.IsNullOrEmpty(token.Issuer))
                {
                    Reject(Errors.InvalidSoftwareStatement, SR.ID2409);
                    return;
                }

                // Client metadata values conveyed in the software statement take precedence over the plain JSON values.
                //
                // See https://datatracker.ietf.org/doc/html/rfc7591#section-3.1.1 for more information.
                using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(token.EncodedPayload));
                if (document.RootElement.ValueKind is not JsonValueKind.Object)
                {
                    Reject(Errors.InvalidSoftwareStatement, SR.ID2409);
                    return;
                }

                foreach (var property in document.RootElement.EnumerateObject())
                {
                    if (property.Name is Claims.Issuer or Claims.Audience or Claims.ExpiresAt or
                                         Claims.IssuedAt or Claims.NotBefore or Claims.JwtId or ClientMetadata.SoftwareStatement)
                    {
                        continue;
                    }

                    context.Request.SetParameter(property.Name, new OpenIddictParameter(property.Value.Clone()));
                }

                void Reject(string error, string identifier) => context.Reject(
                    error: error,
                    description: SR.GetResourceString(identifier),
                    uri: SR.FormatID8000(identifier));
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the metadata specific to client update requests (RFC 7592).
        /// </summary>
        public sealed class ValidateUpdatedMetadata : IOpenIddictServerHandler<ValidateRegistrationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRegistrationRequestContext>()
                    .UseSingletonHandler<ValidateUpdatedMetadata>()
                    .SetOrder(ValidateSoftwareStatement.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateRegistrationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.RequestType is not OpenIddictServerRegistrationRequestType.Update)
                {
                    return;
                }

                // The client MUST NOT include the registration_access_token, registration_client_uri,
                // client_secret_expires_at or client_id_issued_at fields in update requests.
                //
                // See https://datatracker.ietf.org/doc/html/rfc7592#section-2.2 for more information.
                foreach (var name in (string[]) [ClientMetadata.RegistrationAccessToken, ClientMetadata.RegistrationClientUri,
                                                 ClientMetadata.ClientSecretExpiresAt,   ClientMetadata.ClientIdIssuedAt])
                {
                    if (context.Request.HasParameter(name))
                    {
                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2412(name),
                            uri: SR.FormatID8000(SR.ID2412));

                        return;
                    }
                }

                // If the client includes the client_secret field, it MUST match the currently issued client secret:
                // clients MUST NOT be allowed to overwrite their existing client secret with their own chosen value.
                if ((string?) context.Request[ClientMetadata.ClientSecret] is { Length: > 0 } secret && context.Application is not null)
                {
                    var manager = context.ServiceProvider.GetService<IOpenIddictApplicationManager>()
                        ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                    if (!await manager.ValidateClientSecretAsync(context.Application, secret, context.CancellationToken))
                    {
                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2403(ClientMetadata.ClientSecret),
                            uri: SR.FormatID8000(SR.ID2403));

                        return;
                    }
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the client metadata sent by
        /// the client application (RFC 7591, section 2 and OpenID Connect Dynamic Client
        /// Registration 1.0, section 2) and resolving the metadata accepted by the server.
        /// </summary>
        public sealed class ValidateClientMetadata : IOpenIddictServerHandler<ValidateRegistrationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRegistrationRequestContext>()
                    .UseSingletonHandler<ValidateClientMetadata>()
                    .SetOrder(ValidateUpdatedMetadata.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            private static readonly ImmutableHashSet<string> BooleanMetadata = ImmutableHashSet.Create(StringComparer.Ordinal,
                ClientMetadata.BackchannelLogoutSessionRequired, ClientMetadata.DPoPBoundAccessTokens,
                ClientMetadata.FrontchannelLogoutSessionRequired, ClientMetadata.RequireAuthTime,
                ClientMetadata.RequirePushedAuthorizationRequests, ClientMetadata.RequireSignedRequestObject,
                ClientMetadata.TlsClientCertificateBoundAccessTokens);

            private static readonly ImmutableHashSet<string> StringMetadata = ImmutableHashSet.Create(StringComparer.Ordinal,
                ClientMetadata.IdTokenEncryptedResponseAlg, ClientMetadata.IdTokenEncryptedResponseEnc,
                ClientMetadata.RequestObjectEncryptionAlg, ClientMetadata.RequestObjectEncryptionEnc,
                ClientMetadata.RequestObjectSigningAlg, ClientMetadata.SoftwareId, ClientMetadata.SoftwareStatement,
                ClientMetadata.SoftwareVersion, ClientMetadata.TlsClientAuthSanDns, ClientMetadata.TlsClientAuthSanEmail,
                ClientMetadata.TlsClientAuthSanIp, ClientMetadata.TlsClientAuthSanUri, ClientMetadata.TlsClientAuthSubjectDn,
                ClientMetadata.TokenEndpointAuthSigningAlg, ClientMetadata.UserinfoEncryptedResponseAlg,
                ClientMetadata.UserinfoEncryptedResponseEnc, ClientMetadata.UserinfoSignedResponseAlg);

            private static readonly ImmutableHashSet<string> WebUriMetadata = ImmutableHashSet.Create(StringComparer.Ordinal,
                ClientMetadata.BackchannelLogoutUri, ClientMetadata.ClientUri, ClientMetadata.FrontchannelLogoutUri,
                ClientMetadata.InitiateLoginUri, ClientMetadata.LogoUri, ClientMetadata.PolicyUri,
                ClientMetadata.SectorIdentifierUri, ClientMetadata.TosUri);

            private static readonly ImmutableHashSet<string> LocalizableMetadata = ImmutableHashSet.Create(StringComparer.Ordinal,
                ClientMetadata.ClientName, ClientMetadata.ClientUri, ClientMetadata.LogoUri,
                ClientMetadata.PolicyUri, ClientMetadata.TosUri);

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateRegistrationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.RequestType is not (OpenIddictServerRegistrationRequestType.Registration or
                                                OpenIddictServerRegistrationRequestType.Update))
                {
                    return ValueTask.CompletedTask;
                }

                foreach (var parameter in context.Request.GetParameters())
                {
                    // Note: the language tag of localized values (e.g client_name#fr) is ignored for validation purposes.
                    var index = parameter.Key.IndexOf('#');
                    var name = index is > 0 ? parameter.Key[..index] : parameter.Key;
                    if (index is > 0 && !LocalizableMetadata.Contains(name))
                    {
                        continue;
                    }

                    var value = (JsonElement) parameter.Value;

                    var valid = name switch
                    {
                        ClientMetadata.ClientName => value.ValueKind is JsonValueKind.String,

                        ClientMetadata.Contacts or ClientMetadata.DefaultAcrValues => IsStringArray(value, static _ => true),

                        ClientMetadata.RedirectUris or ClientMetadata.PostLogoutRedirectUris or ClientMetadata.RequestUris
                            => IsStringArray(value, IsCallbackUri),

                        ClientMetadata.GrantTypes or ClientMetadata.ResponseTypes
                            => IsStringArray(value, static item => !string.IsNullOrEmpty(item)),

                        ClientMetadata.Scope or ClientMetadata.TokenEndpointAuthMethod or ClientMetadata.ApplicationType or
                        ClientMetadata.SubjectType or ClientMetadata.IdTokenSignedResponseAlg
                            => value.ValueKind is JsonValueKind.String && !string.IsNullOrEmpty(value.GetString()),

                        ClientMetadata.Jwks => value.ValueKind is JsonValueKind.Object,
                        ClientMetadata.JwksUri => value.ValueKind is JsonValueKind.String && IsWebUri(value.GetString()),

                        ClientMetadata.DefaultMaxAge => value.ValueKind is JsonValueKind.Number &&
                            value.TryGetInt64(out var age) && age >= 0,

                        _ when BooleanMetadata.Contains(name) => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
                        _ when StringMetadata.Contains(name)  => value.ValueKind is JsonValueKind.String,
                        _ when WebUriMetadata.Contains(name)  => value.ValueKind is JsonValueKind.String && IsWebUri(value.GetString()),

                        // Unrecognized metadata MUST be ignored by the authorization server.
                        //
                        // See https://datatracker.ietf.org/doc/html/rfc7591#section-2 for more information.
                        _ => (bool?) null
                    };

                    if (valid is null)
                    {
                        continue;
                    }

                    if (valid is false)
                    {
                        context.Logger.LogInformation(6602, SR.GetResourceString(SR.ID6602), parameter.Key);

                        context.Reject(
                            error: name is ClientMetadata.RedirectUris ? Errors.InvalidRedirectUri : Errors.InvalidClientMetadata,
                            description: name is ClientMetadata.RedirectUris or ClientMetadata.PostLogoutRedirectUris or ClientMetadata.RequestUris
                                ? SR.FormatID2405(name) : SR.FormatID2403(parameter.Key),
                            uri: SR.FormatID8000(name is ClientMetadata.RedirectUris or ClientMetadata.PostLogoutRedirectUris or ClientMetadata.RequestUris
                                ? SR.ID2405 : SR.ID2403));

                        return ValueTask.CompletedTask;
                    }

                    context.Metadata[parameter.Key] = value.Clone();
                }

                // Resolve the grant types, that default to authorization_code if not explicitly specified.
                //
                // See https://datatracker.ietf.org/doc/html/rfc7591#section-2 for more information.
                context.GrantTypes.Clear();
                context.GrantTypes.UnionWith(context.Metadata.TryGetValue(ClientMetadata.GrantTypes, out var types)
                    ? types.EnumerateArray().Select(static type => type.GetString()!)
                    : [GrantTypes.AuthorizationCode]);

                // Note: grant types must be both enabled on the server and allowed for dynamically registered clients.
                // Rejecting the request (rather than silently removing the grant) is permitted by RFC 7591, section 3.2.2.
                foreach (var type in context.GrantTypes)
                {
                    if (!context.Options.GrantTypes.Contains(type) || !context.Options.RegistrationAllowedGrantTypes.Contains(type))
                    {
                        Reject(Errors.InvalidClientMetadata, SR.FormatID2404(ClientMetadata.GrantTypes, type), SR.ID2404);
                        return ValueTask.CompletedTask;
                    }
                }

                // Resolve the response types, that default to code when the authorization code grant is used.
                context.ResponseTypes.Clear();

                if (context.Metadata.TryGetValue(ClientMetadata.ResponseTypes, out types))
                {
                    foreach (var type in types.EnumerateArray().Select(static type => type.GetString()!))
                    {
                        // Note: response types are compared using their components and are
                        // normalized to use the representation used in the server options.
                        var components = type.Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
                        var normalized = context.Options.ResponseTypes.FirstOrDefault(value =>
                            value.Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal).SetEquals(components));

                        if (string.IsNullOrEmpty(normalized))
                        {
                            Reject(Errors.InvalidClientMetadata, SR.FormatID2404(ClientMetadata.ResponseTypes, type), SR.ID2404);
                            return ValueTask.CompletedTask;
                        }

                        // Ensure the response types are consistent with the grant types.
                        //
                        // See https://datatracker.ietf.org/doc/html/rfc7591#section-2.1 for more information.
                        if (components.Contains(ResponseTypes.Code) && !context.GrantTypes.Contains(GrantTypes.AuthorizationCode))
                        {
                            Reject(Errors.InvalidClientMetadata, SR.FormatID2407(type, GrantTypes.AuthorizationCode), SR.ID2407);
                            return ValueTask.CompletedTask;
                        }

                        if ((components.Contains(ResponseTypes.Token) || components.Contains(ResponseTypes.IdToken)) &&
                            !context.GrantTypes.Contains(GrantTypes.Implicit))
                        {
                            Reject(Errors.InvalidClientMetadata, SR.FormatID2407(type, GrantTypes.Implicit), SR.ID2407);
                            return ValueTask.CompletedTask;
                        }

                        context.ResponseTypes.Add(normalized);
                    }
                }

                else if (context.GrantTypes.Contains(GrantTypes.AuthorizationCode))
                {
                    if (!context.Options.ResponseTypes.Contains(ResponseTypes.Code))
                    {
                        Reject(Errors.InvalidClientMetadata, SR.FormatID2404(ClientMetadata.ResponseTypes, ResponseTypes.Code), SR.ID2404);
                        return ValueTask.CompletedTask;
                    }

                    context.ResponseTypes.Add(ResponseTypes.Code);
                }

                // Redirect URIs are required when using a redirect-based flow.
                if ((context.GrantTypes.Contains(GrantTypes.AuthorizationCode) || context.GrantTypes.Contains(GrantTypes.Implicit)) &&
                    (!context.Metadata.TryGetValue(ClientMetadata.RedirectUris, out var uris) || uris.GetArrayLength() is 0))
                {
                    Reject(Errors.InvalidRedirectUri, SR.FormatID2406(ClientMetadata.RedirectUris,
                        context.GrantTypes.Contains(GrantTypes.AuthorizationCode) ? GrantTypes.AuthorizationCode : GrantTypes.Implicit), SR.ID2406);
                    return ValueTask.CompletedTask;
                }

                // Resolve the client authentication method, that defaults to client_secret_basic.
                //
                // See https://datatracker.ietf.org/doc/html/rfc7591#section-2 for more information.
                context.TokenEndpointAuthenticationMethod = context.Metadata.TryGetValue(ClientMetadata.TokenEndpointAuthMethod, out var method)
                    ? method.GetString()
                    : ClientAuthenticationMethods.ClientSecretBasic;

                // Note: client_secret_jwt is not supported as client secrets are not stored in plain text.
                if (context.TokenEndpointAuthenticationMethod is not ClientAuthenticationMethods.None &&
                   (context.TokenEndpointAuthenticationMethod is ClientAuthenticationMethods.ClientSecretJwt ||
                    !context.Options.ClientAuthenticationMethods.Contains(context.TokenEndpointAuthenticationMethod!)))
                {
                    Reject(Errors.InvalidClientMetadata, SR.FormatID2404(
                        ClientMetadata.TokenEndpointAuthMethod, context.TokenEndpointAuthenticationMethod), SR.ID2404);
                    return ValueTask.CompletedTask;
                }

                // Public clients cannot use grants that require client authentication.
                if (context.TokenEndpointAuthenticationMethod is ClientAuthenticationMethods.None &&
                    context.GrantTypes.Contains(GrantTypes.ClientCredentials))
                {
                    Reject(Errors.InvalidClientMetadata, SR.FormatID2408(
                        ClientMetadata.TokenEndpointAuthMethod, ClientMetadata.GrantTypes), SR.ID2408);
                    return ValueTask.CompletedTask;
                }

                // JSON Web Key Sets can be sent by value or by reference, but not both.
                //
                // See https://datatracker.ietf.org/doc/html/rfc7591#section-2 for more information.
                if (context.Metadata.ContainsKey(ClientMetadata.Jwks) && context.Metadata.ContainsKey(ClientMetadata.JwksUri))
                {
                    Reject(Errors.InvalidClientMetadata, SR.FormatID2408(ClientMetadata.Jwks, ClientMetadata.JwksUri), SR.ID2408);
                    return ValueTask.CompletedTask;
                }

                // Note: remote JSON Web Key Sets are not supported, as the authorization server would have to retrieve
                // them from an arbitrary location (which would expose it to server-side request forgery attacks).
                if (context.Metadata.TryGetValue(ClientMetadata.JwksUri, out var location))
                {
                    Reject(Errors.InvalidClientMetadata, SR.FormatID2404(ClientMetadata.JwksUri, location.GetString()), SR.ID2404);
                    return ValueTask.CompletedTask;
                }

                if (context.Metadata.TryGetValue(ClientMetadata.Jwks, out var jwks))
                {
                    JsonWebKeySet set;

                    try
                    {
                        set = new JsonWebKeySet(jwks.GetRawText());
                    }

                    catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                    {
                        Reject(Errors.InvalidClientMetadata, SR.FormatID2403(ClientMetadata.Jwks), SR.ID2403);
                        return ValueTask.CompletedTask;
                    }

                    // Only public asymmetric keys can be registered: symmetric and private keys are always rejected.
                    if (set.Keys.Count is 0 || set.Keys.Any(static key =>
                        string.Equals(key.Kty, JsonWebAlgorithmsKeyTypes.Octet, StringComparison.Ordinal) ||
                        !string.IsNullOrEmpty(key.D) || !string.IsNullOrEmpty(key.K) ||
                        !string.IsNullOrEmpty(key.P) || !string.IsNullOrEmpty(key.Q)))
                    {
                        Reject(Errors.InvalidClientMetadata, SR.GetResourceString(SR.ID2418), SR.ID2418);
                        return ValueTask.CompletedTask;
                    }
                }

                // Client authentication methods based on asymmetric keys or certificates require a JSON Web Key Set.
                if (context.TokenEndpointAuthenticationMethod is ClientAuthenticationMethods.PrivateKeyJwt or
                                                                 ClientAuthenticationMethods.SelfSignedTlsClientAuth or
                                                                 ClientAuthenticationMethods.TlsClientAuth && jwks.ValueKind is not JsonValueKind.Object)
                {
                    Reject(Errors.InvalidClientMetadata, SR.FormatID2417(
                        ClientMetadata.Jwks, context.TokenEndpointAuthenticationMethod), SR.ID2417);
                    return ValueTask.CompletedTask;
                }

                // Only the public subject type is supported.
                if (context.Metadata.TryGetValue(ClientMetadata.SubjectType, out var subject) &&
                    !string.Equals(subject.GetString(), SubjectTypes.Public, StringComparison.Ordinal))
                {
                    Reject(Errors.InvalidClientMetadata, SR.FormatID2404(ClientMetadata.SubjectType, subject.GetString()), SR.ID2404);
                    return ValueTask.CompletedTask;
                }

                if (context.Metadata.TryGetValue(ClientMetadata.ApplicationType, out var application) &&
                    application.GetString() is not (ApplicationTypes.Native or ApplicationTypes.Web))
                {
                    Reject(Errors.InvalidClientMetadata, SR.FormatID2404(ClientMetadata.ApplicationType, application.GetString()), SR.ID2404);
                    return ValueTask.CompletedTask;
                }

                // Web clients (the default application type) using the implicit grant MUST only register
                // redirect URIs using the https scheme and MUST NOT use localhost as the host name.
                //
                // See https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata for more information.
                if (context.GrantTypes.Contains(GrantTypes.Implicit) &&
                   (application.ValueKind is not JsonValueKind.String ||
                    string.Equals(application.GetString(), ApplicationTypes.Web, StringComparison.Ordinal)))
                {
                    if (context.Metadata.TryGetValue(ClientMetadata.RedirectUris, out var callbacks) &&
                        callbacks.EnumerateArray().Select(static item => new Uri(item.GetString()!, UriKind.Absolute)).FirstOrDefault(static uri =>
                            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) || uri.IsLoopback) is Uri callback)
                    {
                        Reject(Errors.InvalidRedirectUri, SR.FormatID2404(ClientMetadata.RedirectUris, callback.OriginalString), SR.ID2404);
                        return ValueTask.CompletedTask;
                    }
                }

                // Ensure the identity token signing algorithm is supported by one of the registered signing credentials.
                if (context.Metadata.TryGetValue(ClientMetadata.IdTokenSignedResponseAlg, out var algorithm) &&
                    !context.Options.SigningCredentials.Any(credentials =>
                        string.Equals(credentials.Algorithm, algorithm.GetString(), StringComparison.Ordinal)))
                {
                    Reject(Errors.InvalidClientMetadata, SR.FormatID2404(ClientMetadata.IdTokenSignedResponseAlg, algorithm.GetString()), SR.ID2404);
                    return ValueTask.CompletedTask;
                }

                // Resolve the scopes (the validation of the scopes themselves is performed by a separate handler).
                context.Scopes.Clear();

                if (context.Metadata.TryGetValue(ClientMetadata.Scope, out var scope))
                {
                    context.Scopes.UnionWith(scope.GetString()!.Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries));
                }

                // Enforce the scope registration policy: the scopes allowing to register new client applications can never
                // be requested (otherwise, a registered client could mint its own initial access tokens) and, if an allow list
                // was configured, only the listed scopes (and the openid/offline_access protocol scopes) can be requested.
                foreach (var name in context.Scopes)
                {
                    if (context.Options.InitialAccessTokenScopes.Contains(name) ||
                       (context.Options.RegistrationAllowedScopes.Count is > 0 && name is not (Scopes.OpenId or Scopes.OfflineAccess) &&
                       !context.Options.RegistrationAllowedScopes.Contains(name)))
                    {
                        Reject(Errors.InvalidClientMetadata, SR.FormatID2404(ClientMetadata.Scope, name), SR.ID2404);
                        return ValueTask.CompletedTask;
                    }
                }

                return ValueTask.CompletedTask;

                void Reject(string error, string description, string identifier)
                {
                    context.Logger.LogInformation(6602, SR.GetResourceString(SR.ID6602), description);

                    context.Reject(error: error, description: description, uri: SR.FormatID8000(identifier));
                }

                static bool IsStringArray(JsonElement element, Func<string?, bool> predicate)
                    => element.ValueKind is JsonValueKind.Array && element.EnumerateArray().All(item =>
                        item.ValueKind is JsonValueKind.String && predicate(item.GetString()));

                // Callback URIs MUST be absolute and MUST NOT include a fragment. To prevent script injection (e.g javascript:
                // or data: URIs rendered as the action of form_post responses), only the http and https schemes and private-use
                // URI schemes based on a reverse domain name (that always contain a period) are accepted.
                //
                // See https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
                // and https://datatracker.ietf.org/doc/html/rfc8252#section-7.1 for more information.
                static bool IsCallbackUri(string? value)
                    => Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) &&
                      !OpenIddictHelpers.IsImplicitFileUri(uri) && string.IsNullOrEmpty(uri.Fragment) &&
                      (string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                       string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) ||
                       uri.Scheme.IndexOf('.') is > 0);

                static bool IsWebUri(string? value)
                    => Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) &&
                       (string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase));
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting registration requests that specify unregistered scopes.
        /// Note: this handler is not used when scope validation is disabled.
        /// </summary>
        public sealed class ValidateScopes : IOpenIddictServerHandler<ValidateRegistrationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRegistrationRequestContext>()
                    .AddFilter<RequireScopeValidationEnabled>()
                    .UseSingletonHandler<ValidateScopes>()
                    .SetOrder(ValidateClientMetadata.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateRegistrationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.Scopes.Count is 0)
                {
                    return;
                }

                // If all the specified scopes are registered in the options, avoid making a database lookup.
                var scopes = new HashSet<string>(context.Scopes, StringComparer.Ordinal);
                scopes.ExceptWith(context.Options.Scopes);

                if (scopes.Count is not 0 && !context.Options.EnableDegradedMode)
                {
                    var manager = context.ServiceProvider.GetService<IOpenIddictScopeManager>()
                        ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                    await foreach (var scope in manager.FindByNamesAsync([.. scopes], context.CancellationToken))
                    {
                        var name = await manager.GetNameAsync(scope, context.CancellationToken);
                        if (!string.IsNullOrEmpty(name))
                        {
                            scopes.Remove(name);
                        }
                    }
                }

                if (scopes.Count is not 0)
                {
                    context.Logger.LogInformation(6602, SR.GetResourceString(SR.ID6602), ClientMetadata.Scope);

                    context.Reject(
                        error: Errors.InvalidClientMetadata,
                        description: SR.FormatID2404(ClientMetadata.Scope, string.Join(' ', scopes)),
                        uri: SR.FormatID8000(SR.ID2404));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for creating the application descriptor from the validated client metadata.
        /// Custom handlers executed after this handler can amend the descriptor to enforce additional policies.
        /// </summary>
        public sealed class AttachApplicationDescriptor : IOpenIddictServerHandler<ValidateRegistrationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRegistrationRequestContext>()
                    .UseSingletonHandler<AttachApplicationDescriptor>()
                    .SetOrder(ValidateScopes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateRegistrationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.RequestType is not (OpenIddictServerRegistrationRequestType.Registration or
                                                OpenIddictServerRegistrationRequestType.Update))
                {
                    return ValueTask.CompletedTask;
                }

                context.Descriptor = CreateDescriptor(context);

                return ValueTask.CompletedTask;
            }

            internal static OpenIddictApplicationDescriptor CreateDescriptor(ValidateRegistrationRequestContext context)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ClientType = context.TokenEndpointAuthenticationMethod is ClientAuthenticationMethods.None
                        ? ClientTypes.Public : ClientTypes.Confidential
                };

                var metadata = context.Metadata;

                if (metadata.TryGetValue(ClientMetadata.ApplicationType, out var kind))
                {
                    descriptor.ApplicationType = kind.GetString();
                }

                foreach (var (name, value) in metadata.Select(static item => (item.Key, item.Value)))
                {
                    if (name is ClientMetadata.ClientName)
                    {
                        descriptor.DisplayName = value.GetString();
                    }

                    else if (name.StartsWith(ClientMetadata.ClientName + '#', StringComparison.Ordinal))
                    {
                        try
                        {
                            descriptor.DisplayNames[CultureInfo.GetCultureInfo(name[(ClientMetadata.ClientName.Length + 1)..])] = value.GetString()!;
                        }

                        catch (CultureNotFoundException)
                        {
                            // Ignore localized values whose language tag is not supported.
                        }
                    }
                }

                if (metadata.TryGetValue(ClientMetadata.RedirectUris, out var uris))
                {
                    descriptor.RedirectUris.UnionWith(uris.EnumerateArray().Select(static uri => new Uri(uri.GetString()!, UriKind.Absolute)));
                }

                if (metadata.TryGetValue(ClientMetadata.PostLogoutRedirectUris, out uris))
                {
                    descriptor.PostLogoutRedirectUris.UnionWith(uris.EnumerateArray().Select(static uri => new Uri(uri.GetString()!, UriKind.Absolute)));
                }

                if (metadata.TryGetValue(ClientMetadata.Jwks, out var jwks))
                {
                    descriptor.JsonWebKeySet = new JsonWebKeySet(jwks.GetRawText());
                }

                // Generate a client secret for confidential clients using a secret-based authentication method.
                if (context.TokenEndpointAuthenticationMethod is ClientAuthenticationMethods.ClientSecretBasic or
                                                                 ClientAuthenticationMethods.ClientSecretPost)
                {
                    descriptor.ClientSecret = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(count: 256 / 8));
                }

                // Derive the permissions from the grant types, response types and scopes.
                descriptor.Permissions.Add(Permissions.Endpoints.Registration);

                foreach (var grant in context.GrantTypes)
                {
                    descriptor.Permissions.Add(Permissions.Prefixes.GrantType + grant);

                    switch (grant)
                    {
                        case GrantTypes.AuthorizationCode:
                            descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
                            descriptor.Permissions.Add(Permissions.Endpoints.EndSession);
                            descriptor.Permissions.Add(Permissions.Endpoints.PushedAuthorization);
                            descriptor.Permissions.Add(Permissions.Endpoints.Token);
                            break;

                        case GrantTypes.Implicit:
                            descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
                            descriptor.Permissions.Add(Permissions.Endpoints.EndSession);
                            descriptor.Permissions.Add(Permissions.Endpoints.PushedAuthorization);
                            break;

                        case GrantTypes.DeviceCode:
                            descriptor.Permissions.Add(Permissions.Endpoints.DeviceAuthorization);
                            descriptor.Permissions.Add(Permissions.Endpoints.Token);
                            break;

                        case GrantTypes.Ciba:
                            descriptor.Permissions.Add(Permissions.Endpoints.BackchannelAuthentication);
                            descriptor.Permissions.Add(Permissions.Endpoints.Token);
                            break;

                        default:
                            descriptor.Permissions.Add(Permissions.Endpoints.Token);
                            break;
                    }
                }

                if (descriptor.Permissions.Contains(Permissions.Endpoints.Token))
                {
                    descriptor.Permissions.Add(Permissions.Endpoints.Revocation);

                    if (descriptor.ClientType is ClientTypes.Confidential)
                    {
                        descriptor.Permissions.Add(Permissions.Endpoints.Introspection);
                    }
                }

                foreach (var type in context.ResponseTypes)
                {
                    descriptor.Permissions.Add(Permissions.Prefixes.ResponseType + type);
                }

                foreach (var scope in context.Scopes)
                {
                    // Note: the openid and offline_access scopes are protocol scopes that don't require permissions.
                    if (scope is not (Scopes.OpenId or Scopes.OfflineAccess))
                    {
                        descriptor.Permissions.Add(Permissions.Prefixes.Scope + scope);
                    }
                }

                // Map the features requested by the client application to requirements.
                if (IsTrue(ClientMetadata.RequirePushedAuthorizationRequests))
                {
                    descriptor.Requirements.Add(Requirements.Features.PushedAuthorizationRequests);
                }

                if (IsTrue(ClientMetadata.RequireSignedRequestObject))
                {
                    descriptor.Requirements.Add(Requirements.Features.SignedRequestObjects);
                }

                if (IsTrue(ClientMetadata.DPoPBoundAccessTokens))
                {
                    descriptor.Requirements.Add(Requirements.Features.DPoP);
                }

                // Store the logout and identity token settings.
                if (metadata.TryGetValue(ClientMetadata.BackchannelLogoutUri, out var uri))
                {
                    descriptor.Settings[Settings.Logout.BackchannelLogoutUri] = uri.GetString()!;
                    descriptor.Settings[Settings.Logout.BackchannelLogoutSessionRequired] =
                        IsTrue(ClientMetadata.BackchannelLogoutSessionRequired) ? "true" : "false";
                }

                if (metadata.TryGetValue(ClientMetadata.FrontchannelLogoutUri, out uri))
                {
                    descriptor.Settings[Settings.Logout.FrontchannelLogoutUri] = uri.GetString()!;
                    descriptor.Settings[Settings.Logout.FrontchannelLogoutSessionRequired] =
                        IsTrue(ClientMetadata.FrontchannelLogoutSessionRequired) ? "true" : "false";
                }

                if (metadata.TryGetValue(ClientMetadata.IdTokenSignedResponseAlg, out var algorithm))
                {
                    descriptor.Settings[Settings.Registration.IdentityTokenSigningAlgorithm] = algorithm.GetString()!;
                }

                // Store the accepted client metadata (including the default values applied by the server) so they can be
                // returned by the client configuration endpoint. Note: if a software statement was used, its value MUST be
                // returned unmodified in the client information response and is therefore stored with the other metadata.
                //
                // See https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1 for more information.
                var values = metadata.ToDictionary(static item => item.Key, static item => item.Value, StringComparer.Ordinal);

                values[ClientMetadata.GrantTypes] = CreateElement(writer => WriteStrings(writer, context.GrantTypes));
                values[ClientMetadata.ResponseTypes] = CreateElement(writer => WriteStrings(writer, context.ResponseTypes));
                values[ClientMetadata.TokenEndpointAuthMethod] = CreateElement(writer =>
                    writer.WriteStringValue(context.TokenEndpointAuthenticationMethod));

                descriptor.Properties[Properties.ClientMetadata] = SerializeMetadata(values);

                return descriptor;

                bool IsTrue(string name) => metadata.TryGetValue(name, out var value) && value.ValueKind is JsonValueKind.True;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the application and descriptor resolved during the validation phase.
        /// </summary>
        public sealed class AttachApplication : IOpenIddictServerHandler<HandleRegistrationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleRegistrationRequestContext>()
                    .UseSingletonHandler<AttachApplication>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleRegistrationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = context.Transaction.GetProperty<ValidateRegistrationRequestContext>(
                    typeof(ValidateRegistrationRequestContext).FullName!)
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

                context.Application ??= notification.Application;
                context.Descriptor = notification.Descriptor;

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for creating, reading, updating or deleting the client application
        /// and returning the corresponding client information response (RFC 7591, section 3.2.1 and RFC 7592,
        /// section 3) when a sign-in operation is triggered for a registration request.
        /// </summary>
        public sealed class ProcessRegistrationOperation : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ProcessRegistrationOperation(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireRegistrationRequest>()
                    .UseSingletonHandler<ProcessRegistrationOperation>()
                    // Note: this handler is deliberately executed before the default sign-in handlers,
                    // that are not used for registration requests (as no token is issued in this case).
                    .SetOrder(int.MinValue + 50_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessSignInContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var validation = context.Transaction.GetProperty<ValidateRegistrationRequestContext>(
                    typeof(ValidateRegistrationRequestContext).FullName!)
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

                var notification = context.Transaction.GetProperty<HandleRegistrationRequestContext>(
                    typeof(HandleRegistrationRequestContext).FullName!);

                var applications = context.ServiceProvider.GetService<IOpenIddictApplicationManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var tokens = context.ServiceProvider.GetService<IOpenIddictTokenManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var application = notification?.Application ?? validation.Application;
                var descriptor = notification?.Descriptor ?? validation.Descriptor;

                var response = new OpenIddictResponse();

                // Revoke the registration access token used to authenticate read and update requests before performing the
                // operation: since registration access tokens are not stored in plain text, a new token is issued for each
                // read or update operation (as allowed by RFC 7592, section 3). If the token was concurrently used by another
                // request (e.g a replayed stolen token), the revocation fails and the request is rejected, which ensures
                // that at most one new registration access token can be derived from a given token.
                if (validation.RegistrationAccessToken is not null &&
                    validation.RequestType is OpenIddictServerRegistrationRequestType.Read or
                                              OpenIddictServerRegistrationRequestType.Update &&
                    !await tokens.TryRevokeAsync(validation.RegistrationAccessToken, context.CancellationToken))
                {
                    context.Logger.LogInformation(6603, SR.GetResourceString(SR.ID6603));

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2400),
                        uri: SR.FormatID8000(SR.ID2400));

                    return;
                }

                try
                {
                    switch (validation.RequestType)
                    {
                        case OpenIddictServerRegistrationRequestType.Registration:
                        {
                            // Generate a unique client identifier, unless one was explicitly set by a custom handler.
                            if (string.IsNullOrEmpty(descriptor.ClientId))
                            {
                                descriptor.ClientId = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(count: 256 / 8));
                            }

                            var secret = descriptor.ClientSecret;

                            descriptor.Properties[Properties.ClientMetadata] = CreateMetadata(
                                descriptor, context.Options.TimeProvider.GetUtcNow());

                            application = await applications.CreateAsync(descriptor, context.CancellationToken);

                            await AttachResponseAsync(application, descriptor.ClientId, secret, descriptor.Properties[Properties.ClientMetadata]);

                            context.Logger.LogInformation(6604, SR.GetResourceString(SR.ID6604), descriptor.ClientId);
                            break;
                        }

                        case OpenIddictServerRegistrationRequestType.Read when application is not null:
                        {
                            var properties = await applications.GetPropertiesAsync(application, context.CancellationToken);

                            await AttachResponseAsync(application, await applications.GetClientIdAsync(application, context.CancellationToken),
                                secret: null, properties is not null && properties.TryGetValue(Properties.ClientMetadata, out var metadata) ? metadata : default);
                            break;
                        }

                        case OpenIddictServerRegistrationRequestType.Update when application is not null:
                        {
                            var existing = new OpenIddictApplicationDescriptor();
                            await applications.PopulateAsync(existing, application, context.CancellationToken);

                            // Note: the update operation uses full replace semantics, but the client identifier,
                            // the client issuance date and the consent type (not a client metadata) are preserved.
                            //
                            // See https://datatracker.ietf.org/doc/html/rfc7592#section-2.2 for more information.
                            descriptor.ClientId = existing.ClientId;
                            descriptor.ConsentType ??= existing.ConsentType;

                            // Preserve the existing client secret (that is never returned, as it is not stored in plain
                            // text) when the client still uses a secret-based authentication method. A new secret is
                            // only generated (and returned) when the client didn't have a secret before the update.
                            string? secret = null;

                            if (!string.IsNullOrEmpty(descriptor.ClientSecret))
                            {
                                if (!string.IsNullOrEmpty(existing.ClientSecret))
                                {
                                    descriptor.ClientSecret = existing.ClientSecret;
                                }

                                else
                                {
                                    secret = descriptor.ClientSecret;
                                }
                            }

                            descriptor.Properties[Properties.ClientMetadata] = CreateMetadata(descriptor,
                                GetIssuanceDate(existing) ?? context.Options.TimeProvider.GetUtcNow());

                            try
                            {
                                await applications.UpdateAsync(application, descriptor, context.CancellationToken);
                            }

                            catch (OpenIddictExceptions.ValidationException)
                            {
                                // If the update was rejected, restore the registration access token revoked
                                // before the operation to allow the client to send a corrected update request.
                                await RestoreRegistrationAccessTokenAsync();

                                throw;
                            }

                            await AttachResponseAsync(application, descriptor.ClientId, secret, descriptor.Properties[Properties.ClientMetadata]);

                            context.Logger.LogInformation(6605, SR.GetResourceString(SR.ID6605), descriptor.ClientId);
                            break;
                        }

                        case OpenIddictServerRegistrationRequestType.Deletion when application is not null:
                        {
                            var identifier = await applications.GetIdAsync(application, context.CancellationToken);
                            if (!string.IsNullOrEmpty(identifier))
                            {
                                await tokens.RevokeByApplicationIdAsync(identifier, context.CancellationToken);

                                if (context.ServiceProvider.GetService<IOpenIddictAuthorizationManager>() is IOpenIddictAuthorizationManager authorizations)
                                {
                                    await authorizations.RevokeByApplicationIdAsync(identifier, context.CancellationToken);
                                }
                            }

                            var client = await applications.GetClientIdAsync(application, context.CancellationToken);

                            await applications.DeleteAsync(application, context.CancellationToken);

                            context.Logger.LogInformation(6606, SR.GetResourceString(SR.ID6606), client);
                            break;
                        }

                        default: throw new InvalidOperationException(SR.GetResourceString(SR.ID0807));
                    }
                }

                catch (OpenIddictExceptions.ValidationException exception)
                {
                    context.Logger.LogInformation(6608, exception, SR.GetResourceString(SR.ID6608));

                    // Map errors affecting the redirect URIs to the dedicated invalid_redirect_uri error.
                    var redirect = exception.Results.Any(static result => result.ErrorMessage is string message &&
                        (string.Equals(message, SR.GetResourceString(SR.ID2061), StringComparison.Ordinal) ||
                         string.Equals(message, SR.GetResourceString(SR.ID2062), StringComparison.Ordinal) ||
                         string.Equals(message, SR.GetResourceString(SR.ID2115), StringComparison.Ordinal) ||
                         string.Equals(message, SR.FormatID2134(Parameters.Iss), StringComparison.Ordinal)));

                    context.Reject(
                        error: redirect ? Errors.InvalidRedirectUri : Errors.InvalidClientMetadata,
                        description: SR.GetResourceString(SR.ID2416),
                        uri: SR.FormatID8000(SR.ID2416));

                    return;
                }

                context.Transaction.Response = response;

                var @event = new ApplyRegistrationResponseContext(context.Transaction);
                await _dispatcher.DispatchAsync(@event);

                if (@event.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (@event.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0806));

                async ValueTask AttachResponseAsync(object application, string? client, string? secret, JsonElement metadata)
                {
                    var identifier = await applications.GetIdAsync(application, context.CancellationToken);

                    if (metadata.ValueKind is JsonValueKind.Object)
                    {
                        foreach (var property in metadata.EnumerateObject())
                        {
                            response.SetParameter(property.Name, new OpenIddictParameter(property.Value.Clone()));
                        }
                    }

                    // Attach the additional parameters specified by the application, if any.
                    if (notification is not null)
                    {
                        foreach (var parameter in notification.Parameters)
                        {
                            response.SetParameter(parameter.Key, parameter.Value);
                        }
                    }

                    response[ClientMetadata.ClientId] = client;

                    if (!string.IsNullOrEmpty(secret))
                    {
                        response[ClientMetadata.ClientSecret] = secret;
                    }

                    // Note: client secrets issued by the registration endpoint never expire.
                    if ((string?) response[ClientMetadata.TokenEndpointAuthMethod] is ClientAuthenticationMethods.ClientSecretBasic or
                                                                                       ClientAuthenticationMethods.ClientSecretPost)
                    {
                        response[ClientMetadata.ClientSecretExpiresAt] = 0;
                    }

                    var token = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(count: 256 / 8));
                    var date = context.Options.TimeProvider.GetUtcNow();

                    await tokens.CreateAsync(new OpenIddictTokenDescriptor
                    {
                        ApplicationId = identifier,
                        CreationDate = date,
                        ExpirationDate = context.Options.RegistrationAccessTokenLifetime is TimeSpan lifetime ? date + lifetime : null,
                        ReferenceId = token,
                        Status = Statuses.Valid,
                        Type = TokenTypeIdentifiers.Private.RegistrationAccessToken
                    }, context.CancellationToken);

                    response[ClientMetadata.RegistrationAccessToken] = token;

                    // Note: the registration endpoint is also used as the client configuration endpoint.
                    if (OpenIddictHelpers.CreateAbsoluteUri(context.BaseUri, context.Options.RegistrationEndpointUris.FirstOrDefault()) is Uri uri)
                    {
                        response[ClientMetadata.RegistrationClientUri] = OpenIddictHelpers.AddQueryStringParameter(
                            uri, Parameters.ClientId, client).AbsoluteUri;
                    }
                }

                async ValueTask RestoreRegistrationAccessTokenAsync()
                {
                    if (validation.RegistrationAccessToken is null)
                    {
                        return;
                    }

                    try
                    {
                        var descriptor = new OpenIddictTokenDescriptor();
                        await tokens.PopulateAsync(descriptor, validation.RegistrationAccessToken, context.CancellationToken);

                        descriptor.Status = Statuses.Valid;
                        await tokens.UpdateAsync(validation.RegistrationAccessToken, descriptor, context.CancellationToken);
                    }

                    catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                    {
                        // Note: failing to restore the token doesn't prevent the error from being returned.
                        context.Logger.LogWarning(6613, exception, SR.GetResourceString(SR.ID6613));
                    }
                }

                static DateTimeOffset? GetIssuanceDate(OpenIddictApplicationDescriptor descriptor)
                    => descriptor.Properties.TryGetValue(Properties.ClientMetadata, out var metadata) &&
                       metadata.ValueKind is JsonValueKind.Object &&
                       metadata.TryGetProperty(ClientMetadata.ClientIdIssuedAt, out var value) &&
                       value.TryGetInt64(out var seconds) ? DateTimeOffset.FromUnixTimeSeconds(seconds) : null;
            }

            /// <summary>
            /// Creates the client metadata stored with the application and returned in the client information response
            /// from the final application descriptor: since custom handlers can amend the descriptor after the metadata
            /// were validated, the values derived from the descriptor (e.g grant types resolved from the permissions)
            /// always take precedence, so that the client can determine which values were replaced by the server.
            /// </summary>
            /// <remarks>
            /// See https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1 for more information.
            /// </remarks>
            internal static JsonElement CreateMetadata(OpenIddictApplicationDescriptor descriptor, DateTimeOffset date)
            {
                var values = new Dictionary<string, JsonElement>(StringComparer.Ordinal);

                if (descriptor.Properties.TryGetValue(Properties.ClientMetadata, out var metadata) &&
                    metadata.ValueKind is JsonValueKind.Object)
                {
                    foreach (var property in metadata.EnumerateObject())
                    {
                        values[property.Name] = property.Value;
                    }
                }

                Set(ClientMetadata.ClientName, descriptor.DisplayName is { Length: > 0 } name
                    ? CreateElement(writer => writer.WriteStringValue(name)) : null);

                Set(ClientMetadata.RedirectUris, descriptor.RedirectUris.Count is > 0
                    ? CreateElement(writer => WriteStrings(writer, descriptor.RedirectUris.Select(static uri => uri.OriginalString))) : null);

                Set(ClientMetadata.PostLogoutRedirectUris, descriptor.PostLogoutRedirectUris.Count is > 0
                    ? CreateElement(writer => WriteStrings(writer, descriptor.PostLogoutRedirectUris.Select(static uri => uri.OriginalString))) : null);

                Set(ClientMetadata.GrantTypes, CreateElement(writer => WriteStrings(writer, GetPermissions(Permissions.Prefixes.GrantType))));
                Set(ClientMetadata.ResponseTypes, CreateElement(writer => WriteStrings(writer, GetPermissions(Permissions.Prefixes.ResponseType))));

                // Note: protocol scopes (openid and offline_access) are not represented as permissions
                // and are only returned if they were initially requested by the client application.
                var scopes = new List<string>();

                if (values.TryGetValue(ClientMetadata.Scope, out var scope) && scope.ValueKind is JsonValueKind.String)
                {
                    scopes.AddRange(scope.GetString()!.Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries)
                        .Where(name => name is Scopes.OpenId or Scopes.OfflineAccess ||
                            descriptor.Permissions.Contains(Permissions.Prefixes.Scope + name)));
                }

                scopes.AddRange(GetPermissions(Permissions.Prefixes.Scope).Where(name => !scopes.Contains(name, StringComparer.Ordinal)));

                Set(ClientMetadata.Scope, scopes.Count is > 0 ? CreateElement(writer => writer.WriteStringValue(string.Join(' ', scopes))) : null);

                // Public clients never authenticate at the token endpoint.
                if (descriptor.ClientType is ClientTypes.Public)
                {
                    Set(ClientMetadata.TokenEndpointAuthMethod, CreateElement(static writer =>
                        writer.WriteStringValue(ClientAuthenticationMethods.None)));
                }

                if (descriptor.JsonWebKeySet is null)
                {
                    Set(ClientMetadata.Jwks, null);
                }

                SetFeature(ClientMetadata.RequirePushedAuthorizationRequests, Requirements.Features.PushedAuthorizationRequests);
                SetFeature(ClientMetadata.RequireSignedRequestObject, Requirements.Features.SignedRequestObjects);
                SetFeature(ClientMetadata.DPoPBoundAccessTokens, Requirements.Features.DPoP);

                SetSetting(ClientMetadata.BackchannelLogoutUri, Settings.Logout.BackchannelUri, ClientMetadata.BackchannelLogoutSessionRequired);
                SetSetting(ClientMetadata.FrontchannelLogoutUri, Settings.Logout.FrontchannelUri, ClientMetadata.FrontchannelLogoutSessionRequired);
                SetSetting(ClientMetadata.IdTokenSignedResponseAlg, Settings.Registration.IdentityTokenSigningAlgorithm, dependent: null);

                Set(ClientMetadata.ClientIdIssuedAt, CreateElement(writer => writer.WriteNumberValue(date.ToUnixTimeSeconds())));

                return SerializeMetadata(values);

                IEnumerable<string> GetPermissions(string prefix) => descriptor.Permissions
                    .Where(permission => permission.StartsWith(prefix, StringComparison.Ordinal))
                    .Select(permission => permission[prefix.Length..]);

                void Set(string name, JsonElement? value)
                {
                    if (value is JsonElement element)
                    {
                        values[name] = element;
                    }

                    else
                    {
                        values.Remove(name);
                    }
                }

                void SetFeature(string name, string requirement)
                {
                    if (descriptor.Requirements.Contains(requirement))
                    {
                        Set(name, CreateElement(static writer => writer.WriteBooleanValue(true)));
                    }

                    else if (values.TryGetValue(name, out var value) && value.ValueKind is JsonValueKind.True)
                    {
                        Set(name, null);
                    }
                }

                void SetSetting(string name, string setting, string? dependent)
                {
                    if (descriptor.Settings.TryGetValue(setting, out var value) && !string.IsNullOrEmpty(value))
                    {
                        Set(name, CreateElement(writer => writer.WriteStringValue(value)));
                    }

                    else
                    {
                        Set(name, null);

                        if (!string.IsNullOrEmpty(dependent))
                        {
                            Set(dependent, null);
                        }
                    }
                }
            }
        }

        private static JsonElement SerializeMetadata(IEnumerable<KeyValuePair<string, JsonElement>> metadata)
            => CreateElement(writer =>
            {
                writer.WriteStartObject();

                foreach (var item in metadata)
                {
                    writer.WritePropertyName(item.Key);
                    item.Value.WriteTo(writer);
                }

                writer.WriteEndObject();
            });

        private static void WriteStrings(Utf8JsonWriter writer, IEnumerable<string> values)
        {
            writer.WriteStartArray();

            foreach (var value in values)
            {
                writer.WriteStringValue(value);
            }

            writer.WriteEndArray();
        }

        private static JsonElement CreateElement(Action<Utf8JsonWriter> action)
        {
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream))
            {
                action(writer);
            }

            using var document = JsonDocument.Parse(stream.ToArray());
            return document.RootElement.Clone();
        }
    }
}
