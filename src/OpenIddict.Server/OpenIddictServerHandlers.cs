/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Extensions;

namespace OpenIddict.Server;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictServerHandlers
{
    public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
        /*
         * Authentication processing:
         */
        ValidateAuthenticationDemand.Descriptor,
        EvaluateValidatedTokens.Descriptor,
        ResolveValidatedTokens.Descriptor,
        ValidateRequiredTokens.Descriptor,
        ValidateAccessToken.Descriptor,
        ValidateAuthorizationCode.Descriptor,
        ValidateDeviceCode.Descriptor,
        ValidateGenericToken.Descriptor,
        ValidateIdentityToken.Descriptor,
        ValidateRefreshToken.Descriptor,
        ValidateUserCode.Descriptor,

        /*
         * Challenge processing:
         */
        ValidateChallengeDemand.Descriptor,
        AttachDefaultChallengeError.Descriptor,
        RejectDeviceCodeEntry.Descriptor,
        RejectUserCodeEntry.Descriptor,
        AttachCustomChallengeParameters.Descriptor,

        /*
        * Sign-in processing:
        */
        ValidateSignInDemand.Descriptor,
        RedeemTokenEntry.Descriptor,
        RestoreInternalClaims.Descriptor,
        AttachHostProperties.Descriptor,
        AttachDefaultScopes.Descriptor,
        AttachDefaultPresenters.Descriptor,
        InferResources.Descriptor,
        EvaluateGeneratedTokens.Descriptor,
        AttachAuthorization.Descriptor,

        PrepareAccessTokenPrincipal.Descriptor,
        PrepareAuthorizationCodePrincipal.Descriptor,
        PrepareDeviceCodePrincipal.Descriptor,
        PrepareRefreshTokenPrincipal.Descriptor,
        PrepareIdentityTokenPrincipal.Descriptor,
        PrepareUserCodePrincipal.Descriptor,

        GenerateAccessToken.Descriptor,
        GenerateAuthorizationCode.Descriptor,
        GenerateDeviceCode.Descriptor,
        GenerateRefreshToken.Descriptor,

        AttachDeviceCodeIdentifier.Descriptor,
        UpdateReferenceDeviceCodeEntry.Descriptor,
        AttachTokenDigests.Descriptor,

        GenerateUserCode.Descriptor,
        GenerateIdentityToken.Descriptor,

        AttachSignInParameters.Descriptor,
        AttachCustomSignInParameters.Descriptor,

        /*
         * Sign-out processing:
         */
        ValidateSignOutDemand.Descriptor,
        AttachCustomSignOutParameters.Descriptor,
        
        /*
         * Error processing:
         */
        AttachErrorParameters.Descriptor,
        AttachCustomErrorParameters.Descriptor)

        .AddRange(Authentication.DefaultHandlers)
        .AddRange(Device.DefaultHandlers)
        .AddRange(Discovery.DefaultHandlers)
        .AddRange(Exchange.DefaultHandlers)
        .AddRange(Introspection.DefaultHandlers)
        .AddRange(Protection.DefaultHandlers)
        .AddRange(Revocation.DefaultHandlers)
        .AddRange(Session.DefaultHandlers)
        .AddRange(Userinfo.DefaultHandlers);

    /// <summary>
    /// Contains the logic responsible for rejecting authentication demands made from unsupported endpoints.
    /// </summary>
    public sealed class ValidateAuthenticationDemand : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ValidateAuthenticationDemand>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            switch (context.EndpointType)
            {
                case OpenIddictServerEndpointType.Authorization:
                case OpenIddictServerEndpointType.Introspection:
                case OpenIddictServerEndpointType.Logout:
                case OpenIddictServerEndpointType.Revocation:
                case OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType():
                case OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType():
                case OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType():
                case OpenIddictServerEndpointType.Userinfo:
                case OpenIddictServerEndpointType.Verification:
                    return default;

                case OpenIddictServerEndpointType.Token:
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0001));

                default: throw new InvalidOperationException(SR.GetResourceString(SR.ID0002));
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for selecting the token types that should be validated.
    /// </summary>
    public sealed class EvaluateValidatedTokens : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<EvaluateValidatedTokens>()
                .SetOrder(ValidateAuthenticationDemand.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
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
             context.ValidateAccessToken) = context.EndpointType switch
            {
                // The userinfo endpoint requires sending a valid access token.
                OpenIddictServerEndpointType.Userinfo => (true, true, true),

                _ => (false, false, false)
            };

            (context.ExtractAuthorizationCode,
             context.RequireAuthorizationCode,
             context.ValidateAuthorizationCode) = context.EndpointType switch
            {
                // The authorization code grant requires sending a valid authorization code.
                OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                    => (true, true, true),

                _ => (false, false, false)
            };

            (context.ExtractDeviceCode,
             context.RequireDeviceCode,
             context.ValidateDeviceCode) = context.EndpointType switch
            {
                // The device code grant requires sending a valid device code.
                OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                    => (true, true, true),

                _ => (false, false, false)
            };

            (context.ExtractGenericToken,
             context.RequireGenericToken,
             context.ValidateGenericToken) = context.EndpointType switch
            {
                // Tokens received by the introspection and revocation endpoints can be of any type.
                // Additional token type filtering is made by the endpoint themselves, if needed.
                OpenIddictServerEndpointType.Introspection or OpenIddictServerEndpointType.Revocation
                    => (true, true, true),

                _ => (false, false, false)
            };

            (context.ExtractIdentityToken,
             context.RequireIdentityToken,
             context.ValidateIdentityToken) = context.EndpointType switch
            {
                // The identity token received by the authorization and logout
                // endpoints are not required and serve as optional hints.
                OpenIddictServerEndpointType.Authorization or OpenIddictServerEndpointType.Logout
                    => (true, false, true),

                _ => (false, false, true)
            };

            (context.ExtractRefreshToken,
             context.RequireRefreshToken,
             context.ValidateRefreshToken) = context.EndpointType switch
            {
                // The refresh token grant requires sending a valid refresh token.
                OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                    => (true, true, true),

                _ => (false, false, false)
            };

            (context.ExtractUserCode,
             context.RequireUserCode,
             context.ValidateUserCode) = context.EndpointType switch
            {
                // Note: the verification endpoint can be accessed without specifying a
                // user code (that can be later set by the user using a form, for instance).
                OpenIddictServerEndpointType.Verification => (true, false, true),

                _ => (false, false, false)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the token from the incoming request.
    /// </summary>
    public sealed class ResolveValidatedTokens : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ResolveValidatedTokens>()
                .SetOrder(EvaluateValidatedTokens.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.AccessToken = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Userinfo when context.ExtractAccessToken
                    => context.Request.AccessToken,

                _ => null
            };

            context.AuthorizationCode = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Token when context.ExtractAuthorizationCode
                    => context.Request.Code,

                _ => null
            };

            context.DeviceCode = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Token when context.ExtractDeviceCode
                    => context.Request.DeviceCode,

                _ => null
            };

            (context.GenericToken, context.GenericTokenTypeHint) = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Introspection or
                OpenIddictServerEndpointType.Revocation when context.ExtractGenericToken
                    => (context.Request.Token, context.Request.TokenTypeHint),

                _ => (null, null)
            };

            context.IdentityToken = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization or
                OpenIddictServerEndpointType.Logout when context.ExtractIdentityToken
                    => context.Request.IdTokenHint,

                _ => null
            };

            context.RefreshToken = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Token when context.ExtractRefreshToken
                    => context.Request.RefreshToken,

                _ => null
            };

            context.UserCode = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Verification when context.ExtractUserCode
                    => context.Request.UserCode,

                _ => null
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting authentication demands that lack required tokens.
    /// </summary>
    public sealed class ValidateRequiredTokens : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<EvaluateValidatedTokens>()
                // Note: this handler is registered with a high gap to allow handlers
                // that do token extraction to be executed before this handler runs.
                .SetOrder(EvaluateValidatedTokens.Descriptor.Order + 50_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if ((context.RequireAccessToken       && string.IsNullOrEmpty(context.AccessToken))       ||
                (context.RequireAuthorizationCode && string.IsNullOrEmpty(context.AuthorizationCode)) ||
                (context.RequireDeviceCode        && string.IsNullOrEmpty(context.DeviceCode))        ||
                (context.RequireGenericToken      && string.IsNullOrEmpty(context.GenericToken))      ||
                (context.RequireIdentityToken     && string.IsNullOrEmpty(context.IdentityToken))     ||
                (context.RequireRefreshToken      && string.IsNullOrEmpty(context.RefreshToken))      ||
                (context.RequireUserCode          && string.IsNullOrEmpty(context.UserCode)))
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
    /// Contains the logic responsible for validating the access token resolved from the context.
    /// </summary>
    public sealed class ValidateAccessToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateAccessToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAccessTokenValidated>()
                .UseScopedHandler<ValidateAccessToken>()
                .SetOrder(ValidateRequiredTokens.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.AccessTokenPrincipal is not null || string.IsNullOrEmpty(context.AccessToken))
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
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.AccessTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the authorization code resolved from the context.
    /// </summary>
    public sealed class ValidateAuthorizationCode : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateAuthorizationCode(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthorizationCodeValidated>()
                .UseScopedHandler<ValidateAuthorizationCode>()
                .SetOrder(ValidateAccessToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.AuthorizationCodePrincipal is not null || string.IsNullOrEmpty(context.AuthorizationCode))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.AuthorizationCode,
                ValidTokenTypes = { TokenTypeHints.AuthorizationCode }
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

            context.AuthorizationCodePrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the device code resolved from the context.
    /// </summary>
    public sealed class ValidateDeviceCode : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateDeviceCode(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireDeviceCodeValidated>()
                .UseScopedHandler<ValidateDeviceCode>()
                .SetOrder(ValidateAuthorizationCode.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.DeviceCodePrincipal is not null || string.IsNullOrEmpty(context.DeviceCode))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.DeviceCode,
                ValidTokenTypes = { TokenTypeHints.DeviceCode }
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

            context.DeviceCodePrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating tokens of unknown types resolved from the context.
    /// </summary>
    public sealed class ValidateGenericToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateGenericToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireGenericTokenValidated>()
                .UseScopedHandler<ValidateGenericToken>()
                .SetOrder(ValidateDeviceCode.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.GenericTokenPrincipal is not null || string.IsNullOrEmpty(context.GenericToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.GenericToken,
                TokenTypeHint = context.GenericTokenTypeHint,

                // By default, only access tokens and refresh tokens can be introspected/revoked but
                // tokens received by the introspection and revocation endpoints can be of any type.
                //
                // Additional token type filtering is made by the endpoint themselves, if needed.
                // As such, the valid token types list is deliberately left empty in this case.
                ValidTokenTypes = { }
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

            context.GenericTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the identity token resolved from the context.
    /// </summary>
    public sealed class ValidateIdentityToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateIdentityToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireIdentityTokenValidated>()
                .UseScopedHandler<ValidateIdentityToken>()
                .SetOrder(ValidateGenericToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.IdentityTokenPrincipal is not null || string.IsNullOrEmpty(context.IdentityToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                // Don't validate the lifetime of id_tokens used as id_token_hints.
                DisableLifetimeValidation = context.EndpointType is OpenIddictServerEndpointType.Authorization or
                                                                    OpenIddictServerEndpointType.Logout,
                Token = context.IdentityToken,
                ValidTokenTypes = { TokenTypeHints.IdToken }
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

            context.IdentityTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the refresh token resolved from the context.
    /// </summary>
    public sealed class ValidateRefreshToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateRefreshToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRefreshTokenValidated>()
                .UseScopedHandler<ValidateRefreshToken>()
                .SetOrder(ValidateIdentityToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.RefreshTokenPrincipal is not null || string.IsNullOrEmpty(context.RefreshToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.RefreshToken,
                ValidTokenTypes = { TokenTypeHints.RefreshToken }
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

            context.RefreshTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the user code resolved from the context.
    /// </summary>
    public sealed class ValidateUserCode : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateUserCode(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireUserCodeValidated>()
                .UseScopedHandler<ValidateUserCode>()
                .SetOrder(ValidateRefreshToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.UserCodePrincipal is not null || string.IsNullOrEmpty(context.UserCode))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.UserCode,
                ValidTokenTypes = { TokenTypeHints.UserCode }
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

            context.UserCodePrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting challenge demands made from unsupported endpoints.
    /// </summary>
    public sealed class ValidateChallengeDemand : IOpenIddictServerHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<ValidateChallengeDemand>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.EndpointType is not (OpenIddictServerEndpointType.Authorization or
                                             OpenIddictServerEndpointType.Token         or
                                             OpenIddictServerEndpointType.Userinfo      or
                                             OpenIddictServerEndpointType.Verification))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0006));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for ensuring that the challenge response contains an appropriate error.
    /// </summary>
    public sealed class AttachDefaultChallengeError : IOpenIddictServerHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<AttachDefaultChallengeError>()
                .SetOrder(ValidateChallengeDemand.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.Response.Error ??= context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization or OpenIddictServerEndpointType.Verification
                    => Errors.AccessDenied,

                OpenIddictServerEndpointType.Token    => Errors.InvalidGrant,
                OpenIddictServerEndpointType.Userinfo => Errors.InsufficientAccess,

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0006))
            };

            context.Response.ErrorDescription ??= context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization or OpenIddictServerEndpointType.Verification
                    => SR.GetResourceString(SR.ID2015),

                OpenIddictServerEndpointType.Token    => SR.GetResourceString(SR.ID2024),
                OpenIddictServerEndpointType.Userinfo => SR.GetResourceString(SR.ID2025),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0006))
            };

            context.Response.ErrorUri ??= context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization or OpenIddictServerEndpointType.Verification
                    => SR.FormatID8000(SR.ID2015),

                OpenIddictServerEndpointType.Token    => SR.FormatID8000(SR.ID2024),
                OpenIddictServerEndpointType.Userinfo => SR.FormatID8000(SR.ID2025),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0006))
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting the device code entry associated with the user code.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class RejectDeviceCodeEntry : IOpenIddictServerHandler<ProcessChallengeContext>
    {
        private readonly IOpenIddictTokenManager _tokenManager;

        public RejectDeviceCodeEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        public RejectDeviceCodeEntry(IOpenIddictTokenManager tokenManager)
            => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireDegradedModeDisabled>()
                .AddFilter<RequireTokenStorageEnabled>()
                .UseScopedHandler<RejectDeviceCodeEntry>()
                .SetOrder(AttachDefaultChallengeError.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.EndpointType is not OpenIddictServerEndpointType.Verification)
            {
                return;
            }

            var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                typeof(ProcessAuthenticationContext).FullName!) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

            Debug.Assert(notification.UserCodePrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Extract the device code identifier from the user code principal.
            var identifier = notification.UserCodePrincipal.GetClaim(Claims.Private.DeviceCodeId);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0008));
            }

            var token = await _tokenManager.FindByIdAsync(identifier);
            if (token is not null)
            {
                await _tokenManager.TryRejectAsync(token);
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting the user code entry, if applicable.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class RejectUserCodeEntry : IOpenIddictServerHandler<ProcessChallengeContext>
    {
        private readonly IOpenIddictTokenManager _tokenManager;

        public RejectUserCodeEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        public RejectUserCodeEntry(IOpenIddictTokenManager tokenManager)
            => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireDegradedModeDisabled>()
                .AddFilter<RequireTokenStorageEnabled>()
                .UseScopedHandler<RejectUserCodeEntry>()
                .SetOrder(RejectDeviceCodeEntry.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.EndpointType is not OpenIddictServerEndpointType.Verification)
            {
                return;
            }

            var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                typeof(ProcessAuthenticationContext).FullName!) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

            Debug.Assert(notification.UserCodePrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Extract the device code identifier from the authentication principal.
            var identifier = notification.UserCodePrincipal.GetTokenId();
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0009));
            }

            var token = await _tokenManager.FindByIdAsync(identifier);
            if (token is not null)
            {
                await _tokenManager.TryRejectAsync(token);
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the parameters
    /// populated from user-defined handlers to the challenge response.
    /// </summary>
    public sealed class AttachCustomChallengeParameters : IOpenIddictServerHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<AttachCustomChallengeParameters>()
                .SetOrder(100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
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
    /// Contains the logic responsible for ensuring that the sign-in demand
    /// is compatible with the type of the endpoint that handled the request.
    /// </summary>
    public sealed class ValidateSignInDemand : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<ValidateSignInDemand>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.EndpointType is not (OpenIddictServerEndpointType.Authorization or
                                             OpenIddictServerEndpointType.Device        or
                                             OpenIddictServerEndpointType.Token         or
                                             OpenIddictServerEndpointType.Verification))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0010));
            }

            if (context.Principal is not { Identity: ClaimsIdentity })
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0011));
            }

            // Note: sign-in operations triggered from the device endpoint can't be associated to specific users
            // as users' identity is not known until they reach the verification endpoint and validate the user code.
            // As such, the principal used in this case cannot contain an authenticated identity or a subject claim.
            if (context.EndpointType is OpenIddictServerEndpointType.Device)
            {
                if (context.Principal.Identity.IsAuthenticated)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0012));
                }

                if (!string.IsNullOrEmpty(context.Principal.GetClaim(Claims.Subject)))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0013));
                }
            }

            else
            {
                if (!context.Principal.Identity.IsAuthenticated)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0014));
                }

                if (string.IsNullOrEmpty(context.Principal.GetClaim(Claims.Subject)))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0015));
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for redeeming the token entry corresponding to
    /// the received authorization code, device code, user code or refresh token.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class RedeemTokenEntry : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictTokenManager _tokenManager;

        public RedeemTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        public RedeemTokenEntry(IOpenIddictTokenManager tokenManager)
            => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireDegradedModeDisabled>()
                .AddFilter<RequireTokenStorageEnabled>()
                .UseScopedHandler<RedeemTokenEntry>()
                // Note: this handler is deliberately executed early in the pipeline to ensure
                // that the token database entry is always marked as redeemed even if the sign-in
                // demand is rejected later in the pipeline (e.g because an error was returned).
                .SetOrder(ValidateSignInDemand.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            switch (context.EndpointType)
            {
                case OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType():
                case OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType():
                case OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType() &&
                                                            !context.Options.DisableRollingRefreshTokens:
                case OpenIddictServerEndpointType.Verification:
                    break;

                default: return;
            }

            var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                typeof(ProcessAuthenticationContext).FullName!) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

            var principal = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                    => notification.AuthorizationCodePrincipal,

                OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                    => notification.DeviceCodePrincipal,

                OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                    => notification.RefreshTokenPrincipal,

                OpenIddictServerEndpointType.Verification => notification.UserCodePrincipal,

                _ => null
            };

            Debug.Assert(principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Extract the token identifier from the authentication principal.
            // If no token identifier can be found, this indicates that the token has no backing database entry.
            var identifier = principal.GetTokenId();
            if (string.IsNullOrEmpty(identifier))
            {
                return;
            }

            var token = await _tokenManager.FindByIdAsync(identifier);
            if (token is null)
            {
                return;
            }

            // Mark the token as redeemed to prevent future reuses. If the request is a refresh token request, ignore
            // errors returned while trying to mark the entry as redeemed (that may be caused by concurrent requests).
            if (context.EndpointType is OpenIddictServerEndpointType.Token && context.Request.IsRefreshTokenGrantType())
            {
                await _tokenManager.TryRedeemAsync(token);
            }

            else if (!await _tokenManager.TryRedeemAsync(token))
            {
                context.Reject(
                    error: Errors.InvalidToken,
                    description: principal.GetTokenType() switch
                    {
                        TokenTypeHints.AuthorizationCode => SR.GetResourceString(SR.ID2010),
                        TokenTypeHints.DeviceCode        => SR.GetResourceString(SR.ID2011),
                        TokenTypeHints.RefreshToken      => SR.GetResourceString(SR.ID2012),

                        _ => SR.GetResourceString(SR.ID2013)
                    },
                    uri: principal.GetTokenType() switch
                    {
                        TokenTypeHints.AuthorizationCode => SR.FormatID8000(SR.ID2010),
                        TokenTypeHints.DeviceCode        => SR.FormatID8000(SR.ID2011),
                        TokenTypeHints.RefreshToken      => SR.FormatID8000(SR.ID2012),

                        _ => SR.FormatID8000(SR.ID2013)
                    });

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for re-attaching internal claims to the authentication principal.
    /// </summary>
    public sealed class RestoreInternalClaims : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<RestoreInternalClaims>()
                .SetOrder(RedeemTokenEntry.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            switch (context.EndpointType)
            {
                case OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType():
                case OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType():
                case OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType():
                case OpenIddictServerEndpointType.Verification:
                    break;

                default: return default;
            }

            var identity = (ClaimsIdentity) context.Principal.Identity;

            var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                typeof(ProcessAuthenticationContext).FullName!) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

            var principal = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                    => notification.AuthorizationCodePrincipal,

                OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                    => notification.DeviceCodePrincipal,

                OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                    => notification.RefreshTokenPrincipal,

                OpenIddictServerEndpointType.Verification => notification.UserCodePrincipal,

                _ => null
            };

            if (principal is null)
            {
                return default;
            }

            // Restore the internal claims resolved from the token.
            foreach (var claims in principal.Claims
                .Where(claim => claim.Type.StartsWith(Claims.Prefixes.Private, StringComparison.OrdinalIgnoreCase))
                .GroupBy(claim => claim.Type))
            {
                // If the specified principal already contains one claim of the iterated type, ignore them.
                if (context.Principal.Claims.Any(claim => claim.Type == claims.Key))
                {
                    continue;
                }

                // When the request is a verification request, don't flow the scopes from the user code.
                if (context.EndpointType is OpenIddictServerEndpointType.Verification &&
                    string.Equals(claims.Key, Claims.Private.Scope, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                identity.AddClaims(claims);
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the user-defined properties to the authentication principal.
    /// </summary>
    public sealed class AttachHostProperties : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<AttachHostProperties>()
                .SetOrder(RestoreInternalClaims.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            context.Principal.SetClaim(Claims.Private.HostProperties, context.Properties);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching default scopes to the authentication principal.
    /// </summary>
    public sealed class AttachDefaultScopes : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<AttachDefaultScopes>()
                .SetOrder(AttachHostProperties.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Always include the "openid" scope when the developer doesn't explicitly call SetScopes.
            // Note: the application is allowed to specify a different "scopes": in this case,
            // don't replace the "scopes" property stored in the authentication ticket.
            if (!context.Principal.HasClaim(Claims.Private.Scope) && context.Request.HasScope(Scopes.OpenId))
            {
                context.Principal.SetScopes(Scopes.OpenId);
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching default presenters to the authentication principal.
    /// </summary>
    public sealed class AttachDefaultPresenters : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<AttachDefaultPresenters>()
                .SetOrder(AttachDefaultScopes.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Add the validated client_id to the list of authorized presenters,
            // unless the presenters were explicitly set by the developer.
            if (!context.Principal.HasClaim(Claims.Private.Presenter) && !string.IsNullOrEmpty(context.ClientId))
            {
                context.Principal.SetPresenters(context.ClientId);
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for inferring resources from the audience claims if necessary.
    /// </summary>
    public sealed class InferResources : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<InferResources>()
                .SetOrder(AttachDefaultPresenters.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // When a "resources" property cannot be found in the ticket, infer it from the "audiences" property.
            if (context.Principal.HasClaim(Claims.Private.Audience) &&
               !context.Principal.HasClaim(Claims.Private.Resource))
            {
                context.Principal.SetResources(context.Principal.GetAudiences());
            }

            // Reset the audiences collection, as it's later set, based on the token type.
            context.Principal.SetAudiences(ImmutableArray.Create<string>());

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for selecting the token types that
    /// should be generated and optionally returned in the response.
    /// </summary>
    public sealed class EvaluateGeneratedTokens : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<EvaluateGeneratedTokens>()
                .SetOrder(InferResources.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            (context.GenerateAccessToken, context.IncludeAccessToken) = context.EndpointType switch
            {
                // For authorization requests, generate and return an access token
                // if a response type containing the "token" value was specified.
                OpenIddictServerEndpointType.Authorization when context.Request.HasResponseType(ResponseTypes.Token)
                    => (true, true),

                // For token requests, always generate and return an access token.
                OpenIddictServerEndpointType.Token => (true, true),

                _ => (false, false)
            };

            (context.GenerateAuthorizationCode, context.IncludeAuthorizationCode) = context.EndpointType switch
            {
                // For authorization requests, generate and return an authorization code
                // if a response type containing the "code" value was specified.
                OpenIddictServerEndpointType.Authorization when context.Request.HasResponseType(ResponseTypes.Code)
                    => (true, true),

                _ => (false, false)
            };

            (context.GenerateDeviceCode, context.IncludeDeviceCode) = context.EndpointType switch
            {
                // For device requests, always generate and return a device code.
                OpenIddictServerEndpointType.Device => (true, true),

                // Note: a device code is not directly returned by the verification endpoint (that generally
                // returns an empty response or redirects the user agent to another page), but a device code
                // must be generated to replace the payload of the device code initially returned to the client.
                // In this case, the device code is not returned as part of the response but persisted in the DB.
                OpenIddictServerEndpointType.Verification => (true, false),

                _ => (false, false)
            };

            (context.GenerateIdentityToken, context.IncludeIdentityToken) = context.EndpointType switch
            {
                // For authorization requests, generate and return an identity token if a response type
                // containing code was specified and if the openid scope was explicitly or implicitly granted.
                OpenIddictServerEndpointType.Authorization when
                    context.Principal.HasScope(Scopes.OpenId) &&
                    context.Request.HasResponseType(ResponseTypes.IdToken) => (true, true),

                // For token requests, only generate and return an identity token if the openid scope was granted.
                OpenIddictServerEndpointType.Token when context.Principal.HasScope(Scopes.OpenId) => (true, true),

                _ => (false, false)
            };

            (context.GenerateRefreshToken, context.IncludeRefreshToken) = context.EndpointType switch
            {
                // For token requests, allow a refresh token to be returned
                // if the special offline_access protocol scope was granted.
                OpenIddictServerEndpointType.Token when context.Principal.HasScope(Scopes.OfflineAccess)
                    => (true, true),

                _ => (false, false)
            };

            (context.GenerateUserCode, context.IncludeUserCode) = context.EndpointType switch
            {
                // Only generate and return a user code if the request is a device authorization request.
                OpenIddictServerEndpointType.Device => (true, true),

                _ => (false, false)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for creating an ad-hoc authorization, if necessary.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class AttachAuthorization : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;

        public AttachAuthorization() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        public AttachAuthorization(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager)
        {
            _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));
            _authorizationManager = authorizationManager ?? throw new ArgumentNullException(nameof(authorizationManager));
        }

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireDegradedModeDisabled>()
                .AddFilter<RequireAuthorizationStorageEnabled>()
                .UseScopedHandler<AttachAuthorization>()
                .SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // If no authorization code, device code or refresh token is returned, don't create an authorization.
            if (!context.GenerateAuthorizationCode && !context.GenerateDeviceCode && !context.GenerateRefreshToken)
            {
                return;
            }

            // If an authorization identifier was explicitly specified, don't create an ad-hoc authorization.
            if (!string.IsNullOrEmpty(context.Principal.GetAuthorizationId()))
            {
                return;
            }

            var descriptor = new OpenIddictAuthorizationDescriptor
            {
                CreationDate = DateTimeOffset.UtcNow,
                Principal = context.Principal,
                Status = Statuses.Valid,
                Subject = context.Principal.GetClaim(Claims.Subject),
                Type = AuthorizationTypes.AdHoc
            };

            descriptor.Scopes.UnionWith(context.Principal.GetScopes());

            // If the client application is known, associate it to the authorization.
            if (!string.IsNullOrEmpty(context.Request.ClientId))
            {
                var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0017));

                descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
            }

            var authorization = await _authorizationManager.CreateAsync(descriptor) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0018));

            var identifier = await _authorizationManager.GetIdAsync(authorization);

            if (string.IsNullOrEmpty(context.Request.ClientId))
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6007), identifier);
            }

            else
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6008), context.Request.ClientId, identifier);
            }

            // Attach the unique identifier of the ad hoc authorization to the authentication principal
            // so that it is attached to all the derived tokens, allowing batched revocations support.
            context.Principal.SetAuthorizationId(identifier);
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the access token, if one is going to be returned.
    /// </summary>
    public sealed class PrepareAccessTokenPrincipal : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireAccessTokenGenerated>()
                .UseSingletonHandler<PrepareAccessTokenPrincipal>()
                .SetOrder(AttachAuthorization.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            var principal = context.Principal.Clone(claim =>
            {
                // Never exclude the subject and authorization identifier claims.
                if (string.Equals(claim.Type, Claims.Subject, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.AuthorizationId, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                // Never exclude the presenters and scope private claims.
                if (string.Equals(claim.Type, Claims.Private.Presenter, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.Scope, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                // Never include the public or internal token identifiers to ensure the identifiers
                // that are automatically inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Never include the creation and expiration dates that are automatically
                // inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Always exclude private claims, whose values must generally be kept secret.
                if (claim.Type.StartsWith(Claims.Prefixes.Private, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Claims whose destination is not explicitly referenced or doesn't
                // contain "access_token" are not included in the access token.
                if (!claim.HasDestination(Destinations.AccessToken))
                {
                    context.Logger.LogDebug(SR.GetResourceString(SR.ID6009), claim.Type);

                    return false;
                }

                return true;
            });

            // Remove the destinations from the claim properties.
            foreach (var claim in principal.Claims)
            {
                claim.Properties.Remove(Properties.Destinations);
            }

            principal.SetCreationDate(DateTimeOffset.UtcNow);

            var lifetime = context.Principal.GetAccessTokenLifetime() ?? context.Options.AccessTokenLifetime;
            if (lifetime.HasValue)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Use the server identity as the token issuer.
            principal.SetClaim(Claims.Private.Issuer, context.Issuer?.AbsoluteUri);

            // Set the audiences based on the resource claims stored in the principal.
            principal.SetAudiences(context.Principal.GetResources());

            // Store the client identifier in the public client_id claim, if available.
            // See https://datatracker.ietf.org/doc/html/rfc9068 for more information.
            principal.SetClaim(Claims.ClientId, context.ClientId);

            // When receiving a grant_type=refresh_token request, determine whether the client application
            // requests a limited set of scopes and immediately replace the scopes collection if necessary.
            if (context.EndpointType is OpenIddictServerEndpointType.Token &&
                context.Request.IsRefreshTokenGrantType() && !string.IsNullOrEmpty(context.Request.Scope))
            {
                var scopes = context.Request.GetScopes();
                principal.SetScopes(scopes.Intersect(context.Principal.GetScopes()));

                context.Logger.LogDebug(SR.GetResourceString(SR.ID6010), scopes);
            }

            context.AccessTokenPrincipal = principal;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the authorization code, if one is going to be returned.
    /// </summary>
    public sealed class PrepareAuthorizationCodePrincipal : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireAuthorizationCodeGenerated>()
                .UseSingletonHandler<PrepareAuthorizationCodePrincipal>()
                .SetOrder(PrepareAccessTokenPrincipal.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            var principal = context.Principal.Clone(claim =>
            {
                // Never include the public or internal token identifiers to ensure the identifiers
                // that are automatically inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Never include the creation and expiration dates that are automatically
                // inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Other claims are always included in the authorization code, even private claims.
                return true;
            });

            principal.SetCreationDate(DateTimeOffset.UtcNow);

            var lifetime = context.Principal.GetAuthorizationCodeLifetime() ?? context.Options.AuthorizationCodeLifetime;
            if (lifetime.HasValue)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Use the server identity as the token issuer.
            principal.SetClaim(Claims.Private.Issuer, context.Issuer?.AbsoluteUri);

            // Attach the redirect_uri to allow for later comparison when
            // receiving a grant_type=authorization_code token request.
            principal.SetClaim(Claims.Private.RedirectUri, context.Request.RedirectUri);

            // Attach the code challenge and the code challenge methods to allow the ValidateCodeVerifier
            // handler to validate the code verifier sent by the client as part of the token request.
            if (!string.IsNullOrEmpty(context.Request.CodeChallenge))
            {
                principal.SetClaim(Claims.Private.CodeChallenge, context.Request.CodeChallenge);

                // Default to plain if no explicit code challenge method was specified.
                principal.SetClaim(Claims.Private.CodeChallengeMethod,
                    !string.IsNullOrEmpty(context.Request.CodeChallengeMethod) ?
                    context.Request.CodeChallengeMethod : CodeChallengeMethods.Plain);
            }

            // Attach the nonce so that it can be later returned by
            // the token endpoint as part of the JWT identity token.
            principal.SetClaim(Claims.Private.Nonce, context.Request.Nonce);

            context.AuthorizationCodePrincipal = principal;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the device code, if one is going to be returned.
    /// </summary>
    public sealed class PrepareDeviceCodePrincipal : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireDeviceCodeGenerated>()
                .UseSingletonHandler<PrepareDeviceCodePrincipal>()
                .SetOrder(PrepareAuthorizationCodePrincipal.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            var principal = context.Principal.Clone(claim =>
            {
                // Never include the public or internal token identifiers to ensure the identifiers
                // that are automatically inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Never include the creation and expiration dates that are automatically
                // inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Other claims are always included in the device code, even private claims.
                return true;
            });

            principal.SetCreationDate(DateTimeOffset.UtcNow);

            var lifetime = context.Principal.GetDeviceCodeLifetime() ?? context.Options.DeviceCodeLifetime;
            if (lifetime.HasValue)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Use the server identity as the token issuer.
            principal.SetClaim(Claims.Private.Issuer, context.Issuer?.AbsoluteUri);

            // Restore the device code internal token identifier from the principal
            // resolved from the user code used in the user code verification request.
            if (context.EndpointType is OpenIddictServerEndpointType.Verification)
            {
                principal.SetClaim(Claims.Private.TokenId, context.Principal.GetClaim(Claims.Private.DeviceCodeId));
            }

            context.DeviceCodePrincipal = principal;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the refresh token, if one is going to be returned.
    /// </summary>
    public sealed class PrepareRefreshTokenPrincipal : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireRefreshTokenGenerated>()
                .UseSingletonHandler<PrepareRefreshTokenPrincipal>()
                .SetOrder(PrepareDeviceCodePrincipal.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            var principal = context.Principal.Clone(claim =>
            {
                // Never include the public or internal token identifiers to ensure the identifiers
                // that are automatically inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Never include the creation and expiration dates that are automatically
                // inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Other claims are always included in the refresh token, even private claims.
                return true;
            });

            principal.SetCreationDate(DateTimeOffset.UtcNow);

            // When sliding expiration is disabled, the expiration date of generated refresh tokens is fixed
            // and must exactly match the expiration date of the refresh token used in the token request.
            if (context.EndpointType is OpenIddictServerEndpointType.Token &&
                context.Request.IsRefreshTokenGrantType() &&
                context.Options.DisableSlidingRefreshTokenExpiration)
            {
                var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                    typeof(ProcessAuthenticationContext).FullName!) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

                Debug.Assert(notification.RefreshTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                principal.SetExpirationDate(notification.RefreshTokenPrincipal.GetExpirationDate());
            }

            else
            {
                var lifetime = context.Principal.GetRefreshTokenLifetime() ?? context.Options.RefreshTokenLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }
            }

            // Use the server identity as the token issuer.
            principal.SetClaim(Claims.Private.Issuer, context.Issuer?.AbsoluteUri);

            context.RefreshTokenPrincipal = principal;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the identity token, if one is going to be returned.
    /// </summary>
    public sealed class PrepareIdentityTokenPrincipal : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireIdentityTokenGenerated>()
                .UseSingletonHandler<PrepareIdentityTokenPrincipal>()
                .SetOrder(PrepareRefreshTokenPrincipal.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Replace the principal by a new one containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            var principal = context.Principal.Clone(claim =>
            {
                // Never exclude the subject and authorization identifier claims.
                if (string.Equals(claim.Type, Claims.Subject, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.AuthorizationId, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                // Never include the public or internal token identifiers to ensure the identifiers
                // that are automatically inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Never include the creation and expiration dates that are automatically
                // inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Always exclude private claims by default, whose values must generally be kept secret.
                if (claim.Type.StartsWith(Claims.Prefixes.Private, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Claims whose destination is not explicitly referenced or doesn't
                // contain "id_token" are not included in the identity token.
                if (!claim.HasDestination(Destinations.IdentityToken))
                {
                    context.Logger.LogDebug(SR.GetResourceString(SR.ID6011), claim.Type);

                    return false;
                }

                return true;
            });

            // Remove the destinations from the claim properties.
            foreach (var claim in principal.Claims)
            {
                claim.Properties.Remove(Properties.Destinations);
            }

            principal.SetCreationDate(DateTimeOffset.UtcNow);

            var lifetime = context.Principal.GetIdentityTokenLifetime() ?? context.Options.IdentityTokenLifetime;
            if (lifetime.HasValue)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Use the server identity as the token issuer.
            principal.SetClaim(Claims.Private.Issuer, context.Issuer?.AbsoluteUri);

            // If available, use the client_id as both the audience and the authorized party.
            // See https://openid.net/specs/openid-connect-core-1_0.html#IDToken for more information.
            if (!string.IsNullOrEmpty(context.ClientId))
            {
                principal.SetAudiences(context.ClientId);
                principal.SetClaim(Claims.AuthorizedParty, context.ClientId);
            }

            // If a nonce was present in the authorization request, it MUST be included in the id_token generated
            // by the token endpoint. For that, OpenIddict simply flows the nonce as an authorization code claim.
            // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation for more information.
            principal.SetClaim(Claims.Nonce, context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization => context.Request.Nonce,
                OpenIddictServerEndpointType.Token         => context.Principal.GetClaim(Claims.Private.Nonce),

                _ => null
            });

            context.IdentityTokenPrincipal = principal;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the user code, if one is going to be returned.
    /// </summary>
    public sealed class PrepareUserCodePrincipal : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireUserCodeGenerated>()
                .UseSingletonHandler<PrepareUserCodePrincipal>()
                .SetOrder(PrepareIdentityTokenPrincipal.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            var principal = context.Principal.Clone(claim =>
            {
                // Never include the public or internal token identifiers to ensure the identifiers
                // that are automatically inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Never include the creation and expiration dates that are automatically
                // inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Other claims are always included in the authorization code, even private claims.
                return true;
            });

            principal.SetCreationDate(DateTimeOffset.UtcNow);

            var lifetime = context.Principal.GetUserCodeLifetime() ?? context.Options.UserCodeLifetime;
            if (lifetime.HasValue)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Use the server identity as the token issuer.
            principal.SetClaim(Claims.Private.Issuer, context.Issuer?.AbsoluteUri);

            // Store the client_id as a public client_id claim.
            principal.SetClaim(Claims.ClientId, context.Request.ClientId);

            context.UserCodePrincipal = principal;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating an access token for the current sign-in operation.
    /// </summary>
    public sealed class GenerateAccessToken : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public GenerateAccessToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireAccessTokenGenerated>()
                .UseScopedHandler<GenerateAccessToken>()
                .SetOrder(100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                ClientId = context.ClientId,
                CreateTokenEntry = !context.Options.DisableTokenStorage,
                // Access tokens can be converted to reference tokens if the
                // corresponding option was enabled in the server options.
                PersistTokenPayload = context.Options.UseReferenceAccessTokens,
                Principal = context.AccessTokenPrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.AccessToken
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

            context.AccessToken = notification.Token;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating an authorization code for the current sign-in operation.
    /// </summary>
    public sealed class GenerateAuthorizationCode : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public GenerateAuthorizationCode(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireAuthorizationCodeGenerated>()
                .UseScopedHandler<GenerateAuthorizationCode>()
                .SetOrder(GenerateAccessToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                ClientId = context.ClientId,
                CreateTokenEntry = !context.Options.DisableTokenStorage,
                PersistTokenPayload = !context.Options.DisableTokenStorage,
                Principal = context.AuthorizationCodePrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.AuthorizationCode
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

            context.AuthorizationCode = notification.Token;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating a device code for the current sign-in operation.
    /// </summary>
    public sealed class GenerateDeviceCode : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public GenerateDeviceCode(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireDeviceCodeGenerated>()
                .UseScopedHandler<GenerateDeviceCode>()
                .SetOrder(GenerateAuthorizationCode.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                ClientId = context.ClientId,
                CreateTokenEntry = !context.Options.DisableTokenStorage,
                // Device codes can be converted to reference tokens if they are not generated
                // as part of a device code swap made by the user code verification endpoint.
                PersistTokenPayload = context.EndpointType switch
                {
                    OpenIddictServerEndpointType.Verification => false,

                    _ => !context.Options.DisableTokenStorage
                },
                Principal = context.DeviceCodePrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.DeviceCode
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

            context.DeviceCode = notification.Token;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating a refresh token for the current sign-in operation.
    /// </summary>
    public sealed class GenerateRefreshToken : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public GenerateRefreshToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireRefreshTokenGenerated>()
                .UseScopedHandler<GenerateRefreshToken>()
                .SetOrder(GenerateDeviceCode.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                ClientId = context.ClientId,
                CreateTokenEntry = !context.Options.DisableTokenStorage,
                // Refresh tokens can be converted to reference tokens if the
                // corresponding option was enabled in the server options.
                PersistTokenPayload = context.Options.UseReferenceRefreshTokens,
                Principal = context.RefreshTokenPrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.RefreshToken
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

            context.RefreshToken = notification.Token;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating and attaching the device code identifier to the user code principal.
    /// </summary>
    public sealed class AttachDeviceCodeIdentifier : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireDeviceCodeGenerated>()
                .AddFilter<RequireUserCodeGenerated>()
                .UseSingletonHandler<AttachDeviceCodeIdentifier>()
                .SetOrder(GenerateRefreshToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.UserCodePrincipal is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0020));
            }

            var identifier = context.DeviceCodePrincipal?.GetTokenId();
            if (!string.IsNullOrEmpty(identifier))
            {
                context.UserCodePrincipal.SetClaim(Claims.Private.DeviceCodeId, identifier);
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for updating the existing reference device code entry.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class UpdateReferenceDeviceCodeEntry : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictTokenManager _tokenManager;

        public UpdateReferenceDeviceCodeEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        public UpdateReferenceDeviceCodeEntry(IOpenIddictTokenManager tokenManager)
            => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireDegradedModeDisabled>()
                .AddFilter<RequireTokenStorageEnabled>()
                .AddFilter<RequireDeviceCodeGenerated>()
                .UseScopedHandler<UpdateReferenceDeviceCodeEntry>()
                .SetOrder(AttachDeviceCodeIdentifier.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.EndpointType is not OpenIddictServerEndpointType.Verification || string.IsNullOrEmpty(context.DeviceCode))
            {
                return;
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            if (context.DeviceCodePrincipal is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0020));
            }

            // Extract the token identifier from the authentication principal.
            var identifier = context.Principal.GetClaim(Claims.Private.DeviceCodeId);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0008));
            }

            var token = await _tokenManager.FindByIdAsync(identifier) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0265));

            // Replace the device code details by the payload derived from the new device code principal,
            // that includes all the user claims populated by the application after authenticating the user.
            var descriptor = new OpenIddictTokenDescriptor();
            await _tokenManager.PopulateAsync(descriptor, token);

            // Note: the lifetime is deliberately extended to give more time to the client to redeem the code.
            descriptor.ExpirationDate = context.DeviceCodePrincipal.GetExpirationDate();
            descriptor.Payload = context.DeviceCode;
            descriptor.Principal = context.DeviceCodePrincipal;
            descriptor.Status = Statuses.Valid;
            descriptor.Subject = context.DeviceCodePrincipal.GetClaim(Claims.Subject);

            await _tokenManager.UpdateAsync(token, descriptor);

            context.Logger.LogTrace(SR.GetResourceString(SR.ID6021), await _tokenManager.GetIdAsync(token));
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating and attaching the hashes of
    /// the access token and authorization code to the identity token principal.
    /// </summary>
    public sealed class AttachTokenDigests : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireIdentityTokenGenerated>()
                .UseSingletonHandler<AttachTokenDigests>()
                .SetOrder(UpdateReferenceDeviceCodeEntry.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.IdentityTokenPrincipal is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0022));
            }

            if (string.IsNullOrEmpty(context.AccessToken) && string.IsNullOrEmpty(context.AuthorizationCode))
            {
                return default;
            }

            var credentials = context.Options.SigningCredentials.Find(
                credentials => credentials.Key is AsymmetricSecurityKey) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0266));

            if (!string.IsNullOrEmpty(context.AccessToken))
            {
                var digest = ComputeTokenHash(credentials, context.AccessToken);

                // Note: only the left-most half of the hash is used.
                // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
                context.IdentityTokenPrincipal.SetClaim(Claims.AccessTokenHash, Base64UrlEncoder.Encode(digest, 0, digest.Length / 2));
            }

            if (!string.IsNullOrEmpty(context.AuthorizationCode))
            {
                var digest = ComputeTokenHash(credentials, context.AuthorizationCode);

                // Note: only the left-most half of the hash is used.
                // See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
                context.IdentityTokenPrincipal.SetClaim(Claims.CodeHash, Base64UrlEncoder.Encode(digest, 0, digest.Length / 2));
            }

            return default;

            static byte[] ComputeTokenHash(SigningCredentials credentials, string token) => credentials switch
            {
                // Note: ASCII is deliberately used here, as it's the encoding required by the specification.
                // For more information, see https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken.

                { Digest:    SecurityAlgorithms.Sha256          or SecurityAlgorithms.Sha256Digest             } or
                { Algorithm: SecurityAlgorithms.EcdsaSha256     or SecurityAlgorithms.EcdsaSha256Signature     } or
                { Algorithm: SecurityAlgorithms.HmacSha256      or SecurityAlgorithms.HmacSha256Signature      } or
                { Algorithm: SecurityAlgorithms.RsaSha256       or SecurityAlgorithms.RsaSha256Signature       } or
                { Algorithm: SecurityAlgorithms.RsaSsaPssSha256 or SecurityAlgorithms.RsaSsaPssSha256Signature }
                    => OpenIddictHelpers.ComputeSha256Hash(Encoding.ASCII.GetBytes(token)),

                { Digest:    SecurityAlgorithms.Sha384          or SecurityAlgorithms.Sha384Digest             } or
                { Algorithm: SecurityAlgorithms.EcdsaSha384     or SecurityAlgorithms.EcdsaSha384Signature     } or
                { Algorithm: SecurityAlgorithms.HmacSha384      or SecurityAlgorithms.HmacSha384Signature      } or
                { Algorithm: SecurityAlgorithms.RsaSha384       or SecurityAlgorithms.RsaSha384Signature       } or
                { Algorithm: SecurityAlgorithms.RsaSsaPssSha384 or SecurityAlgorithms.RsaSsaPssSha384Signature }
                    => OpenIddictHelpers.ComputeSha384Hash(Encoding.ASCII.GetBytes(token)),

                { Digest:    SecurityAlgorithms.Sha512          or SecurityAlgorithms.Sha512Digest             } or
                { Algorithm: SecurityAlgorithms.EcdsaSha512     or SecurityAlgorithms.EcdsaSha512Signature     } or
                { Algorithm: SecurityAlgorithms.HmacSha512      or SecurityAlgorithms.HmacSha512Signature      } or
                { Algorithm: SecurityAlgorithms.RsaSha512       or SecurityAlgorithms.RsaSha512Signature       } or
                { Algorithm: SecurityAlgorithms.RsaSsaPssSha512 or SecurityAlgorithms.RsaSsaPssSha512Signature }
                    => OpenIddictHelpers.ComputeSha512Hash(Encoding.ASCII.GetBytes(token)),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0267))
            };
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating a user code for the current sign-in operation.
    /// </summary>
    public sealed class GenerateUserCode : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public GenerateUserCode(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireUserCodeGenerated>()
                .UseScopedHandler<GenerateUserCode>()
                .SetOrder(AttachTokenDigests.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                ClientId = context.ClientId,
                CreateTokenEntry = !context.Options.DisableTokenStorage,
                PersistTokenPayload = !context.Options.DisableTokenStorage,
                Principal = context.UserCodePrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.UserCode
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

            context.UserCode = notification.Token;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating an identity token for the current sign-in operation.
    /// </summary>
    public sealed class GenerateIdentityToken : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public GenerateIdentityToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireIdentityTokenGenerated>()
                .UseScopedHandler<GenerateIdentityToken>()
                .SetOrder(GenerateUserCode.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                ClientId = context.ClientId,
                CreateTokenEntry = !context.Options.DisableTokenStorage,
                // Identity tokens cannot never be reference tokens.
                PersistTokenPayload = false,
                Principal = context.IdentityTokenPrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.IdToken
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

            context.IdentityToken = notification.Token;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the appropriate parameters to the sign-in response.
    /// </summary>
    public sealed class AttachSignInParameters : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<AttachSignInParameters>()
                .SetOrder(GenerateIdentityToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.IncludeAccessToken)
            {
                context.Response.AccessToken = context.AccessToken;
                context.Response.TokenType = TokenTypes.Bearer;

                // If the principal is available, attach additional metadata.
                if (context.AccessTokenPrincipal is not null)
                {
                    // If an expiration date was set on the access token principal, return it to the client application.
                    var date = context.AccessTokenPrincipal.GetExpirationDate();
                    if (date.HasValue && date.Value > DateTimeOffset.UtcNow)
                    {
                        context.Response.ExpiresIn = (long) ((date.Value - DateTimeOffset.UtcNow).TotalSeconds + .5);
                    }

                    // If the granted access token scopes differ from the requested scopes, return the granted scopes
                    // list as a parameter to inform the client application of the fact the scopes set will be reduced.
                    var scopes = context.AccessTokenPrincipal.GetScopes().ToHashSet(StringComparer.Ordinal);
                    if ((context.EndpointType is OpenIddictServerEndpointType.Token && context.Request.IsAuthorizationCodeGrantType()) ||
                        !scopes.SetEquals(context.Request.GetScopes()))
                    {
                        context.Response.Scope = string.Join(" ", scopes);
                    }
                }
            }

            if (context.IncludeAuthorizationCode)
            {
                context.Response.Code = context.AuthorizationCode;
            }

            if (context.IncludeDeviceCode)
            {
                context.Response.DeviceCode = context.DeviceCode;

                // If the principal is available, attach additional metadata.
                if (context.DeviceCodePrincipal is not null)
                {
                    // If an expiration date was set on the device code principal, return it to the client application.
                    var date = context.DeviceCodePrincipal.GetExpirationDate();
                    if (date.HasValue && date.Value > DateTimeOffset.UtcNow)
                    {
                        context.Response.ExpiresIn = (long) ((date.Value - DateTimeOffset.UtcNow).TotalSeconds + .5);
                    }
                }
            }

            if (context.IncludeIdentityToken)
            {
                context.Response.IdToken = context.IdentityToken;
            }

            if (context.IncludeRefreshToken)
            {
                context.Response.RefreshToken = context.RefreshToken;
            }

            if (context.IncludeUserCode)
            {
                context.Response.UserCode = context.UserCode;

                var address = GetEndpointAbsoluteUri(context.Issuer, context.Options.VerificationEndpointUris.FirstOrDefault());
                if (address is not null)
                {
                    var builder = new UriBuilder(address)
                    {
                        Query = string.Concat(Parameters.UserCode, "=", context.UserCode)
                    };

                    context.Response[Parameters.VerificationUri] = address.AbsoluteUri;
                    context.Response[Parameters.VerificationUriComplete] = builder.Uri.AbsoluteUri;
                }
            }

            return default;

            static Uri? GetEndpointAbsoluteUri(Uri? issuer, Uri? endpoint)
            {
                // If the endpoint is disabled (i.e a null address is specified), return null.
                if (endpoint is null)
                {
                    return null;
                }

                // If the endpoint address is already an absolute URL, return it as-is.
                if (endpoint.IsAbsoluteUri)
                {
                    return endpoint;
                }

                // At this stage, throw an exception if the issuer cannot be retrieved.
                if (issuer is not { IsAbsoluteUri: true })
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0023));
                }

                // Ensure the issuer ends with a trailing slash, as it is necessary
                // for Uri's constructor to correctly compute correct absolute URLs.
                if (!issuer.OriginalString.EndsWith("/", StringComparison.Ordinal))
                {
                    issuer = new Uri(issuer.OriginalString + "/", UriKind.Absolute);
                }

                // Ensure the endpoint does not start with a leading slash, as it is necessary
                // for Uri's constructor to correctly compute correct absolute URLs.
                if (endpoint.OriginalString.StartsWith("/", StringComparison.Ordinal))
                {
                    endpoint = new Uri(endpoint.OriginalString[1..], UriKind.Relative);
                }

                return new Uri(issuer, endpoint);
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the parameters
    /// populated from user-defined handlers to the sign-in response.
    /// </summary>
    public sealed class AttachCustomSignInParameters : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<AttachCustomSignInParameters>()
                .SetOrder(100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
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
    /// Contains the logic responsible for ensuring that the sign-out demand
    /// is compatible with the type of the endpoint that handled the request.
    /// </summary>
    public sealed class ValidateSignOutDemand : IOpenIddictServerHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .UseSingletonHandler<ValidateSignOutDemand>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.EndpointType is not OpenIddictServerEndpointType.Logout)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0024));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the parameters
    /// populated from user-defined handlers to the sign-out response.
    /// </summary>
    public sealed class AttachCustomSignOutParameters : IOpenIddictServerHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .UseSingletonHandler<AttachCustomSignOutParameters>()
                .SetOrder(100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
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
    public sealed class AttachErrorParameters : IOpenIddictServerHandler<ProcessErrorContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessErrorContext>()
                .UseSingletonHandler<AttachErrorParameters>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
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
    public sealed class AttachCustomErrorParameters : IOpenIddictServerHandler<ProcessErrorContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessErrorContext>()
                .UseSingletonHandler<AttachCustomErrorParameters>()
                .SetOrder(100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
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
