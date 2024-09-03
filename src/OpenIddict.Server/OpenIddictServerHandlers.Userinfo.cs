﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Claims;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Server;

public static partial class OpenIddictServerHandlers
{
    public static class UserInfo
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * UserInfo request top-level processing:
             */
            ExtractUserInfoRequest.Descriptor,
            ValidateUserInfoRequest.Descriptor,
            HandleUserInfoRequest.Descriptor,
            ApplyUserInfoResponse<ProcessChallengeContext>.Descriptor,
            ApplyUserInfoResponse<ProcessErrorContext>.Descriptor,
            ApplyUserInfoResponse<ProcessRequestContext>.Descriptor,

            /*
             * UserInfo request validation:
             */
            ValidateAccessTokenParameter.Descriptor,
            ValidateAuthentication.Descriptor,

            /*
             * UserInfo request handling:
             */
            AttachPrincipal.Descriptor,
            AttachAudiences.Descriptor,
            AttachClaims.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for extracting userinfo requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ExtractUserInfoRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ExtractUserInfoRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireUserInfoRequest>()
                    .UseScopedHandler<ExtractUserInfoRequest>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ExtractUserInfoRequestContext(context.Transaction);
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

                if (notification.Request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0053));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6129), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating userinfo requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ValidateUserInfoRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateUserInfoRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireUserInfoRequest>()
                    .UseScopedHandler<ValidateUserInfoRequest>()
                    .SetOrder(ExtractUserInfoRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ValidateUserInfoRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                // Store the context object in the transaction so it can be later retrieved by handlers
                // that want to access the principal without triggering a new validation process.
                context.Transaction.SetProperty(typeof(ValidateUserInfoRequestContext).FullName!, notification);

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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6130));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling userinfo requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class HandleUserInfoRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public HandleUserInfoRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireUserInfoRequest>()
                    .UseScopedHandler<HandleUserInfoRequest>()
                    .SetOrder(ValidateUserInfoRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new HandleUserInfoRequestContext(context.Transaction);
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

                var response = new OpenIddictResponse
                {
                    [Claims.Subject] = notification.Subject,
                    [Claims.Address] = notification.Address,
                    [Claims.Birthdate] = notification.BirthDate,
                    [Claims.Email] = notification.Email,
                    [Claims.EmailVerified] = notification.EmailVerified,
                    [Claims.FamilyName] = notification.FamilyName,
                    [Claims.GivenName] = notification.GivenName,
                    [Claims.Issuer] = notification.Issuer?.AbsoluteUri,
                    [Claims.PhoneNumber] = notification.PhoneNumber,
                    [Claims.PhoneNumberVerified] = notification.PhoneNumberVerified,
                    [Claims.PreferredUsername] = notification.PreferredUsername,
                    [Claims.Profile] = notification.Profile,
                    [Claims.Website] = notification.Website
                };

                switch (notification.Audiences.Count)
                {
                    case 0: break;

                    case 1:
                        response[Claims.Audience] = notification.Audiences.ElementAt(0);
                        break;

                    default:
                        response[Claims.Audience] = notification.Audiences.ToArray();
                        break;
                }

                foreach (var claim in notification.Claims)
                {
                    response.SetParameter(claim.Key, claim.Value);
                }

                context.Transaction.Response = response;
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing userinfo responses and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyUserInfoResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ApplyUserInfoResponse(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireUserInfoRequest>()
                    .UseScopedHandler<ApplyUserInfoResponse<TContext>>()
                    .SetOrder(500_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ApplyUserInfoResponseContext(context.Transaction);
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

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0054));
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting userinfo requests that don't specify an access token.
        /// </summary>
        public sealed class ValidateAccessTokenParameter : IOpenIddictServerHandler<ValidateUserInfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateUserInfoRequestContext>()
                    .UseSingletonHandler<ValidateAccessTokenParameter>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateUserInfoRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (string.IsNullOrEmpty(context.Request.AccessToken))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6131), Parameters.AccessToken);

                    context.Reject(
                        error: Errors.MissingToken,
                        description: SR.FormatID2029(Parameters.AccessToken),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for applying the authentication logic to userinfo requests.
        /// </summary>
        public sealed class ValidateAuthentication : IOpenIddictServerHandler<ValidateUserInfoRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateAuthentication(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateUserInfoRequestContext>()
                    .UseScopedHandler<ValidateAuthentication>()
                    .SetOrder(ValidateAccessTokenParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateUserInfoRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

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

                // Attach the security principal extracted from the token to the validation context.
                context.Principal = notification.AccessTokenPrincipal;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the principal
        /// extracted from the access token to the event context.
        /// </summary>
        public sealed class AttachPrincipal : IOpenIddictServerHandler<HandleUserInfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleUserInfoRequestContext>()
                    .UseSingletonHandler<AttachPrincipal>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleUserInfoRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = context.Transaction.GetProperty<ValidateUserInfoRequestContext>(
                    typeof(ValidateUserInfoRequestContext).FullName!) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

                Debug.Assert(notification.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                context.Principal ??= notification.Principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the audiences to the userinfo response.
        /// </summary>
        public sealed class AttachAudiences : IOpenIddictServerHandler<HandleUserInfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleUserInfoRequestContext>()
                    .UseSingletonHandler<AttachAudiences>()
                    .SetOrder(AttachPrincipal.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleUserInfoRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                // Note: when receiving an access token, its audiences list cannot be used for the "aud" claim
                // as the client application is not the intented audience but only an authorized presenter.
                // See http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
                context.Audiences.UnionWith(context.Principal.GetPresenters());

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching well known claims to the userinfo response.
        /// </summary>
        public sealed class AttachClaims : IOpenIddictServerHandler<HandleUserInfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleUserInfoRequestContext>()
                    .UseSingletonHandler<AttachClaims>()
                    .SetOrder(AttachAudiences.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleUserInfoRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                context.Issuer = context.Options.Issuer ?? context.BaseUri;
                context.Subject = context.Principal.GetClaim(Claims.Subject);

                // The following claims are all optional and should be excluded when
                // no corresponding value has been found in the authentication principal:

                if (context.Principal.HasScope(Scopes.Profile))
                {
                    context.FamilyName = context.Principal.GetClaim(Claims.FamilyName);
                    context.GivenName = context.Principal.GetClaim(Claims.GivenName);
                    context.BirthDate = context.Principal.GetClaim(Claims.Birthdate);
                }

                if (context.Principal.HasScope(Scopes.Email))
                {
                    context.Email = context.Principal.GetClaim(Claims.Email);
                }

                if (context.Principal.HasScope(Scopes.Phone))
                {
                    context.PhoneNumber = context.Principal.GetClaim(Claims.PhoneNumber);
                }

                return default;
            }
        }
    }
}
