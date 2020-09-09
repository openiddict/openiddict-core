/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server
{
    public static partial class OpenIddictServerHandlers
    {
        public static class Userinfo
        {
            public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Userinfo request top-level processing:
                 */
                ExtractUserinfoRequest.Descriptor,
                ValidateUserinfoRequest.Descriptor,
                HandleUserinfoRequest.Descriptor,
                ApplyUserinfoResponse<ProcessChallengeContext>.Descriptor,
                ApplyUserinfoResponse<ProcessErrorContext>.Descriptor,
                ApplyUserinfoResponse<ProcessRequestContext>.Descriptor,

                /*
                 * Userinfo request validation:
                 */
                ValidateAccessTokenParameter.Descriptor,
                ValidateToken.Descriptor,

                /*
                 * Userinfo request handling:
                 */
                AttachPrincipal.Descriptor,
                AttachAudiences.Descriptor,
                AttachClaims.Descriptor);

            /// <summary>
            /// Contains the logic responsible of extracting userinfo requests and invoking the corresponding event handlers.
            /// </summary>
            public class ExtractUserinfoRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ExtractUserinfoRequest(IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .AddFilter<RequireUserinfoRequest>()
                        .UseScopedHandler<ExtractUserinfoRequest>()
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

                    var notification = new ExtractUserinfoRequestContext(context.Transaction);
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
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1052));
                    }

                    context.Logger.LogInformation(SR.GetResourceString(SR.ID7129), notification.Request);
                }
            }

            /// <summary>
            /// Contains the logic responsible of validating userinfo requests and invoking the corresponding event handlers.
            /// </summary>
            public class ValidateUserinfoRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ValidateUserinfoRequest(IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .AddFilter<RequireUserinfoRequest>()
                        .UseScopedHandler<ValidateUserinfoRequest>()
                        .SetOrder(ExtractUserinfoRequest.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ProcessRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new ValidateUserinfoRequestContext(context.Transaction);
                    await _dispatcher.DispatchAsync(notification);

                    // Store the context object in the transaction so it can be later retrieved by handlers
                    // that want to access the principal without triggering a new validation process.
                    context.Transaction.SetProperty(typeof(ValidateUserinfoRequestContext).FullName!, notification);

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

                    context.Logger.LogInformation(SR.GetResourceString(SR.ID7130));
                }
            }

            /// <summary>
            /// Contains the logic responsible of handling userinfo requests and invoking the corresponding event handlers.
            /// </summary>
            public class HandleUserinfoRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public HandleUserinfoRequest(IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .AddFilter<RequireUserinfoRequest>()
                        .UseScopedHandler<HandleUserinfoRequest>()
                        .SetOrder(ValidateUserinfoRequest.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ProcessRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new HandleUserinfoRequestContext(context.Transaction);
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
            /// Contains the logic responsible of processing userinfo responses and invoking the corresponding event handlers.
            /// </summary>
            public class ApplyUserinfoResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ApplyUserinfoResponse(IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                        .AddFilter<RequireUserinfoRequest>()
                        .UseScopedHandler<ApplyUserinfoResponse<TContext>>()
                        .SetOrder(int.MaxValue - 100_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(TContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new ApplyUserinfoResponseContext(context.Transaction);
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

                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1053));
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting userinfo requests that don't specify an access token.
            /// </summary>
            public class ValidateAccessTokenParameter : IOpenIddictServerHandler<ValidateUserinfoRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateUserinfoRequestContext>()
                        .UseSingletonHandler<ValidateAccessTokenParameter>()
                        .SetOrder(int.MinValue + 100_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(ValidateUserinfoRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (string.IsNullOrEmpty(context.Request.AccessToken))
                    {
                        context.Logger.LogError(SR.GetResourceString(SR.ID7131), Parameters.AccessToken);

                        context.Reject(
                            error: Errors.MissingToken,
                            description: context.Localizer[SR.ID3029, Parameters.AccessToken]);

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of rejecting userinfo requests that don't specify a valid token.
            /// </summary>
            public class ValidateToken : IOpenIddictServerHandler<ValidateUserinfoRequestContext>
            {
                private readonly IOpenIddictServerDispatcher _dispatcher;

                public ValidateToken(IOpenIddictServerDispatcher dispatcher)
                    => _dispatcher = dispatcher;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateUserinfoRequestContext>()
                        .UseScopedHandler<ValidateToken>()
                        .SetOrder(ValidateAccessTokenParameter.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public async ValueTask HandleAsync(ValidateUserinfoRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new ProcessAuthenticationContext(context.Transaction);
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

                    // Attach the security principal extracted from the token to the validation context.
                    context.Principal = notification.Principal;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the principal
            /// extracted from the access token to the event context.
            /// </summary>
            public class AttachPrincipal : IOpenIddictServerHandler<HandleUserinfoRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleUserinfoRequestContext>()
                        .UseSingletonHandler<AttachPrincipal>()
                        .SetOrder(int.MinValue + 100_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(HandleUserinfoRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = context.Transaction.GetProperty<ValidateUserinfoRequestContext>(
                        typeof(ValidateUserinfoRequestContext).FullName!) ??
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1006));

                    context.Principal ??= notification.Principal;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the audiences to the userinfo response.
            /// </summary>
            public class AttachAudiences : IOpenIddictServerHandler<HandleUserinfoRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleUserinfoRequestContext>()
                        .UseSingletonHandler<AttachAudiences>()
                        .SetOrder(AttachPrincipal.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(HandleUserinfoRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(context.Principal is not null, SR.GetResourceString(SR.ID5006));

                    // Note: when receiving an access token, its audiences list cannot be used for the "aud" claim
                    // as the client application is not the intented audience but only an authorized presenter.
                    // See http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
                    context.Audiences.UnionWith(context.Principal.GetPresenters());

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching well known claims to the userinfo response.
            /// </summary>
            public class AttachClaims : IOpenIddictServerHandler<HandleUserinfoRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleUserinfoRequestContext>()
                        .UseSingletonHandler<AttachClaims>()
                        .SetOrder(AttachAudiences.Descriptor.Order + 1_000)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(HandleUserinfoRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    Debug.Assert(context.Principal is not null, SR.GetResourceString(SR.ID5006));

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
}
