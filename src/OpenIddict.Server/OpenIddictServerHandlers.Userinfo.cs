/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using Properties = OpenIddict.Server.OpenIddictServerConstants.Properties;

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
                private readonly IOpenIddictServerProvider _provider;

                public ExtractUserinfoRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<ExtractUserinfoRequest>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Userinfo)
                    {
                        return;
                    }

                    var notification = new ExtractUserinfoRequestContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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

                    if (notification.Request == null)
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .Append("The userinfo request was not correctly extracted. To extract userinfo requests, ")
                            .Append("create a class implementing 'IOpenIddictServerHandler<ExtractUserinfoRequestContext>' ")
                            .AppendLine("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                            .ToString());
                    }

                    context.Logger.LogInformation("The userinfo request was successfully extracted: {Request}.", notification.Request);
                }
            }

            /// <summary>
            /// Contains the logic responsible of validating userinfo requests and invoking the corresponding event handlers.
            /// </summary>
            public class ValidateUserinfoRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public ValidateUserinfoRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<ValidateUserinfoRequest>()
                        .SetOrder(ExtractUserinfoRequest.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Userinfo)
                    {
                        return;
                    }

                    var notification = new ValidateUserinfoRequestContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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

                    // Store the security principal extracted from the authorization code/refresh token as an environment property.
                    context.Transaction.Properties[Properties.AmbientPrincipal] = notification.Principal;

                    context.Logger.LogInformation("The userinfo request was successfully validated.");
                }
            }

            /// <summary>
            /// Contains the logic responsible of handling userinfo requests and invoking the corresponding event handlers.
            /// </summary>
            public class HandleUserinfoRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public HandleUserinfoRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<HandleUserinfoRequest>()
                        .SetOrder(ValidateUserinfoRequest.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Userinfo)
                    {
                        return;
                    }

                    var notification = new HandleUserinfoRequestContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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
                            response[Claims.Audience] = new JArray(notification.Audiences);
                            break;
                    }

                    foreach (var claim in notification.Claims)
                    {
                        response.SetParameter(claim.Key, claim.Value);
                    }

                    context.Response = response;
                }
            }

            /// <summary>
            /// Contains the logic responsible of processing userinfo responses and invoking the corresponding event handlers.
            /// </summary>
            public class ApplyUserinfoResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
            {
                private readonly IOpenIddictServerProvider _provider;

                public ApplyUserinfoResponse([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                        .UseScopedHandler<ApplyUserinfoResponse<TContext>>()
                        .SetOrder(int.MaxValue - 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] TContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Userinfo)
                    {
                        return;
                    }

                    var notification = new ApplyUserinfoResponseContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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

                    throw new InvalidOperationException(new StringBuilder()
                        .Append("The userinfo response was not correctly applied. To apply userinfo response, ")
                        .Append("create a class implementing 'IOpenIddictServerHandler<ApplyUserinfoResponseContext>' ")
                        .AppendLine("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                        .ToString());
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
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] ValidateUserinfoRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (string.IsNullOrEmpty(context.Request.AccessToken))
                    {
                        context.Logger.LogError("The userinfo request was rejected because the access token was missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'access_token' parameter is missing.");

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
                private readonly IOpenIddictServerProvider _provider;

                public ValidateToken([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateUserinfoRequestContext>()
                        .UseScopedHandler<ValidateToken>()
                        .SetOrder(ValidateAccessTokenParameter.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ValidateUserinfoRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var notification = new ProcessAuthenticationContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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

                    // Attach the security principal extracted from the token to the
                    // validation context and store it as an environment property.
                    context.Principal = notification.Principal;
                    context.Transaction.Properties[Properties.AmbientPrincipal] = notification.Principal;
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
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleUserinfoRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.Transaction.Properties.TryGetValue(Properties.AmbientPrincipal, out var principal))
                    {
                        context.Principal ??= (ClaimsPrincipal) principal;
                    }

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
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleUserinfoRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

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
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleUserinfoRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

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
