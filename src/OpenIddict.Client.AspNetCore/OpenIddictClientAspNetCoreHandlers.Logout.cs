/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Text.Json;
using Microsoft.AspNetCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace OpenIddict.Client.AspNetCore;

public static partial class OpenIddictClientAspNetCoreHandlers
{
    public static class Logout
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Back-channel logout request extraction:
             */
            ExtractPostRequest<ExtractBackchannelLogoutRequestContext>.Descriptor,

            /*
             * Back-channel logout request handling:
             */
            EnablePassthroughMode<HandleBackchannelLogoutRequestContext, RequireBackchannelLogoutEndpointPassthroughEnabled>.Descriptor,

            /*
             * Back-channel logout response handling:
             */
            AttachHttpResponseCode<ApplyBackchannelLogoutResponseContext>.Descriptor,
            AttachCacheControlHeader<ApplyBackchannelLogoutResponseContext>.Descriptor,
            ProcessJsonErrorResponse<ApplyBackchannelLogoutResponseContext>.Descriptor,
            ProcessEmptyResponse<ApplyBackchannelLogoutResponseContext>.Descriptor,

            /*
             * Front-channel logout request extraction:
             */
            ExtractGetOrPostRequest<ExtractFrontchannelLogoutRequestContext>.Descriptor,

            /*
             * Front-channel logout request handling:
             */
            EnablePassthroughMode<HandleFrontchannelLogoutRequestContext, RequireFrontchannelLogoutEndpointPassthroughEnabled>.Descriptor,
            SignOutFrontchannelLogoutSession.Descriptor,

            /*
             * Front-channel logout response handling:
             */
            AttachHttpResponseCode<ApplyFrontchannelLogoutResponseContext>.Descriptor,
            AttachFrontchannelLogoutCacheControlHeader.Descriptor,
            ProcessPassthroughErrorResponse<ApplyFrontchannelLogoutResponseContext, RequireFrontchannelLogoutEndpointPassthroughEnabled>.Descriptor,
            ProcessStatusCodePagesErrorResponse<ApplyFrontchannelLogoutResponseContext>.Descriptor,
            ProcessLocalErrorResponse<ApplyFrontchannelLogoutResponseContext>.Descriptor,
            ProcessEmptyResponse<ApplyFrontchannelLogoutResponseContext>.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for extracting OpenID Connect requests from POST HTTP requests.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public sealed class ExtractPostRequest<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseValidatingContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ExtractPostRequest<TContext>>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

                // Back-channel logout requests MUST be sent using POST and the form-urlencoded content type.
                //
                // See https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRequest for more information.
                if (!HttpMethods.IsPost(request.Method))
                {
                    context.Logger.LogInformation(6137, SR.GetResourceString(SR.ID6137), request.Method);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2084),
                        uri: SR.FormatID8000(SR.ID2084));

                    return;
                }

                if (string.IsNullOrEmpty(request.ContentType))
                {
                    context.Logger.LogInformation(6138, SR.GetResourceString(SR.ID6138), HeaderNames.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2081(HeaderNames.ContentType),
                        uri: SR.FormatID8000(SR.ID2081));

                    return;
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    context.Logger.LogInformation(6139, SR.GetResourceString(SR.ID6139), HeaderNames.ContentType, request.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2082(HeaderNames.ContentType),
                        uri: SR.FormatID8000(SR.ID2082));

                    return;
                }

                context.Transaction.Request = new OpenIddictRequest(await request.ReadFormAsync(context.CancellationToken));
            }
        }

        /// <summary>
        /// Contains the logic responsible for signing out the local session targeted by a front-channel logout request.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public sealed class SignOutFrontchannelLogoutSession : IOpenIddictClientHandler<HandleFrontchannelLogoutRequestContext>
        {
            private readonly IOptionsMonitor<OpenIddictClientAspNetCoreOptions> _options;

            public SignOutFrontchannelLogoutSession(IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options)
                => _options = options ?? throw new ArgumentNullException(nameof(options));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleFrontchannelLogoutRequestContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<SignOutFrontchannelLogoutSession>()
                    // Note: this handler is deliberately executed after the handler enabling the pass-through mode.
                    .SetOrder(EnablePassthroughMode<HandleFrontchannelLogoutRequestContext,
                        RequireFrontchannelLogoutEndpointPassthroughEnabled>.Descriptor.Order + 25_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(HandleFrontchannelLogoutRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var scheme = _options.CurrentValue.FrontchannelLogoutSignOutScheme;
                if (string.IsNullOrEmpty(scheme) || string.IsNullOrEmpty(context.SessionId))
                {
                    return;
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

                // Only terminate the current session if it's the session identified by the authorization server,
                // which prevents forged front-channel logout requests from terminating unrelated sessions.
                //
                // See https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout for more information.
                var result = await request.HttpContext.AuthenticateAsync(scheme);
                if (result is not { Succeeded: true, Principal: not null } || !context.IsMatchingSession(result.Principal))
                {
                    context.Logger.LogInformation(6567, SR.GetResourceString(SR.ID6567));
                    return;
                }

                await request.HttpContext.SignOutAsync(scheme);

                context.Logger.LogInformation(6566, SR.GetResourceString(SR.ID6566), scheme, context.SessionId);
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the cache headers required by
        /// <see href="https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout">OpenID Connect
        /// Front-Channel Logout 1.0, section 2</see> to front-channel logout responses.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public sealed class AttachFrontchannelLogoutCacheControlHeader : IOpenIddictClientHandler<ApplyFrontchannelLogoutResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyFrontchannelLogoutResponseContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<AttachFrontchannelLogoutCacheControlHeader>()
                    .SetOrder(AttachHttpResponseCode<ApplyFrontchannelLogoutResponseContext>.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyFrontchannelLogoutResponseContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

                response.Headers[HeaderNames.CacheControl] = "no-cache, no-store";
                response.Headers[HeaderNames.Pragma] = "no-cache";

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for returning errors as JSON documents, as allowed by
        /// <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#BCResponse">OpenID Connect
        /// Back-Channel Logout 1.0, section 2.8</see>.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public sealed class ProcessJsonErrorResponse<TContext> : IOpenIddictClientHandler<TContext>
            where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ProcessJsonErrorResponse<TContext>>()
                    .SetOrder(500_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

                Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

                if (string.IsNullOrEmpty(context.Transaction.Response.Error))
                {
                    return;
                }

                context.Logger.LogInformation(6143, SR.GetResourceString(SR.ID6143), context.Transaction.Response);

                using var stream = new MemoryStream();
                using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
                {
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                    Indented = false
                });

                writer.WriteStartObject();
                writer.WriteString(Parameters.Error, context.Transaction.Response.Error);

                if (!string.IsNullOrEmpty(context.Transaction.Response.ErrorDescription))
                {
                    writer.WriteString(Parameters.ErrorDescription, context.Transaction.Response.ErrorDescription);
                }

                if (!string.IsNullOrEmpty(context.Transaction.Response.ErrorUri))
                {
                    writer.WriteString(Parameters.ErrorUri, context.Transaction.Response.ErrorUri);
                }

                writer.WriteEndObject();
                writer.Flush();

                response.ContentLength = stream.Length;
                response.ContentType = "application/json;charset=UTF-8";

                stream.Seek(offset: 0, loc: SeekOrigin.Begin);
                await stream.CopyToAsync(response.Body, 4096, context.CancellationToken);

                context.HandleRequest();
            }
        }
    }
}
