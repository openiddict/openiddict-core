/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreHandlerFilters;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers.Serialization;

namespace OpenIddict.Server.AspNetCore
{
    public static partial class OpenIddictServerAspNetCoreHandlers
    {
        public static class Serialization
        {
            public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Token serialization:
                 */
                InferTokenSerializationIssuerFromHost<SerializeAccessTokenContext>.Descriptor,
                InferTokenSerializationIssuerFromHost<SerializeAuthorizationCodeContext>.Descriptor,
                InferTokenSerializationIssuerFromHost<SerializeIdentityTokenContext>.Descriptor,
                InferTokenSerializationIssuerFromHost<SerializeRefreshTokenContext>.Descriptor,

                /*
                 * Token deserialization:
                 */
                InferTokenDeserializationIssuerFromHost<DeserializeAccessTokenContext>.Descriptor,
                InferTokenDeserializationIssuerFromHost<DeserializeAuthorizationCodeContext>.Descriptor,
                InferTokenDeserializationIssuerFromHost<DeserializeIdentityTokenContext>.Descriptor,
                InferTokenDeserializationIssuerFromHost<DeserializeRefreshTokenContext>.Descriptor);
        }

        /// <summary>
        /// Contains the logic responsible of infering the issuer URL from the HTTP request host for token deserialization.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class InferTokenSerializationIssuerFromHost<TContext> : IOpenIddictServerHandler<TContext>
            where TContext : BaseSerializingContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<InferTokenSerializationIssuerFromHost<TContext>>()
                    .SetOrder(AttachIdentityTokenSerializationParameters.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                // If the issuer was not populated by another handler (e.g from the server options),
                // try to infer it from the request scheme/host/path base (which requires HTTP/1.1).
                if (context.Issuer == null)
                {
                    if (!request.Host.HasValue)
                    {
                        throw new InvalidOperationException("No host was attached to the HTTP request.");
                    }

                    if (!Uri.TryCreate(request.Scheme + "://" + request.Host + request.PathBase, UriKind.Absolute, out Uri issuer))
                    {
                        throw new InvalidOperationException("The issuer address cannot be inferred from the current request.");
                    }

                    context.Issuer = issuer;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of infering the discovery document issuer URL from the HTTP request host.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class InferTokenDeserializationIssuerFromHost<TContext> : IOpenIddictServerHandler<TContext>
            where TContext : BaseDeserializingContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<InferTokenDeserializationIssuerFromHost<TContext>>()
                    .SetOrder(AttachIdentityTokenDeserializationParameters.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                // If the issuer was not populated by another handler (e.g from the server options),
                // try to infer it from the request scheme/host/path base (which requires HTTP/1.1).
                if (context.TokenValidationParameters != null && context.TokenValidationParameters.ValidIssuer == null)
                {
                    if (!request.Host.HasValue)
                    {
                        throw new InvalidOperationException("No host was attached to the HTTP request.");
                    }

                    if (!Uri.TryCreate(request.Scheme + "://" + request.Host + request.PathBase, UriKind.Absolute, out Uri issuer))
                    {
                        throw new InvalidOperationException("The issuer address cannot be inferred from the current request.");
                    }

                    context.TokenValidationParameters.ValidIssuer = issuer.AbsoluteUri;
                }

                return default;
            }
        }
    }
}
