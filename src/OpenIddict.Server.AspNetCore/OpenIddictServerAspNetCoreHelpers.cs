/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNetCore.Http;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Microsoft.AspNetCore
{
    /// <summary>
    /// Exposes companion extensions for the OpenIddict/ASP.NET Core integration.
    /// </summary>
    public static class OpenIddictServerAspNetCoreHelpers
    {
        /// <summary>
        /// Retrieves the <see cref="HttpRequest"/> instance stored in the <see cref="OpenIddictServerTransaction"/> properties.
        /// </summary>
        /// <param name="transaction">The transaction instance.</param>
        /// <returns>The <see cref="HttpRequest"/> instance or <c>null</c> if it couldn't be found.</returns>
        public static HttpRequest? GetHttpRequest(this OpenIddictServerTransaction transaction)
        {
            if (transaction == null)
            {
                throw new ArgumentNullException(nameof(transaction));
            }

            if (!transaction.Properties.TryGetValue(typeof(HttpRequest).FullName!, out object? property))
            {
                return null;
            }

            if (property is WeakReference<HttpRequest> reference && reference.TryGetTarget(out HttpRequest? request))
            {
                return request;
            }

            return null;
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIddictServerEndpointType"/> instance stored in <see cref="BaseContext"/>.
        /// </summary>
        /// <param name="context">The context instance.</param>
        /// <returns>The <see cref="OpenIddictServerEndpointType"/>.</returns>
        public static OpenIddictServerEndpointType GetOpenIddictServerEndpointType(this HttpContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction?.EndpointType ?? default;
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIddictRequest"/> instance stored in <see cref="BaseContext"/>.
        /// </summary>
        /// <param name="context">The context instance.</param>
        /// <returns>The <see cref="OpenIddictRequest"/> instance or <c>null</c> if it couldn't be found.</returns>
        public static OpenIddictRequest? GetOpenIddictServerRequest(this HttpContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction?.Request;
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIddictResponse"/> instance stored in <see cref="BaseContext"/>.
        /// </summary>
        /// <param name="context">The context instance.</param>
        /// <returns>The <see cref="OpenIddictResponse"/> instance or <c>null</c> if it couldn't be found.</returns>
        public static OpenIddictResponse? GetOpenIddictServerResponse(this HttpContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction?.Response;
        }
    }
}
