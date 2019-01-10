/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;

namespace OpenIddict.Server
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
    /// </summary>
    internal sealed partial class OpenIddictServerProvider : OpenIdConnectServerProvider
    {
        public override async Task DeserializeAccessToken([NotNull] DeserializeAccessTokenContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;
            if (options.DisableTokenStorage)
            {
                return;
            }

            context.Ticket = await ReceiveTokenAsync(
                OpenIdConnectConstants.TokenUsages.AccessToken,
                context.AccessToken, options,
                context.Request, context.DataFormat);

            // Prevent the OpenID Connect server middleware from using
            // its default logic to deserialize reference access tokens.
            if (options.UseReferenceTokens)
            {
                context.HandleDeserialization();
            }

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.DeserializeAccessToken(context));
        }

        public override async Task DeserializeAuthorizationCode([NotNull] DeserializeAuthorizationCodeContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;
            if (options.DisableTokenStorage)
            {
                return;
            }

            context.Ticket = await ReceiveTokenAsync(
                OpenIdConnectConstants.TokenUsages.AuthorizationCode,
                context.AuthorizationCode, options,
                context.Request, context.DataFormat);

            // Prevent the OpenID Connect server middleware from using its default logic.
            context.HandleDeserialization();

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.DeserializeAuthorizationCode(context));
        }

        public override Task DeserializeIdentityToken(DeserializeIdentityTokenContext context)
            => _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.DeserializeIdentityToken(context));

        public override async Task DeserializeRefreshToken([NotNull] DeserializeRefreshTokenContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;
            if (options.DisableTokenStorage)
            {
                return;
            }

            context.Ticket = await ReceiveTokenAsync(
                OpenIdConnectConstants.TokenUsages.RefreshToken,
                context.RefreshToken, options,
                context.Request, context.DataFormat);

            // Prevent the OpenID Connect server middleware from using its default logic.
            context.HandleDeserialization();

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.DeserializeRefreshToken(context));
        }

        public override async Task SerializeAccessToken([NotNull] SerializeAccessTokenContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;
            if (options.DisableTokenStorage)
            {
                return;
            }

            var token = await CreateTokenAsync(
                OpenIdConnectConstants.TokenUsages.AccessToken,
                context.Ticket, options, context.Request, context.DataFormat);

            // If a reference token was returned by CreateTokenAsync(),
            // force the OpenID Connect server middleware to use it.
            if (!string.IsNullOrEmpty(token))
            {
                context.AccessToken = token;
                context.HandleSerialization();
            }

            // Otherwise, let the OpenID Connect server middleware
            // serialize the token using its default internal logic.

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.SerializeAccessToken(context));
        }

        public override async Task SerializeAuthorizationCode([NotNull] SerializeAuthorizationCodeContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;
            if (options.DisableTokenStorage)
            {
                return;
            }

            Debug.Assert(context.Request.IsAuthorizationRequest(), "The request should be an authorization request.");

            var token = await CreateTokenAsync(
                OpenIdConnectConstants.TokenUsages.AuthorizationCode,
                context.Ticket, options, context.Request, context.DataFormat);

            // If a reference token was returned by CreateTokenAsync(),
            // force the OpenID Connect server middleware to use it.
            if (!string.IsNullOrEmpty(token))
            {
                context.AuthorizationCode = token;
                context.HandleSerialization();
            }

            // Otherwise, let the OpenID Connect server middleware
            // serialize the token using its default internal logic.

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.SerializeAuthorizationCode(context));
        }

        public override Task SerializeIdentityToken(SerializeIdentityTokenContext context)
            => _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.SerializeIdentityToken(context));

        public override async Task SerializeRefreshToken([NotNull] SerializeRefreshTokenContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;
            if (options.DisableTokenStorage)
            {
                return;
            }

            Debug.Assert(context.Request.IsTokenRequest(), "The request should be a token request.");

            var token = await CreateTokenAsync(
                OpenIdConnectConstants.TokenUsages.RefreshToken,
                context.Ticket, options, context.Request, context.DataFormat);

            // If a reference token was returned by CreateTokenAsync(),
            // force the OpenID Connect server middleware to use it.
            if (!string.IsNullOrEmpty(token))
            {
                context.RefreshToken = token;
                context.HandleSerialization();
            }

            // Otherwise, let the OpenID Connect server middleware
            // serialize the token using its default internal logic.

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.SerializeRefreshToken(context));
        }
    }
}
