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

namespace OpenIddict
{
    public partial class OpenIddictProvider<TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TApplication : class where TAuthorization : class where TScope : class where TToken : class
    {
        public override async Task DeserializeAccessToken([NotNull] DeserializeAccessTokenContext context)
        {
            var options = (OpenIddictOptions) context.Options;
            if (options.DisableTokenRevocation)
            {
                return;
            }

            context.Ticket = await ReceiveTokenAsync(
                OpenIdConnectConstants.TokenUsages.AccessToken,
                context.AccessToken, options, context.HttpContext,
                context.Request, context.DataFormat);

            // Prevent the OpenID Connect server middleware from using
            // its default logic to deserialize reference access tokens.
            if (options.UseReferenceTokens)
            {
                context.HandleDeserialization();
            }
        }

        public override async Task DeserializeAuthorizationCode([NotNull] DeserializeAuthorizationCodeContext context)
        {
            var options = (OpenIddictOptions) context.Options;
            if (options.DisableTokenRevocation)
            {
                return;
            }

            context.Ticket = await ReceiveTokenAsync(
                OpenIdConnectConstants.TokenUsages.AuthorizationCode,
                context.AuthorizationCode, options, context.HttpContext,
                context.Request, context.DataFormat);

            // Prevent the OpenID Connect server middleware from using its default logic.
            context.HandleDeserialization();
        }

        public override async Task DeserializeRefreshToken([NotNull] DeserializeRefreshTokenContext context)
        {
            var options = (OpenIddictOptions) context.Options;
            if (options.DisableTokenRevocation)
            {
                return;
            }

            context.Ticket = await ReceiveTokenAsync(
                OpenIdConnectConstants.TokenUsages.RefreshToken,
                context.RefreshToken, options, context.HttpContext,
                context.Request, context.DataFormat);

            // Prevent the OpenID Connect server middleware from using its default logic.
            context.HandleDeserialization();
        }

        public override async Task SerializeAccessToken([NotNull] SerializeAccessTokenContext context)
        {
            var options = (OpenIddictOptions) context.Options;
            if (options.DisableTokenRevocation)
            {
                return;
            }

            var token = await CreateTokenAsync(
                OpenIdConnectConstants.TokenUsages.AccessToken,
                context.Ticket, options, context.HttpContext,
                context.Request, context.DataFormat);

            // If a reference token was returned by CreateTokenAsync(),
            // force the OpenID Connect server middleware to use it.
            if (!string.IsNullOrEmpty(token))
            {
                context.AccessToken = token;
                context.HandleSerialization();
            }

            // Otherwise, let the OpenID Connect server middleware
            // serialize the token using its default internal logic.
        }

        public override async Task SerializeAuthorizationCode([NotNull] SerializeAuthorizationCodeContext context)
        {
            var options = (OpenIddictOptions) context.Options;
            if (options.DisableTokenRevocation)
            {
                return;
            }

            Debug.Assert(context.Request.IsAuthorizationRequest(), "The request should be an authorization request.");

            var token = await CreateTokenAsync(
                OpenIdConnectConstants.TokenUsages.AuthorizationCode,
                context.Ticket, options, context.HttpContext,
                context.Request, context.DataFormat);

            // If a reference token was returned by CreateTokenAsync(),
            // force the OpenID Connect server middleware to use it.
            if (!string.IsNullOrEmpty(token))
            {
                context.AuthorizationCode = token;
                context.HandleSerialization();
            }

            // Otherwise, let the OpenID Connect server middleware
            // serialize the token using its default internal logic.
        }

        public override async Task SerializeRefreshToken([NotNull] SerializeRefreshTokenContext context)
        {
            var options = (OpenIddictOptions) context.Options;
            if (options.DisableTokenRevocation)
            {
                return;
            }

            Debug.Assert(context.Request.IsTokenRequest(), "The request should be a token request.");

            var token = await CreateTokenAsync(
                OpenIdConnectConstants.TokenUsages.RefreshToken,
                context.Ticket, options, context.HttpContext,
                context.Request, context.DataFormat);

            // If a reference token was returned by CreateTokenAsync(),
            // force the OpenID Connect server middleware to use it.
            if (!string.IsNullOrEmpty(token))
            {
                context.RefreshToken = token;
                context.HandleSerialization();
            }

            // Otherwise, let the OpenID Connect server middleware
            // serialize the token using its default internal logic.
        }
    }
}