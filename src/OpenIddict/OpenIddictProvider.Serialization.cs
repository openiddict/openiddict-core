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
            if (!options.UseReferenceTokens)
            {
                return;
            }

            context.Ticket = await ReceiveTokenAsync(
                context.AccessToken, options, context.HttpContext,
                context.Request, context.DataFormat);

            // Prevent the OpenID Connect server middleware from using
            // its default logic to deserialize the reference token.
            context.HandleDeserialization();
        }

        public override async Task DeserializeAuthorizationCode([NotNull] DeserializeAuthorizationCodeContext context)
        {
            var options = (OpenIddictOptions) context.Options;
            if (!options.UseReferenceTokens)
            {
                return;
            }

            context.Ticket = await ReceiveTokenAsync(
                context.AuthorizationCode, options, context.HttpContext,
                context.Request, context.DataFormat);

            // Prevent the OpenID Connect server middleware from using
            // its default logic to deserialize the reference token.
            context.HandleDeserialization();
        }

        public override async Task DeserializeRefreshToken([NotNull] DeserializeRefreshTokenContext context)
        {
            var options = (OpenIddictOptions) context.Options;
            if (!options.UseReferenceTokens)
            {
                return;
            }

            context.Ticket = await ReceiveTokenAsync(
                context.RefreshToken, options, context.HttpContext,
                context.Request, context.DataFormat);

            // Prevent the OpenID Connect server middleware from using
            // its default logic to deserialize the reference token.
            context.HandleDeserialization();
        }

        public override async Task SerializeAccessToken([NotNull] SerializeAccessTokenContext context)
        {
            var token = await CreateTokenAsync(
                OpenIdConnectConstants.TokenUsages.AccessToken,
                context.Ticket, (OpenIddictOptions) context.Options,
                context.HttpContext, context.Request, context.DataFormat);

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
            Debug.Assert(context.Request.IsAuthorizationRequest(), "The request should be an authorization request.");

            var token = await CreateTokenAsync(
                OpenIdConnectConstants.TokenUsages.AuthorizationCode,
                context.Ticket, (OpenIddictOptions) context.Options,
                context.HttpContext, context.Request, context.DataFormat);

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
            Debug.Assert(context.Request.IsTokenRequest(), "The request should be a token request.");

            var token = await CreateTokenAsync(
                OpenIdConnectConstants.TokenUsages.RefreshToken,
                context.Ticket, (OpenIddictOptions) context.Options,
                context.HttpContext, context.Request, context.DataFormat);

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