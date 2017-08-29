/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Core;

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

            var ticket = await ReceiveTokenAsync(
                context.AccessToken, options, context.HttpContext,
                context.Request, context.DataFormat);

            // If a valid ticket was returned by ReceiveTokenAsync(),
            // force the OpenID Connect server middleware to use it.
            if (ticket != null)
            {
                context.Ticket = ticket;
                context.HandleDeserialization();
            }

            // Otherwise, let the OpenID Connect server middleware
            // deserialize the token using its default internal logic.
        }

        public override async Task DeserializeAuthorizationCode([NotNull] DeserializeAuthorizationCodeContext context)
        {
            var options = (OpenIddictOptions) context.Options;
            if (!options.UseReferenceTokens)
            {
                return;
            }

            var ticket = await ReceiveTokenAsync(
                context.AuthorizationCode, options, context.HttpContext,
                context.Request, context.DataFormat);

            // If a valid ticket was returned by ReceiveTokenAsync(),
            // force the OpenID Connect server middleware to use it.
            if (ticket != null)
            {
                context.Ticket = ticket;
                context.HandleDeserialization();
            }

            // Otherwise, let the OpenID Connect server middleware
            // deserialize the token using its default internal logic.
        }

        public override async Task DeserializeRefreshToken([NotNull] DeserializeRefreshTokenContext context)
        {
            var options = (OpenIddictOptions) context.Options;
            if (!options.UseReferenceTokens)
            {
                return;
            }

            var ticket = await ReceiveTokenAsync(
                context.RefreshToken, options, context.HttpContext,
                context.Request, context.DataFormat);

            // If a valid ticket was returned by ReceiveTokenAsync(),
            // force the OpenID Connect server middleware to use it.
            if (ticket != null)
            {
                context.Ticket = ticket;
                context.HandleDeserialization();
            }

            // Otherwise, let the OpenID Connect server middleware
            // deserialize the token using its default internal logic.
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

        private async Task<string> CreateTokenAsync(
            [NotNull] string type, [NotNull] AuthenticationTicket ticket,
            [NotNull] OpenIddictOptions options, [NotNull] HttpContext context,
            [NotNull] OpenIdConnectRequest request,
            [NotNull] ISecureDataFormat<AuthenticationTicket> format)
        {
            Debug.Assert(!(options.DisableTokenRevocation && options.UseReferenceTokens),
                "Token revocation cannot be disabled when using reference tokens.");

            Debug.Assert(!string.Equals(type, OpenIdConnectConstants.TokenUsages.IdToken, StringComparison.OrdinalIgnoreCase),
                "Identity tokens shouldn't be stored in the database.");

            if (options.DisableTokenRevocation)
            {
                return null;
            }

            // Resolve the subject from the authentication ticket. If it cannot be found, throw an exception.
            var subject = ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.Subject);
            if (string.IsNullOrEmpty(subject))
            {
                throw new InvalidOperationException("The subject associated with the authentication ticket cannot be retrieved.");
            }

            TToken token;
            string result = null;

            // If reference tokens are enabled, create a new entry for
            // authorization codes, refresh tokens and access tokens.
            if (options.UseReferenceTokens)
            {
                // When the token is a reference token, remove the token identifier from the
                // authentication ticket as it is restored when receiving and decrypting it.
                ticket.RemoveProperty(OpenIdConnectConstants.Properties.TokenId);

                // Note: the data format is automatically replaced at startup time to ensure
                // that encrypted tokens stored in the database cannot be considered as
                // valid tokens if the developer decides to disable reference tokens support.
                var ciphertext = format.Protect(ticket);

                // Generate a new crypto-secure random identifier that will be
                // substituted to the ciphertext returned by the data format.
                var bytes = new byte[256 / 8];
                options.RandomNumberGenerator.GetBytes(bytes);
                result = Base64UrlEncoder.Encode(bytes);

                // Compute the digest of the generated identifier and use
                // it as the hashed identifier of the reference token.
                // Doing that prevents token identifiers stolen from
                // the database from being used as valid reference tokens.
                string hash;
                using (var algorithm = SHA256.Create())
                {
                    hash = Convert.ToBase64String(algorithm.ComputeHash(bytes));
                }

                token = await Tokens.CreateAsync(type, subject, hash, ciphertext,
                    ticket.Properties.IssuedUtc,
                    ticket.Properties.ExpiresUtc, context.RequestAborted);
            }

            // Otherwise, only create a token metadata entry for authorization codes and refresh tokens.
            else if (string.Equals(type, OpenIdConnectConstants.TokenUsages.AuthorizationCode, StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(type, OpenIdConnectConstants.TokenUsages.RefreshToken, StringComparison.OrdinalIgnoreCase))
            {
                token = await Tokens.CreateAsync(type, subject,
                    ticket.Properties.IssuedUtc,
                    ticket.Properties.ExpiresUtc, context.RequestAborted);
            }

            else
            {
                return null;
            }

            // If a null value was returned by CreateAsync(), return immediately.
            if (token == null)
            {
                return null;
            }

            // Throw an exception if the token identifier can't be resolved.
            var identifier = await Tokens.GetIdAsync(token, context.RequestAborted);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException("The unique key associated with a refresh token cannot be null or empty.");
            }

            // Attach the key returned by the underlying store
            // to the refresh token to override the default GUID
            // generated by the OpenID Connect server middleware.
            ticket.SetTokenId(identifier);

            // If the client application is known, associate it with the token.
            if (!string.IsNullOrEmpty(request.ClientId))
            {
                var application = await Applications.FindByClientIdAsync(request.ClientId, context.RequestAborted);
                if (application == null)
                {
                    throw new InvalidOperationException("The client application cannot be retrieved from the database.");
                }

                var key = await Applications.GetIdAsync(application, context.RequestAborted);

                await Tokens.SetClientAsync(token, key, context.RequestAborted);
            }

            // If an authorization identifier was specified, bind it to the token.
            if (ticket.HasProperty(OpenIddictConstants.Properties.AuthorizationId))
            {
                await Tokens.SetAuthorizationAsync(token,
                    ticket.GetProperty(OpenIddictConstants.Properties.AuthorizationId), context.RequestAborted);
            }

            // Otherwise, create an ad-hoc authorization if the token is an authorization code.
            else if (string.Equals(type, OpenIdConnectConstants.TokenUsages.AuthorizationCode, StringComparison.OrdinalIgnoreCase))
            {
                Debug.Assert(!string.IsNullOrEmpty(request.ClientId), "The client identifier shouldn't be null.");

                var application = await Applications.FindByClientIdAsync(request.ClientId, context.RequestAborted);
                if (application == null)
                {
                    throw new InvalidOperationException("The client application cannot be retrieved from the database.");
                }

                var authorization = await Authorizations.CreateAsync(subject,
                    await Applications.GetIdAsync(application, context.RequestAborted), request.GetScopes(), context.RequestAborted);

                if (authorization != null)
                {
                    var key = await Authorizations.GetIdAsync(authorization, context.RequestAborted);
                    ticket.SetProperty(OpenIddictConstants.Properties.AuthorizationId, key);

                    await Tokens.SetAuthorizationAsync(token, key, context.RequestAborted);
                }
            }

            if (!string.IsNullOrEmpty(result))
            {
                Logger.LogTrace("A new reference token was successfully generated and persisted " +
                                "in the database: {Token} ; {Claims} ; {Properties}.",
                                result, ticket.Principal.Claims, ticket.Properties.Items);
            }

            return result;
        }

        private async Task<AuthenticationTicket> ReceiveTokenAsync(
            [NotNull] string value, [NotNull] OpenIddictOptions options,
            [NotNull] HttpContext context, [NotNull] OpenIdConnectRequest request,
            [NotNull] ISecureDataFormat<AuthenticationTicket> format)
        {
            if (!options.UseReferenceTokens)
            {
                return null;
            }

            string hash;
            try
            {
                // Compute the digest of the received token and use it
                // to retrieve the reference token from the database.
                using (var algorithm = SHA256.Create())
                {
                    hash = Convert.ToBase64String(algorithm.ComputeHash(Base64UrlEncoder.DecodeBytes(value)));
                }
            }

            // Swallow format-related exceptions to ensure badly formed
            // or tampered tokens don't cause an exception at this stage.
            catch
            {
                return null;
            }

            // Retrieve the token entry from the database. If it
            // cannot be found, assume the token is not valid.
            var token = await Tokens.FindByHashAsync(hash, context.RequestAborted);
            if (token == null)
            {
                Logger.LogInformation("The reference token corresponding to the '{Hash}' hashed " +
                                      "identifier cannot be found in the database.", hash);

                return null;
            }

            var identifier = await Tokens.GetIdAsync(token, context.RequestAborted);
            if (string.IsNullOrEmpty(identifier))
            {
                Logger.LogWarning("The identifier associated with the received token cannot be retrieved. " +
                                  "This may indicate that the token entry is corrupted.");

                return null;
            }

            // Extract the encrypted payload from the token. If it's null or empty,
            // assume the token is not a reference token and consider it as invalid.
            var ciphertext = await Tokens.GetCiphertextAsync(token, context.RequestAborted);
            if (string.IsNullOrEmpty(ciphertext))
            {
                Logger.LogWarning("The ciphertext associated with the token '{Identifier}' cannot be retrieved. " +
                                  "This may indicate that the token is not a reference token.", identifier);

                return null;
            }

            var ticket = format.Unprotect(ciphertext);
            if (ticket == null)
            {
                Logger.LogWarning("The ciphertext associated with the token '{Identifier}' cannot be decrypted. " +
                                  "This may indicate that the token entry is corrupted or tampered.",
                                  await Tokens.GetIdAsync(token, context.RequestAborted));

                return null;
            }

            // Restore the token identifier using the unique
            // identifier attached with the database entry.
            ticket.SetTokenId(identifier);

            // If the authorization identifier cannot be found in the ticket properties,
            // try to restore it using the identifier associated with the database entry.
            if (!ticket.HasProperty(OpenIddictConstants.Properties.AuthorizationId))
            {
                ticket.SetProperty(OpenIddictConstants.Properties.AuthorizationId,
                    await Tokens.GetAuthorizationIdAsync(token, context.RequestAborted));
            }

            Logger.LogTrace("The reference token '{Identifier}' was successfully retrieved " +
                            "from the database and decrypted:  {Claims} ; {Properties}.",
                            identifier, ticket.Principal.Claims, ticket.Properties.Items);

            return ticket;
        }
    }
}