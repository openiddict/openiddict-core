/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Security.Cryptography;
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
            var options = (OpenIddictOptions) context.Options;

            Debug.Assert(context.Request.IsTokenRequest(), "The request should be a token request.");

            // When rolling tokens are disabled, extend the expiration date associated with the
            // existing token instead of returning a new refresh token with a new expiration date.
            if (options.UseSlidingExpiration && !options.UseRollingTokens && context.Request.IsRefreshTokenGrantType())
            {
                var identifier = context.Request.GetProperty<string>(OpenIddictConstants.Properties.TokenId);

                var entry = await Tokens.FindByIdAsync(identifier, context.HttpContext.RequestAborted);
                if (entry != null)
                {
                    Logger.LogInformation("The expiration date of the '{Identifier}' token was automatically updated: {Date}.",
                                          identifier, context.Ticket.Properties.ExpiresUtc);

                    await Tokens.ExtendAsync(entry, context.Ticket.Properties.ExpiresUtc, context.HttpContext.RequestAborted);

                    context.RefreshToken = null;
                    context.HandleSerialization();

                    return;
                }

                // If the refresh token entry could not be
                // found in the database, generate a new one.
            }

            var token = await CreateTokenAsync(
                OpenIdConnectConstants.TokenUsages.RefreshToken, context.Ticket, options,
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

            Debug.Assert(!(options.DisableTokenRevocation && options.UseRollingTokens),
                "Token revocation cannot be disabled when using rolling tokens.");

            Debug.Assert(type != OpenIdConnectConstants.TokenUsages.IdToken,
                "Identity tokens shouldn't be stored in the database.");

            if (options.DisableTokenRevocation)
            {
                return null;
            }

            var descriptor = new OpenIddictTokenDescriptor
            {
                CreationDate = ticket.Properties.IssuedUtc,
                ExpirationDate = ticket.Properties.ExpiresUtc,
                Status = OpenIddictConstants.Statuses.Valid,
                Subject = ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.Subject),
                Type = type
            };

            string result = null;

            // When reference tokens are enabled or when the token is an authorization code or a
            // refresh token, remove the unnecessary properties from the authentication ticket.
            if (options.UseReferenceTokens ||
               (type == OpenIdConnectConstants.TokenUsages.AuthorizationCode ||
                type == OpenIdConnectConstants.TokenUsages.RefreshToken))
            {
                ticket.Properties.IssuedUtc = ticket.Properties.ExpiresUtc = null;
                ticket.RemoveProperty(OpenIdConnectConstants.Properties.TokenId);
            }

            // If reference tokens are enabled, create a new entry for
            // authorization codes, refresh tokens and access tokens.
            if (options.UseReferenceTokens)
            {
                // Note: the data format is automatically replaced at startup time to ensure
                // that encrypted tokens stored in the database cannot be considered as
                // valid tokens if the developer decides to disable reference tokens support.
                descriptor.Ciphertext = format.Protect(ticket);

                // Generate a new crypto-secure random identifier that will be
                // substituted to the ciphertext returned by the data format.
                var bytes = new byte[256 / 8];
                options.RandomNumberGenerator.GetBytes(bytes);
                result = Base64UrlEncoder.Encode(bytes);

                // Compute the digest of the generated identifier and use
                // it as the hashed identifier of the reference token.
                // Doing that prevents token identifiers stolen from
                // the database from being used as valid reference tokens.
                using (var algorithm = SHA256.Create())
                {
                    descriptor.Hash = Convert.ToBase64String(algorithm.ComputeHash(bytes));
                }
            }

            // Otherwise, only create a token metadata entry for authorization codes and refresh tokens.
            else if (type != OpenIdConnectConstants.TokenUsages.AuthorizationCode &&
                     type != OpenIdConnectConstants.TokenUsages.RefreshToken)
            {
                return null;
            }

            // If the client application is known, associate it with the token.
            if (!string.IsNullOrEmpty(request.ClientId))
            {
                var application = await Applications.FindByClientIdAsync(request.ClientId, context.RequestAborted);
                if (application == null)
                {
                    throw new InvalidOperationException("The client application cannot be retrieved from the database.");
                }

                descriptor.ApplicationId = await Applications.GetIdAsync(application, context.RequestAborted);
            }

            // If an authorization identifier was specified, bind it to the token.
            if (ticket.HasProperty(OpenIddictConstants.Properties.AuthorizationId))
            {
                descriptor.AuthorizationId = ticket.GetProperty(OpenIddictConstants.Properties.AuthorizationId);
            }

            // Otherwise, create an ad hoc authorization if the token is an authorization code.
            else if (type == OpenIdConnectConstants.TokenUsages.AuthorizationCode)
            {
                Debug.Assert(!string.IsNullOrEmpty(descriptor.ApplicationId), "The client identifier shouldn't be null.");

                var authorization = await CreateAuthorizationAsync(descriptor, context, request);
                if (authorization != null)
                {
                    descriptor.AuthorizationId = await Authorizations.GetIdAsync(authorization, context.RequestAborted);

                    Logger.LogInformation("An ad hoc authorization was automatically created and " +
                                          "associated with the '{ClientId}' application: {Identifier}.",
                                          request.ClientId, descriptor.AuthorizationId);
                }
            }

            // If a null value was returned by CreateAsync(), return immediately.
            var token = await Tokens.CreateAsync(descriptor, context.RequestAborted);
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

            // Restore the token identifier using the unique
            // identifier attached with the database entry.
            ticket.SetTokenId(identifier);

            // Dynamically set the creation and expiration dates.
            ticket.Properties.IssuedUtc = await Tokens.GetCreationDateAsync(token, context.RequestAborted);
            ticket.Properties.ExpiresUtc = await Tokens.GetExpirationDateAsync(token, context.RequestAborted);

            ticket.SetProperty(OpenIddictConstants.Properties.AuthorizationId, descriptor.AuthorizationId);

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

            // Dynamically set the creation and expiration dates.
            ticket.Properties.IssuedUtc = await Tokens.GetCreationDateAsync(token, context.RequestAborted);
            ticket.Properties.ExpiresUtc = await Tokens.GetExpirationDateAsync(token, context.RequestAborted);

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

        private Task<TAuthorization> CreateAuthorizationAsync(
            [NotNull] OpenIddictTokenDescriptor token,
            [NotNull] HttpContext context, [NotNull] OpenIdConnectRequest request)
        {
            var descriptor = new OpenIddictAuthorizationDescriptor
            {
                ApplicationId = token.ApplicationId,
                Status = OpenIddictConstants.Statuses.Valid,
                Subject = token.Subject,
                Type = OpenIddictConstants.AuthorizationTypes.AdHoc
            };

            foreach (var scope in request.GetScopes())
            {
                descriptor.Scopes.Add(scope);
            }

            return Authorizations.CreateAsync(descriptor, context.RequestAborted);
        }
    }
}