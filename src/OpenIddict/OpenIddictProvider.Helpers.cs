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
        private async Task CreateAuthorizationAsync(
            [NotNull] AuthenticationTicket ticket, [NotNull] OpenIddictOptions options,
            [NotNull] HttpContext context, [NotNull] OpenIdConnectRequest request)
        {
            if (options.DisableTokenRevocation)
            {
                return;
            }

            var descriptor = new OpenIddictAuthorizationDescriptor
            {
                Status = OpenIddictConstants.Statuses.Valid,
                Subject = ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.Subject),
                Type = OpenIddictConstants.AuthorizationTypes.AdHoc
            };

            foreach (var scope in request.GetScopes())
            {
                descriptor.Scopes.Add(scope);
            }

            // If the client application is known, bind it to the authorization.
            if (!string.IsNullOrEmpty(request.ClientId))
            {
                var application = await Applications.FindByClientIdAsync(request.ClientId, context.RequestAborted);
                if (application == null)
                {
                    throw new InvalidOperationException("The client application cannot be retrieved from the database.");
                }

                descriptor.ApplicationId = await Applications.GetIdAsync(application, context.RequestAborted);
            }

            var authorization = await Authorizations.CreateAsync(descriptor, context.RequestAborted);
            if (authorization != null)
            {
                var identifier = await Authorizations.GetIdAsync(authorization, context.RequestAborted);

                if (string.IsNullOrEmpty(request.ClientId))
                {
                    Logger.LogInformation("An ad hoc authorization was automatically created and " +
                                          "associated with an unknown application: {Identifier}.", identifier);
                }

                else
                {
                    Logger.LogInformation("An ad hoc authorization was automatically created and " +
                                          "associated with the '{ClientId}' application: {Identifier}.",
                                          request.ClientId, identifier);
                }

                // Attach the unique identifier of the ad hoc authorization to the authentication ticket
                // so that it is attached to all the derived tokens, allowing batched revocations support.
                ticket.SetProperty(OpenIddictConstants.Properties.AuthorizationId, identifier);
            }
        }

        private async Task<string> CreateTokenAsync(
            [NotNull] string type, [NotNull] AuthenticationTicket ticket,
            [NotNull] OpenIddictOptions options, [NotNull] HttpContext context,
            [NotNull] OpenIdConnectRequest request,
            [NotNull] ISecureDataFormat<AuthenticationTicket> format)
        {
            Debug.Assert(!(options.DisableTokenRevocation && options.UseReferenceTokens),
                "Token revocation cannot be disabled when using reference tokens.");

            Debug.Assert(type == OpenIdConnectConstants.TokenUsages.AccessToken ||
                         type == OpenIdConnectConstants.TokenUsages.AuthorizationCode ||
                         type == OpenIdConnectConstants.TokenUsages.RefreshToken,
                "Only authorization codes, access and refresh tokens should be created using this method.");

            // When sliding expiration is disabled, the expiration date of generated refresh tokens is fixed
            // and must exactly match the expiration date of the refresh token used in the token request.
            if (request.IsTokenRequest() && request.IsRefreshTokenGrantType() &&
               !options.UseSlidingExpiration && type == OpenIdConnectConstants.TokenUsages.RefreshToken)
            {
                var properties = request.GetProperty<AuthenticationTicket>(
                    OpenIddictConstants.Properties.AuthenticationTicket)?.Properties;
                Debug.Assert(properties != null, "The authentication properties shouldn't be null.");

                ticket.Properties.ExpiresUtc = properties.ExpiresUtc;
            }

            if (options.DisableTokenRevocation)
            {
                return null;
            }

            var descriptor = new OpenIddictTokenDescriptor
            {
                AuthorizationId = ticket.GetProperty(OpenIddictConstants.Properties.AuthorizationId),
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
                ticket.RemoveProperty(OpenIddictConstants.Properties.AuthorizationId)
                      .RemoveProperty(OpenIdConnectConstants.Properties.TokenId);
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

            // Restore the authorization identifier using the identifier attached with the database entry.
            ticket.SetProperty(OpenIddictConstants.Properties.AuthorizationId,
                await Tokens.GetAuthorizationIdAsync(token, context.RequestAborted));

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

            // Restore the authorization identifier using the identifier attached with the database entry.
            ticket.SetProperty(OpenIddictConstants.Properties.AuthorizationId,
                await Tokens.GetAuthorizationIdAsync(token, context.RequestAborted));

            Logger.LogTrace("The reference token '{Identifier}' was successfully retrieved " +
                            "from the database and decrypted:  {Claims} ; {Properties}.",
                            identifier, ticket.Principal.Claims, ticket.Properties.Items);

            return ticket;
        }

        private async Task RevokeAuthorizationAsync([NotNull] AuthenticationTicket ticket, [NotNull] HttpContext context)
        {
            var identifier = ticket.GetProperty(OpenIddictConstants.Properties.AuthorizationId);
            if (string.IsNullOrEmpty(identifier))
            {
                return;
            }

            var authorization = await Authorizations.FindByIdAsync(identifier, context.RequestAborted);
            if (authorization == null)
            {
                return;
            }

            await Authorizations.RevokeAsync(authorization, context.RequestAborted);

            Logger.LogInformation("The authorization '{Identifier}' was automatically revoked.", identifier);
        }

        private async Task RevokeTokensAsync([NotNull] AuthenticationTicket ticket, [NotNull] HttpContext context)
        {
            var identifier = ticket.GetProperty(OpenIddictConstants.Properties.AuthorizationId);
            if (string.IsNullOrEmpty(identifier))
            {
                return;
            }

            foreach (var token in await Tokens.FindByAuthorizationIdAsync(identifier, context.RequestAborted))
            {
                // Don't overwrite the status of the token used in the token request.
                if (string.Equals(ticket.GetTokenId(), await Tokens.GetIdAsync(token, context.RequestAborted)))
                {
                    continue;
                }

                await Tokens.RevokeAsync(token, context.RequestAborted);

                Logger.LogInformation("The token '{Identifier}' was automatically revoked.",
                    await Tokens.GetIdAsync(token, context.RequestAborted));
            }
        }
    }
}