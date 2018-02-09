/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using OpenIddict.Core;

namespace OpenIddict
{
    public partial class OpenIddictProvider<TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TApplication : class where TAuthorization : class where TScope : class where TToken : class
    {
        private async Task CreateAuthorizationAsync([NotNull] AuthenticationTicket ticket,
            [NotNull] OpenIddictOptions options, [NotNull] OpenIdConnectRequest request)
        {
            var descriptor = new OpenIddictAuthorizationDescriptor
            {
                Principal = ticket.Principal,
                Status = OpenIddictConstants.Statuses.Valid,
                Subject = ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.Subject),
                Type = OpenIddictConstants.AuthorizationTypes.AdHoc
            };

            foreach (var property in ticket.Properties.Items)
            {
                descriptor.Properties.Add(property);
            }

            foreach (var scope in ticket.GetScopes())
            {
                descriptor.Scopes.Add(scope);
            }

            // If the client application is known, bind it to the authorization.
            if (!string.IsNullOrEmpty(request.ClientId))
            {
                var application = request.GetProperty<TApplication>($"{OpenIddictConstants.Properties.Application}:{request.ClientId}");
                Debug.Assert(application != null, "The client application shouldn't be null.");

                descriptor.ApplicationId = await Applications.GetIdAsync(application);
            }

            var authorization = await Authorizations.CreateAsync(descriptor);
            if (authorization != null)
            {
                var identifier = await Authorizations.GetIdAsync(authorization);

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
            [NotNull] OpenIddictOptions options,
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
                Principal = ticket.Principal,
                Status = OpenIddictConstants.Statuses.Valid,
                Subject = ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.Subject),
                Type = type
            };

            foreach (var property in ticket.Properties.Items)
            {
                descriptor.Properties.Add(property);
            }

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
                descriptor.Payload = format.Protect(ticket);

                // Generate a new crypto-secure random identifier that will be
                // substituted to the ciphertext returned by the data format.
                var bytes = new byte[256 / 8];
                options.RandomNumberGenerator.GetBytes(bytes);
                result = Base64UrlEncoder.Encode(bytes);

                // Obfuscate the reference identifier so it can be safely stored in the databse.
                descriptor.ReferenceId = await Tokens.ObfuscateReferenceIdAsync(result);
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
                var application = request.GetProperty<TApplication>($"{OpenIddictConstants.Properties.Application}:{request.ClientId}");
                Debug.Assert(application != null, "The client application shouldn't be null.");

                descriptor.ApplicationId = await Applications.GetIdAsync(application);
            }

            // If a null value was returned by CreateAsync(), return immediately.

            // Note: the request cancellation token is deliberately not used here to ensure the caller
            // cannot prevent this operation from being executed by resetting the TCP connection.
            var token = await Tokens.CreateAsync(descriptor);
            if (token == null)
            {
                return null;
            }

            // Throw an exception if the token identifier can't be resolved.
            var identifier = await Tokens.GetIdAsync(token);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException("The unique key associated with a refresh token cannot be null or empty.");
            }

            // Restore the token identifier using the unique
            // identifier attached with the database entry.
            ticket.SetTokenId(identifier);

            // Dynamically set the creation and expiration dates.
            ticket.Properties.IssuedUtc = descriptor.CreationDate;
            ticket.Properties.ExpiresUtc = descriptor.ExpirationDate;

            // Restore the authorization identifier using the identifier attached with the database entry.
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
            [NotNull] string type, [NotNull] string value,
            [NotNull] OpenIddictOptions options,
            [NotNull] OpenIdConnectRequest request,
            [NotNull] ISecureDataFormat<AuthenticationTicket> format)
        {
            Debug.Assert(!(options.DisableTokenRevocation && options.UseReferenceTokens),
                "Token revocation cannot be disabled when using reference tokens.");

            Debug.Assert(type == OpenIdConnectConstants.TokenUsages.AccessToken ||
                         type == OpenIdConnectConstants.TokenUsages.AuthorizationCode ||
                         type == OpenIdConnectConstants.TokenUsages.RefreshToken,
                "Only authorization codes, access and refresh tokens should be validated using this method.");

            string identifier;
            AuthenticationTicket ticket;
            TToken token;

            if (options.UseReferenceTokens)
            {
                // For introspection or revocation requests, this method may be called more than once.
                // For reference tokens, this may result in multiple database calls being made.
                // To optimize that, the token is added to the request properties to indicate that
                // a database lookup was already made with the same identifier. If the marker exists,
                // the property value (that may be null) is used instead of making a database call.
                if (request.HasProperty($"{OpenIddictConstants.Properties.ReferenceToken}:{value}"))
                {
                    token = request.GetProperty<TToken>($"{OpenIddictConstants.Properties.ReferenceToken}:{value}");
                }

                else
                {
                    // Retrieve the token entry from the database. If it
                    // cannot be found, assume the token is not valid.
                    token = await Tokens.FindByReferenceIdAsync(value);

                    // Store the token as a request property so it can be retrieved if this method is called another time.
                    request.AddProperty($"{OpenIddictConstants.Properties.ReferenceToken}:{value}", token);
                }

                if (token == null)
                {
                    Logger.LogInformation("The reference token corresponding to the '{Identifier}' " +
                                          "reference identifier cannot be found in the database.", value);

                    return null;
                }

                identifier = await Tokens.GetIdAsync(token);
                if (string.IsNullOrEmpty(identifier))
                {
                    Logger.LogWarning("The identifier associated with the received token cannot be retrieved. " +
                                      "This may indicate that the token entry is corrupted.");

                    return null;
                }

                // Extract the encrypted payload from the token. If it's null or empty,
                // assume the token is not a reference token and consider it as invalid.
                var payload = await Tokens.GetPayloadAsync(token);
                if (string.IsNullOrEmpty(payload))
                {
                    Logger.LogWarning("The ciphertext associated with the token '{Identifier}' cannot be retrieved. " +
                                      "This may indicate that the token is not a reference token.", identifier);

                    return null;
                }

                ticket = format.Unprotect(payload);
                if (ticket == null)
                {
                    Logger.LogWarning("The ciphertext associated with the token '{Identifier}' cannot be decrypted. " +
                                      "This may indicate that the token entry is corrupted or tampered.",
                                      await Tokens.GetIdAsync(token));

                    return null;
                }

                request.SetProperty($"{OpenIddictConstants.Properties.Token}:{identifier}", token);
            }

            else if (type == OpenIdConnectConstants.TokenUsages.AuthorizationCode ||
                     type == OpenIdConnectConstants.TokenUsages.RefreshToken)
            {
                ticket = format.Unprotect(value);
                if (ticket == null)
                {
                    Logger.LogTrace("The received token was invalid or malformed: {Token}.", value);

                    return null;
                }

                identifier = ticket.GetTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    Logger.LogWarning("The identifier associated with the received token cannot be retrieved. " +
                                      "This may indicate that the token entry is corrupted.");

                    return null;
                }

                // For introspection or revocation requests, this method may be called more than once.
                // For codes/refresh tokens, this may result in multiple database calls being made.
                // To optimize that, the token is added to the request properties to indicate that
                // a database lookup was already made with the same identifier. If the marker exists,
                // the property value (that may be null) is used instead of making a database call.
                if (request.HasProperty($"{OpenIddictConstants.Properties.Token}:{identifier}"))
                {
                    token = request.GetProperty<TToken>($"{OpenIddictConstants.Properties.Token}:{identifier}");
                }

                // Otherwise, retrieve the authorization code/refresh token entry from the database.
                // If it cannot be found, assume the authorization code/refresh token is not valid.
                else
                {
                    token = await Tokens.FindByIdAsync(identifier);

                    // Store the token as a request property so it can be retrieved if this method is called another time.
                    request.AddProperty($"{OpenIddictConstants.Properties.Token}:{identifier}", token);
                }

                if (token == null)
                {
                    Logger.LogInformation("The token '{Identifier}' cannot be found in the database.", ticket.GetTokenId());

                    return null;
                }
            }

            else
            {
                return null;
            }

            // Restore the token identifier using the unique
            // identifier attached with the database entry.
            ticket.SetTokenId(identifier);

            // Dynamically set the creation and expiration dates.
            ticket.Properties.IssuedUtc = await Tokens.GetCreationDateAsync(token);
            ticket.Properties.ExpiresUtc = await Tokens.GetExpirationDateAsync(token);

            // Restore the authorization identifier using the identifier attached with the database entry.
            ticket.SetProperty(OpenIddictConstants.Properties.AuthorizationId,
                await Tokens.GetAuthorizationIdAsync(token));

            Logger.LogTrace("The token '{Identifier}' was successfully decrypted and " +
                            "retrieved from the database: {Claims} ; {Properties}.",
                            ticket.GetTokenId(), ticket.Principal.Claims, ticket.Properties.Items);

            return ticket;
        }

        private async Task<bool> TryRevokeAuthorizationAsync([NotNull] AuthenticationTicket ticket)
        {
            // Note: if the authorization identifier or the authorization itself
            // cannot be found, return true as the authorization doesn't need
            // to be revoked if it doesn't exist or is already invalid.
            var identifier = ticket.GetProperty(OpenIddictConstants.Properties.AuthorizationId);
            if (string.IsNullOrEmpty(identifier))
            {
                return true;
            }

            var authorization = await Authorizations.FindByIdAsync(identifier);
            if (authorization == null)
            {
                return true;
            }

            try
            {
                // Note: the request cancellation token is deliberately not used here to ensure the caller
                // cannot prevent this operation from being executed by resetting the TCP connection.
                await Authorizations.RevokeAsync(authorization);

                Logger.LogInformation("The authorization '{Identifier}' was automatically revoked.", identifier);

                return true;
            }

            catch (Exception exception)
            {
                Logger.LogWarning(exception, "An exception occurred while trying to revoke the authorization " +
                                             "associated with the token '{Identifier}'.", identifier);

                return false;
            }
        }

        private async Task<bool> TryRevokeTokenAsync([NotNull] TToken token)
        {
            var identifier = await Tokens.GetIdAsync(token);
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The token identifier shouldn't be null or empty.");

            try
            {
                // Note: the request cancellation token is deliberately not used here to ensure the caller
                // cannot prevent this operation from being executed by resetting the TCP connection.
                await Tokens.RevokeAsync(token);

                Logger.LogInformation("The token '{Identifier}' was automatically revoked.", identifier);

                return true;
            }

            catch (Exception exception)
            {
                Logger.LogWarning(exception, "An exception occurred while trying to revoke " +
                                             "the token '{Identifier}'.", identifier);

                return false;
            }
        }

        private async Task<bool> TryRevokeTokensAsync([NotNull] AuthenticationTicket ticket)
        {
            // Note: if the authorization identifier is null, return true as no tokens need to be revoked.
            var identifier = ticket.GetProperty(OpenIddictConstants.Properties.AuthorizationId);
            if (string.IsNullOrEmpty(identifier))
            {
                return true;
            }

            foreach (var token in await Tokens.FindByAuthorizationIdAsync(identifier))
            {
                // Don't change the status of the token used in the token request.
                if (string.Equals(ticket.GetTokenId(), await Tokens.GetIdAsync(token), StringComparison.Ordinal))
                {
                    continue;
                }

                await TryRevokeTokenAsync(token);
            }

            return true;
        }

        private async Task<bool> TryRedeemTokenAsync([NotNull] TToken token)
        {
            var identifier = await Tokens.GetIdAsync(token);
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The token identifier shouldn't be null or empty.");

            try
            {
                // Note: the request cancellation token is deliberately not used here to ensure the caller
                // cannot prevent this operation from being executed by resetting the TCP connection.
                await Tokens.RedeemAsync(token);

                Logger.LogInformation("The token '{Identifier}' was automatically marked as redeemed.", identifier);

                return true;
            }

            catch (Exception exception)
            {
                Logger.LogWarning(exception, "An exception occurred while trying to " +
                                             "redeem the token '{Identifier}'.", identifier);

                return false;
            }
        }

        private async Task<bool> TryExtendTokenAsync(
            [NotNull] TToken token, [NotNull] AuthenticationTicket ticket, [NotNull] OpenIddictOptions options)
        {
            var identifier = ticket.GetTokenId();
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The token identifier shouldn't be null or empty.");

            try
            {
                // Compute the new expiration date of the refresh token.
                var date = options.SystemClock.UtcNow;
                date += ticket.GetRefreshTokenLifetime() ?? options.RefreshTokenLifetime;

                // Note: the request cancellation token is deliberately not used here to ensure the caller
                // cannot prevent this operation from being executed by resetting the TCP connection.
                await Tokens.ExtendAsync(token, date);

                Logger.LogInformation("The expiration date of the refresh token '{Identifier}' " +
                                      "was automatically updated: {Date}.", identifier, date);

                return true;
            }

            catch (Exception exception)
            {
                Logger.LogWarning(exception, "An exception occurred while trying to update the " +
                                             "expiration date of the token '{Identifier}'.", identifier);

                return false;
            }
        }

        private IEnumerable<(string property, string parameter, OpenIdConnectParameter value)> GetParameters(
            OpenIdConnectRequest request, AuthenticationProperties properties)
        {
            Debug.Assert(properties != null, "The authentication properties shouldn't be null.");

            Debug.Assert(request != null, "The request shouldn't be null.");
            Debug.Assert(request.IsAuthorizationRequest() || request.IsLogoutRequest() || request.IsTokenRequest(),
                "The request should be an authorization, logout or token request.");

            foreach (var property in properties.Items)
            {
                if (string.IsNullOrEmpty(property.Key))
                {
                    continue;
                }

                if (string.IsNullOrEmpty(property.Value))
                {
                    continue;
                }

                if (property.Key.EndsWith(OpenIddictConstants.PropertyTypes.Boolean))
                {
                    var name = property.Key.Substring(
                        /* index: */ 0,
                        /* length: */ property.Key.LastIndexOf(OpenIddictConstants.PropertyTypes.Boolean));

                    bool value;

                    try
                    {
                        value = bool.Parse(property.Value);
                    }

                    catch (Exception exception)
                    {
                        Logger.LogWarning(exception, "An error occurred while parsing the public property " +
                                                     "'{Name}' from the authentication ticket.", name);

                        continue;
                    }

                    yield return (property.Key, name, value);
                }

                else if (property.Key.EndsWith(OpenIddictConstants.PropertyTypes.Integer))
                {
                    var name = property.Key.Substring(
                        /* index: */ 0,
                        /* length: */ property.Key.LastIndexOf(OpenIddictConstants.PropertyTypes.Integer));

                    long value;

                    try
                    {
                        value = long.Parse(property.Value, CultureInfo.InvariantCulture);
                    }

                    catch (Exception exception)
                    {
                        Logger.LogWarning(exception, "An error occurred while parsing the public property " +
                                                     "'{Name}' from the authentication ticket.", name);

                        continue;
                    }

                    yield return (property.Key, name, value);
                }

                else if (property.Key.EndsWith(OpenIddictConstants.PropertyTypes.Json))
                {
                    var name = property.Key.Substring(
                        /* index: */ 0,
                        /* length: */ property.Key.LastIndexOf(OpenIddictConstants.PropertyTypes.Json));

                    if (request.IsAuthorizationRequest() || request.IsLogoutRequest())
                    {
                        Logger.LogWarning("The JSON property '{Name}' was excluded as it was not " +
                                          "compatible with the OpenID Connect response type.", name);

                        continue;
                    }

                    JToken value;

                    try
                    {
                        value = JToken.Parse(property.Value);
                    }

                    catch (Exception exception)
                    {
                        Logger.LogWarning(exception, "An error occurred while deserializing the public JSON " +
                                                     "property '{Name}' from the authentication ticket.", name);

                        continue;
                    }

                    yield return (property.Key, name, value);
                }

                else if (property.Key.EndsWith(OpenIddictConstants.PropertyTypes.String))
                {
                    var name = property.Key.Substring(
                        /* index: */ 0,
                        /* length: */ property.Key.LastIndexOf(OpenIddictConstants.PropertyTypes.String));

                    yield return (property.Key, name, property.Value);
                }

                continue;
            }
        }
    }
}