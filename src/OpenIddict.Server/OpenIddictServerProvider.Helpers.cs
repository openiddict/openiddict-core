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
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using OpenIddict.Abstractions;

namespace OpenIddict.Server
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
    /// </summary>
    internal sealed partial class OpenIddictServerProvider : OpenIdConnectServerProvider
    {
        private async Task CreateAuthorizationAsync([NotNull] AuthenticationTicket ticket,
            [NotNull] OpenIddictServerOptions options, [NotNull] OpenIdConnectRequest request)
        {
            var descriptor = new OpenIddictAuthorizationDescriptor
            {
                Principal = ticket.Principal,
                Status = OpenIddictConstants.Statuses.Valid,
                Subject = ticket.Principal.GetClaim(OpenIddictConstants.Claims.Subject),
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
                var application = await _applicationManager.FindByClientIdAsync(request.ClientId);
                if (application == null)
                {
                    throw new InvalidOperationException("The application entry cannot be found in the database.");
                }

                descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
            }

            var authorization = await _authorizationManager.CreateAsync(descriptor);
            if (authorization != null)
            {
                var identifier = await _authorizationManager.GetIdAsync(authorization);

                if (string.IsNullOrEmpty(request.ClientId))
                {
                    _logger.LogInformation("An ad hoc authorization was automatically created and " +
                                           "associated with an unknown application: {Identifier}.", identifier);
                }

                else
                {
                    _logger.LogInformation("An ad hoc authorization was automatically created and " +
                                           "associated with the '{ClientId}' application: {Identifier}.",
                                           request.ClientId, identifier);
                }

                // Attach the unique identifier of the ad hoc authorization to the authentication ticket
                // so that it is attached to all the derived tokens, allowing batched revocations support.
                ticket.SetInternalAuthorizationId(identifier);
            }
        }

        private async Task<string> CreateTokenAsync(
            [NotNull] string type, [NotNull] AuthenticationTicket ticket,
            [NotNull] OpenIddictServerOptions options,
            [NotNull] OpenIdConnectRequest request,
            [NotNull] ISecureDataFormat<AuthenticationTicket> format)
        {
            Debug.Assert(!(options.DisableTokenStorage && options.UseReferenceTokens),
                "Token storage cannot be disabled when using reference tokens.");

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

            if (options.DisableTokenStorage)
            {
                return null;
            }

            var descriptor = new OpenIddictTokenDescriptor
            {
                AuthorizationId = ticket.GetInternalAuthorizationId(),
                CreationDate = ticket.Properties.IssuedUtc,
                ExpirationDate = ticket.Properties.ExpiresUtc,
                Principal = ticket.Principal,
                Status = OpenIddictConstants.Statuses.Valid,
                Subject = ticket.Principal.GetClaim(OpenIddictConstants.Claims.Subject),
                Type = type
            };

            foreach (var property in ticket.Properties.Items)
            {
                descriptor.Properties.Add(property);
            }

            // When reference tokens are enabled or when the token is an authorization code or a
            // refresh token, remove the unnecessary properties from the authentication ticket.
            if (options.UseReferenceTokens ||
               (type == OpenIdConnectConstants.TokenUsages.AuthorizationCode ||
                type == OpenIdConnectConstants.TokenUsages.RefreshToken))
            {
                ticket.Properties.IssuedUtc = ticket.Properties.ExpiresUtc = null;
                ticket.RemoveProperty(OpenIddictConstants.Properties.InternalAuthorizationId)
                      .RemoveProperty(OpenIddictConstants.Properties.InternalTokenId);
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

                // Note: the default token manager automatically obfuscates the
                // reference identifier so it can be safely stored in the databse.
                descriptor.ReferenceId = Base64UrlEncoder.Encode(bytes);
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
                var application = await _applicationManager.FindByClientIdAsync(request.ClientId);
                if (application == null)
                {
                    throw new InvalidOperationException("The application entry cannot be found in the database.");
                }

                descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
            }

            // If a null value was returned by CreateAsync(), return immediately.

            // Note: the request cancellation token is deliberately not used here to ensure the caller
            // cannot prevent this operation from being executed by resetting the TCP connection.
            var token = await _tokenManager.CreateAsync(descriptor);
            if (token == null)
            {
                return null;
            }

            // Throw an exception if the token identifier can't be resolved.
            var identifier = await _tokenManager.GetIdAsync(token);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException("The unique key associated with a refresh token cannot be null or empty.");
            }

            // Dynamically set the creation and expiration dates.
            ticket.Properties.IssuedUtc = descriptor.CreationDate;
            ticket.Properties.ExpiresUtc = descriptor.ExpirationDate;

            // Restore the token/authorization identifiers using the identifiers attached with the database entry.
            ticket.SetInternalAuthorizationId(descriptor.AuthorizationId)
                  .SetInternalTokenId(identifier);

            if (options.UseReferenceTokens)
            {
                _logger.LogTrace("A new reference token was successfully generated and persisted " +
                                 "in the database: {Token} ; {Claims} ; {Properties}.",
                                 descriptor.ReferenceId, ticket.Principal.Claims, ticket.Properties.Items);

                return descriptor.ReferenceId;
            }

            return null;
        }

        private async Task<AuthenticationTicket> ReceiveTokenAsync(
            [NotNull] string type, [NotNull] string value,
            [NotNull] OpenIddictServerOptions options,
            [NotNull] OpenIdConnectRequest request,
            [NotNull] ISecureDataFormat<AuthenticationTicket> format)
        {
            Debug.Assert(!(options.DisableTokenStorage && options.UseReferenceTokens),
                "Token revocation cannot be disabled when using reference tokens.");

            Debug.Assert(type == OpenIdConnectConstants.TokenUsages.AccessToken ||
                         type == OpenIdConnectConstants.TokenUsages.AuthorizationCode ||
                         type == OpenIdConnectConstants.TokenUsages.RefreshToken,
                "Only authorization codes, access and refresh tokens should be validated using this method.");

            string identifier;
            AuthenticationTicket ticket;
            object token;

            if (options.UseReferenceTokens)
            {
                token = await _tokenManager.FindByReferenceIdAsync(value);
                if (token == null)
                {
                    _logger.LogInformation("The reference token corresponding to the '{Identifier}' " +
                                           "reference identifier cannot be found in the database.", value);

                    return null;
                }

                // Optimization: avoid extracting/decrypting the token payload
                // (that relies on a format specific to the token type requested)
                // if the token type associated with the token entry isn't valid.
                var usage = await _tokenManager.GetTypeAsync(token);
                if (string.IsNullOrEmpty(usage))
                {
                    _logger.LogWarning("The token type associated with the received token cannot be retrieved. " +
                                       "This may indicate that the token entry is corrupted.");

                    return null;
                }

                if (!string.Equals(usage, type, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("The token type '{ActualType}' associated with the database entry doesn't match " +
                                       "the expected type: {ExpectedType}.", await _tokenManager.GetTypeAsync(token), type);

                    return null;
                }

                identifier = await _tokenManager.GetIdAsync(token);
                if (string.IsNullOrEmpty(identifier))
                {
                    _logger.LogWarning("The identifier associated with the received token cannot be retrieved. " +
                                       "This may indicate that the token entry is corrupted.");

                    return null;
                }

                // Extract the encrypted payload from the token. If it's null or empty,
                // assume the token is not a reference token and consider it as invalid.
                var payload = await _tokenManager.GetPayloadAsync(token);
                if (string.IsNullOrEmpty(payload))
                {
                    _logger.LogWarning("The ciphertext associated with the token '{Identifier}' cannot be retrieved. " +
                                       "This may indicate that the token is not a reference token.", identifier);

                    return null;
                }

                ticket = format.Unprotect(payload);
                if (ticket == null)
                {
                    _logger.LogWarning("The ciphertext associated with the token '{Identifier}' cannot be decrypted. " +
                                       "This may indicate that the token entry is corrupted or tampered.",
                                       await _tokenManager.GetIdAsync(token));

                    return null;
                }
            }

            else if (type == OpenIdConnectConstants.TokenUsages.AuthorizationCode ||
                     type == OpenIdConnectConstants.TokenUsages.RefreshToken)
            {
                ticket = format.Unprotect(value);
                if (ticket == null)
                {
                    _logger.LogTrace("The received token was invalid or malformed: {Token}.", value);

                    return null;
                }

                identifier = ticket.GetInternalTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    _logger.LogWarning("The identifier associated with the received token cannot be retrieved. " +
                                       "This may indicate that the token entry is corrupted.");

                    return null;
                }

                token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null)
                {
                    _logger.LogInformation("The token '{Identifier}' cannot be found in the database.", identifier);

                    return null;
                }
            }

            else
            {
                return null;
            }

            // Dynamically set the creation and expiration dates.
            ticket.Properties.IssuedUtc = await _tokenManager.GetCreationDateAsync(token);
            ticket.Properties.ExpiresUtc = await _tokenManager.GetExpirationDateAsync(token);

            // Restore the token/authorization identifiers using the identifiers attached with the database entry.
            ticket.SetInternalAuthorizationId(await _tokenManager.GetAuthorizationIdAsync(token))
                  .SetInternalTokenId(identifier);

            _logger.LogTrace("The token '{Identifier}' was successfully decrypted and " +
                             "retrieved from the database: {Claims} ; {Properties}.",
                             identifier, ticket.Principal.Claims, ticket.Properties.Items);

            return ticket;
        }

        private async Task<bool> TryRevokeAuthorizationAsync([NotNull] AuthenticationTicket ticket)
        {
            // Note: if the authorization identifier or the authorization itself
            // cannot be found, return true as the authorization doesn't need
            // to be revoked if it doesn't exist or is already invalid.
            var identifier = ticket.GetInternalAuthorizationId();
            if (string.IsNullOrEmpty(identifier))
            {
                return true;
            }

            var authorization = await _authorizationManager.FindByIdAsync(identifier);
            if (authorization == null)
            {
                return true;
            }

            try
            {
                // Note: the request cancellation token is deliberately not used here to ensure the caller
                // cannot prevent this operation from being executed by resetting the TCP connection.
                await _authorizationManager.RevokeAsync(authorization);

                _logger.LogInformation("The authorization '{Identifier}' was automatically revoked.", identifier);

                return true;
            }

            catch (OpenIddictExceptions.ConcurrencyException exception)
            {
                _logger.LogDebug(exception, "A concurrency exception occurred while trying to revoke the authorization " +
                                            "associated with the token '{Identifier}'.", identifier);

                return false;
            }

            catch (Exception exception)
            {
                _logger.LogWarning(exception, "An exception occurred while trying to revoke the authorization " +
                                              "associated with the token '{Identifier}'.", identifier);

                return false;
            }
        }

        private async Task<bool> TryRevokeTokenAsync([NotNull] object token)
        {
            var identifier = await _tokenManager.GetIdAsync(token);
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The token identifier shouldn't be null or empty.");

            try
            {
                // Note: the request cancellation token is deliberately not used here to ensure the caller
                // cannot prevent this operation from being executed by resetting the TCP connection.
                await _tokenManager.RevokeAsync(token);

                _logger.LogInformation("The token '{Identifier}' was automatically revoked.", identifier);

                return true;
            }

            catch (OpenIddictExceptions.ConcurrencyException exception)
            {
                _logger.LogDebug(exception, "A concurrency exception occurred while trying to revoke the token '{Identifier}'.", identifier);

                return false;
            }

            catch (Exception exception)
            {
                _logger.LogWarning(exception, "An exception occurred while trying to revoke the token '{Identifier}'.", identifier);

                return false;
            }
        }

        private async Task<bool> TryRevokeTokensAsync([NotNull] AuthenticationTicket ticket)
        {
            // Note: if the authorization identifier is null, return true as no tokens need to be revoked.
            var identifier = ticket.GetInternalAuthorizationId();
            if (string.IsNullOrEmpty(identifier))
            {
                return true;
            }

            var result = true;

            foreach (var token in await _tokenManager.FindByAuthorizationIdAsync(identifier))
            {
                // Don't change the status of the token used in the token request.
                if (string.Equals(ticket.GetInternalTokenId(),
                    await _tokenManager.GetIdAsync(token), StringComparison.Ordinal))
                {
                    continue;
                }

                result &= await TryRevokeTokenAsync(token);
            }

            return result;
        }

        private async Task<bool> TryRedeemTokenAsync([NotNull] object token)
        {
            var identifier = await _tokenManager.GetIdAsync(token);
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The token identifier shouldn't be null or empty.");

            try
            {
                // Note: the request cancellation token is deliberately not used here to ensure the caller
                // cannot prevent this operation from being executed by resetting the TCP connection.
                await _tokenManager.RedeemAsync(token);

                _logger.LogInformation("The token '{Identifier}' was automatically marked as redeemed.", identifier);

                return true;
            }

            catch (OpenIddictExceptions.ConcurrencyException exception)
            {
                _logger.LogDebug(exception, "A concurrency exception occurred while trying to redeem with the token '{Identifier}'.", identifier);

                return false;
            }

            catch (Exception exception)
            {
                _logger.LogWarning(exception, "An exception occurred while trying to redeem the token '{Identifier}'.", identifier);

                return false;
            }
        }

        private async Task<bool> TryExtendRefreshTokenAsync(
            [NotNull] object token, [NotNull] AuthenticationTicket ticket, [NotNull] OpenIddictServerOptions options)
        {
            var identifier = ticket.GetInternalTokenId();
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The token identifier shouldn't be null or empty.");

            try
            {
                // Compute the new expiration date of the refresh token.
                var lifetime = ticket.GetRefreshTokenLifetime() ?? options.RefreshTokenLifetime;
                if (lifetime != null)
                {
                    // Note: the request cancellation token is deliberately not used here to ensure the caller
                    // cannot prevent this operation from being executed by resetting the TCP connection.
                    var date = options.SystemClock.UtcNow + lifetime.Value;
                    await _tokenManager.ExtendAsync(token, date);

                    _logger.LogInformation("The expiration date of the refresh token '{Identifier}' " +
                                           "was automatically updated: {Date}.", identifier, date);
                }

                else if (await _tokenManager.GetExpirationDateAsync(token) != null)
                {
                    // Note: the request cancellation token is deliberately not used here to ensure the caller
                    // cannot prevent this operation from being executed by resetting the TCP connection.
                    await _tokenManager.ExtendAsync(token, date: null);

                    _logger.LogInformation("The expiration date of the refresh token '{Identifier}' was removed.", identifier);
                }

                return true;
            }

            catch (OpenIddictExceptions.ConcurrencyException exception)
            {
                _logger.LogDebug(exception, "A concurrency exception occurred while trying to update the " +
                                            "expiration date of the token '{Identifier}'.", identifier);

                return false;
            }

            catch (Exception exception)
            {
                _logger.LogWarning(exception, "An exception occurred while trying to update the " +
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
                        startIndex: 0,
                        length: property.Key.LastIndexOf(OpenIddictConstants.PropertyTypes.Boolean));

                    bool value;

                    try
                    {
                        value = bool.Parse(property.Value);
                    }

                    catch (Exception exception)
                    {
                        _logger.LogWarning(exception, "An error occurred while parsing the public property " +
                                                      "'{Name}' from the authentication ticket.", name);

                        continue;
                    }

                    yield return (property.Key, name, value);
                }

                else if (property.Key.EndsWith(OpenIddictConstants.PropertyTypes.Integer))
                {
                    var name = property.Key.Substring(
                        startIndex: 0,
                        length: property.Key.LastIndexOf(OpenIddictConstants.PropertyTypes.Integer));

                    long value;

                    try
                    {
                        value = long.Parse(property.Value, CultureInfo.InvariantCulture);
                    }

                    catch (Exception exception)
                    {
                        _logger.LogWarning(exception, "An error occurred while parsing the public property " +
                                                      "'{Name}' from the authentication ticket.", name);

                        continue;
                    }

                    yield return (property.Key, name, value);
                }

                else if (property.Key.EndsWith(OpenIddictConstants.PropertyTypes.Json))
                {
                    var name = property.Key.Substring(
                        startIndex: 0,
                        length: property.Key.LastIndexOf(OpenIddictConstants.PropertyTypes.Json));

                    if (request.IsAuthorizationRequest() || request.IsLogoutRequest())
                    {
                        _logger.LogWarning("The JSON property '{Name}' was excluded as it was not " +
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
                        _logger.LogWarning(exception, "An error occurred while deserializing the public JSON " +
                                                      "property '{Name}' from the authentication ticket.", name);

                        continue;
                    }

                    yield return (property.Key, name, value);
                }

                else if (property.Key.EndsWith(OpenIddictConstants.PropertyTypes.String))
                {
                    var name = property.Key.Substring(
                        startIndex: 0,
                        length: property.Key.LastIndexOf(OpenIddictConstants.PropertyTypes.String));

                    yield return (property.Key, name, property.Value);
                }

                continue;
            }
        }
    }
}
