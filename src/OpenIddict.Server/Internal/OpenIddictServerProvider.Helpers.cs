/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using OpenIddict.Abstractions;

namespace OpenIddict.Server.Internal
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
    /// Note: this API supports the OpenIddict infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future minor releases.
    /// </summary>
    public sealed partial class OpenIddictServerProvider : OpenIdConnectServerProvider
    {
        private async Task CreateAuthorizationAsync(
            [NotNull] AuthenticationTicket ticket, [NotNull] OpenIddictServerOptions options,
            [NotNull] HttpContext context, [NotNull] OpenIdConnectRequest request)
        {
            var logger = GetLogger(context.RequestServices);
            var applicationManager = GetApplicationManager(context.RequestServices);
            var authorizationManager = GetAuthorizationManager(context.RequestServices);

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
                var application = await applicationManager.FindByClientIdAsync(request.ClientId);
                if (application == null)
                {
                    throw new InvalidOperationException("The application entry cannot be found in the database.");
                }

                descriptor.ApplicationId = await applicationManager.GetIdAsync(application);
            }

            var authorization = await authorizationManager.CreateAsync(descriptor);
            if (authorization != null)
            {
                var identifier = await authorizationManager.GetIdAsync(authorization);

                if (string.IsNullOrEmpty(request.ClientId))
                {
                    logger.LogInformation("An ad hoc authorization was automatically created and " +
                                          "associated with an unknown application: {Identifier}.", identifier);
                }

                else
                {
                    logger.LogInformation("An ad hoc authorization was automatically created and " +
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
            [NotNull] OpenIddictServerOptions options, [NotNull] HttpContext context,
            [NotNull] OpenIdConnectRequest request,
            [NotNull] ISecureDataFormat<AuthenticationTicket> format)
        {
            Debug.Assert(!(options.DisableTokenStorage && options.UseReferenceTokens),
                "Token storage cannot be disabled when using reference tokens.");

            Debug.Assert(type == OpenIdConnectConstants.TokenUsages.AccessToken ||
                         type == OpenIdConnectConstants.TokenUsages.AuthorizationCode ||
                         type == OpenIdConnectConstants.TokenUsages.RefreshToken,
                "Only authorization codes, access and refresh tokens should be created using this method.");

            var logger = GetLogger(context.RequestServices);
            var applicationManager = GetApplicationManager(context.RequestServices);
            var tokenManager = GetTokenManager(context.RequestServices);

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
                var application = await applicationManager.FindByClientIdAsync(request.ClientId);
                if (application == null)
                {
                    throw new InvalidOperationException("The application entry cannot be found in the database.");
                }

                descriptor.ApplicationId = await applicationManager.GetIdAsync(application);
            }

            // If a null value was returned by CreateAsync(), return immediately.

            // Note: the request cancellation token is deliberately not used here to ensure the caller
            // cannot prevent this operation from being executed by resetting the TCP connection.
            var token = await tokenManager.CreateAsync(descriptor);
            if (token == null)
            {
                return null;
            }

            // Throw an exception if the token identifier can't be resolved.
            var identifier = await tokenManager.GetIdAsync(token);
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
                logger.LogTrace("A new reference token was successfully generated and persisted " +
                                "in the database: {Token} ; {Claims} ; {Properties}.",
                                descriptor.ReferenceId, ticket.Principal.Claims, ticket.Properties.Items);

                return descriptor.ReferenceId;
            }

            return null;
        }

        private async Task<AuthenticationTicket> ReceiveTokenAsync(
            [NotNull] string type, [NotNull] string value,
            [NotNull] OpenIddictServerOptions options, [NotNull] HttpContext context,
            [NotNull] OpenIdConnectRequest request,
            [NotNull] ISecureDataFormat<AuthenticationTicket> format)
        {
            var logger = GetLogger(context.RequestServices);
            var tokenManager = GetTokenManager(context.RequestServices);

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
                token = await tokenManager.FindByReferenceIdAsync(value);
                if (token == null)
                {
                    logger.LogInformation("The reference token corresponding to the '{Identifier}' " +
                                          "reference identifier cannot be found in the database.", value);

                    return null;
                }

                // Optimization: avoid extracting/decrypting the token payload
                // (that relies on a format specific to the token type requested)
                // if the token type associated with the token entry isn't valid.
                var usage = await tokenManager.GetTypeAsync(token);
                if (string.IsNullOrEmpty(usage))
                {
                    logger.LogWarning("The token type associated with the received token cannot be retrieved. " +
                                      "This may indicate that the token entry is corrupted.");

                    return null;
                }

                if (!string.Equals(usage, type, StringComparison.OrdinalIgnoreCase))
                {
                    logger.LogWarning("The token type '{ActualType}' associated with the database entry doesn't match " +
                                      "the expected type: {ExpectedType}.", await tokenManager.GetTypeAsync(token), type);

                    return null;
                }

                identifier = await tokenManager.GetIdAsync(token);
                if (string.IsNullOrEmpty(identifier))
                {
                    logger.LogWarning("The identifier associated with the received token cannot be retrieved. " +
                                      "This may indicate that the token entry is corrupted.");

                    return null;
                }

                // Extract the encrypted payload from the token. If it's null or empty,
                // assume the token is not a reference token and consider it as invalid.
                var payload = await tokenManager.GetPayloadAsync(token);
                if (string.IsNullOrEmpty(payload))
                {
                    logger.LogWarning("The ciphertext associated with the token '{Identifier}' cannot be retrieved. " +
                                      "This may indicate that the token is not a reference token.", identifier);

                    return null;
                }

                ticket = format.Unprotect(payload);
                if (ticket == null)
                {
                    logger.LogWarning("The ciphertext associated with the token '{Identifier}' cannot be decrypted. " +
                                      "This may indicate that the token entry is corrupted or tampered.",
                                      await tokenManager.GetIdAsync(token));

                    return null;
                }
            }

            else if (type == OpenIdConnectConstants.TokenUsages.AuthorizationCode ||
                     type == OpenIdConnectConstants.TokenUsages.RefreshToken)
            {
                ticket = format.Unprotect(value);
                if (ticket == null)
                {
                    logger.LogTrace("The received token was invalid or malformed: {Token}.", value);

                    return null;
                }

                identifier = ticket.GetInternalTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    logger.LogWarning("The identifier associated with the received token cannot be retrieved. " +
                                      "This may indicate that the token entry is corrupted.");

                    return null;
                }

                token = await tokenManager.FindByIdAsync(identifier);
                if (token == null)
                {
                    logger.LogInformation("The token '{Identifier}' cannot be found in the database.", identifier);

                    return null;
                }
            }

            else
            {
                return null;
            }

            // Dynamically set the creation and expiration dates.
            ticket.Properties.IssuedUtc = await tokenManager.GetCreationDateAsync(token);
            ticket.Properties.ExpiresUtc = await tokenManager.GetExpirationDateAsync(token);

            // Restore the token/authorization identifiers using the identifiers attached with the database entry.
            ticket.SetInternalAuthorizationId(await tokenManager.GetAuthorizationIdAsync(token))
                  .SetInternalTokenId(identifier);

            logger.LogTrace("The token '{Identifier}' was successfully decrypted and " +
                            "retrieved from the database: {Claims} ; {Properties}.",
                            identifier, ticket.Principal.Claims, ticket.Properties.Items);

            return ticket;
        }

        private async Task<bool> TryRevokeAuthorizationAsync([NotNull] AuthenticationTicket ticket, [NotNull] HttpContext context)
        {
            var logger = GetLogger(context.RequestServices);
            var authorizationManager = GetAuthorizationManager(context.RequestServices);

            // Note: if the authorization identifier or the authorization itself
            // cannot be found, return true as the authorization doesn't need
            // to be revoked if it doesn't exist or is already invalid.
            var identifier = ticket.GetInternalAuthorizationId();
            if (string.IsNullOrEmpty(identifier))
            {
                return true;
            }

            var authorization = await authorizationManager.FindByIdAsync(identifier);
            if (authorization == null)
            {
                return true;
            }

            try
            {
                // Note: the request cancellation token is deliberately not used here to ensure the caller
                // cannot prevent this operation from being executed by resetting the TCP connection.
                await authorizationManager.RevokeAsync(authorization);

                logger.LogInformation("The authorization '{Identifier}' was automatically revoked.", identifier);

                return true;
            }

            catch (OpenIddictExceptions.ConcurrencyException exception)
            {
                logger.LogDebug(0, exception, "A concurrency exception occurred while trying to revoke the authorization " +
                                              "associated with the token '{Identifier}'.", identifier);

                return false;
            }

            catch (Exception exception)
            {
                logger.LogWarning(0, exception, "An exception occurred while trying to revoke the authorization " +
                                                "associated with the token '{Identifier}'.", identifier);

                return false;
            }
        }

        private async Task<bool> TryRevokeTokenAsync([NotNull] object token, [NotNull] HttpContext context)
        {
            var logger = GetLogger(context.RequestServices);
            var tokenManager = GetTokenManager(context.RequestServices);

            var identifier = await tokenManager.GetIdAsync(token);
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The token identifier shouldn't be null or empty.");

            try
            {
                // Note: the request cancellation token is deliberately not used here to ensure the caller
                // cannot prevent this operation from being executed by resetting the TCP connection.
                await tokenManager.RevokeAsync(token);

                logger.LogInformation("The token '{Identifier}' was automatically revoked.", identifier);

                return true;
            }

            catch (OpenIddictExceptions.ConcurrencyException exception)
            {
                logger.LogDebug(0, exception, "A concurrency exception occurred while trying to revoke the token '{Identifier}'.", identifier);

                return false;
            }

            catch (Exception exception)
            {
                logger.LogWarning(0, exception, "An exception occurred while trying to revoke the token '{Identifier}'.", identifier);

                return false;
            }
        }

        private async Task<bool> TryRevokeTokensAsync([NotNull] AuthenticationTicket ticket, [NotNull] HttpContext context)
        {
            var tokenManager = GetTokenManager(context.RequestServices);

            // Note: if the authorization identifier is null, return true as no tokens need to be revoked.
            var identifier = ticket.GetInternalAuthorizationId();
            if (string.IsNullOrEmpty(identifier))
            {
                return true;
            }

            var result = true;

            foreach (var token in await tokenManager.FindByAuthorizationIdAsync(identifier))
            {
                // Don't change the status of the token used in the token request.
                if (string.Equals(ticket.GetInternalTokenId(),
                    await tokenManager.GetIdAsync(token), StringComparison.Ordinal))
                {
                    continue;
                }

                result &= await TryRevokeTokenAsync(token, context);
            }

            return result;
        }

        private async Task<bool> TryRedeemTokenAsync([NotNull] object token, [NotNull] HttpContext context)
        {
            var logger = GetLogger(context.RequestServices);
            var tokenManager = GetTokenManager(context.RequestServices);

            var identifier = await tokenManager.GetIdAsync(token);
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The token identifier shouldn't be null or empty.");

            try
            {
                // Note: the request cancellation token is deliberately not used here to ensure the caller
                // cannot prevent this operation from being executed by resetting the TCP connection.
                await tokenManager.RedeemAsync(token);

                logger.LogInformation("The token '{Identifier}' was automatically marked as redeemed.", identifier);

                return true;
            }

            catch (OpenIddictExceptions.ConcurrencyException exception)
            {
                logger.LogDebug(0, exception, "A concurrency exception occurred while trying to redeem with the token '{Identifier}'.", identifier);

                return false;
            }

            catch (Exception exception)
            {
                logger.LogWarning(0, exception, "An exception occurred while trying to redeem the token '{Identifier}'.", identifier);

                return false;
            }
        }

        private async Task<bool> TryExtendRefreshTokenAsync(
            [NotNull] object token, [NotNull] AuthenticationTicket ticket,
            [NotNull] HttpContext context, [NotNull] OpenIddictServerOptions options)
        {
            var logger = GetLogger(context.RequestServices);
            var tokenManager = GetTokenManager(context.RequestServices);

            var identifier = ticket.GetInternalTokenId();
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The token identifier shouldn't be null or empty.");

            try
            {
                // Compute the new expiration date of the refresh token.
                var date = options.SystemClock.UtcNow + (ticket.GetRefreshTokenLifetime() ?? options.RefreshTokenLifetime);

                // Note: the request cancellation token is deliberately not used here to ensure the caller
                // cannot prevent this operation from being executed by resetting the TCP connection.
                await tokenManager.ExtendAsync(token, date);

                logger.LogInformation("The expiration date of the refresh token '{Identifier}' " +
                                      "was automatically updated: {Date}.", identifier, date);

                return true;
            }

            catch (OpenIddictExceptions.ConcurrencyException exception)
            {
                logger.LogDebug(0, exception, "A concurrency exception occurred while trying to update the " +
                                              "expiration date of the token '{Identifier}'.", identifier);

                return false;
            }

            catch (Exception exception)
            {
                logger.LogWarning(0, exception, "An exception occurred while trying to update the " +
                                                "expiration date of the token '{Identifier}'.", identifier);

                return false;
            }
        }

        private IEnumerable<Tuple<string, string, OpenIdConnectParameter>> GetParameters(
            [NotNull] HttpContext context, [NotNull] OpenIdConnectRequest request,
            [NotNull] AuthenticationProperties properties)
        {
            var logger = GetLogger(context.RequestServices);

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
                        logger.LogWarning(0, exception, "An error occurred while parsing the public property " +
                                                        "'{Name}' from the authentication ticket.", name);

                        continue;
                    }

                    yield return Tuple.Create(property.Key, name, new OpenIdConnectParameter(value));
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
                        logger.LogWarning(0, exception, "An error occurred while parsing the public property " +
                                                        "'{Name}' from the authentication ticket.", name);

                        continue;
                    }

                    yield return Tuple.Create(property.Key, name, new OpenIdConnectParameter(value));
                }

                else if (property.Key.EndsWith(OpenIddictConstants.PropertyTypes.Json))
                {
                    var name = property.Key.Substring(
                        startIndex: 0,
                        length: property.Key.LastIndexOf(OpenIddictConstants.PropertyTypes.Json));

                    if (request.IsAuthorizationRequest() || request.IsLogoutRequest())
                    {
                        logger.LogWarning("The JSON property '{Name}' was excluded as it was not " +
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
                        logger.LogWarning(0, exception, "An error occurred while deserializing the public JSON " +
                                                        "property '{Name}' from the authentication ticket.", name);

                        continue;
                    }

                    yield return Tuple.Create(property.Key, name, new OpenIdConnectParameter(value));
                }

                else if (property.Key.EndsWith(OpenIddictConstants.PropertyTypes.String))
                {
                    var name = property.Key.Substring(
                        startIndex: 0,
                        length: property.Key.LastIndexOf(OpenIddictConstants.PropertyTypes.String));

                    yield return Tuple.Create(property.Key, name, new OpenIdConnectParameter(property.Value));
                }

                continue;
            }
        }

        private static ILogger GetLogger(IServiceProvider provider)
            => provider.GetRequiredService<ILogger<OpenIddictServerProvider>>();

        private static IOpenIddictServerEventDispatcher GetEventDispatcher(IServiceProvider provider)
            => provider.GetRequiredService<IOpenIddictServerEventDispatcher>();

        private static IOpenIddictApplicationManager GetApplicationManager(IServiceProvider provider)
            => provider.GetService<IOpenIddictApplicationManager>() ?? throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the server handler.")
                .Append("To register the OpenIddict core services, use 'services.AddOpenIddict().AddCore()'.")
                .ToString());

        private static IOpenIddictAuthorizationManager GetAuthorizationManager(IServiceProvider provider)
            => provider.GetService<IOpenIddictAuthorizationManager>() ?? throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the server handler.")
                .Append("To register the OpenIddict core services, use 'services.AddOpenIddict().AddCore()'.")
                .ToString());

        private static IOpenIddictScopeManager GetScopeManager(IServiceProvider provider)
            => provider.GetService<IOpenIddictScopeManager>() ?? throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the server handler.")
                .Append("To register the OpenIddict core services, use 'services.AddOpenIddict().AddCore()'.")
                .ToString());

        private static IOpenIddictTokenManager GetTokenManager(IServiceProvider provider)
            => provider.GetService<IOpenIddictTokenManager>() ?? throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the server handler.")
                .Append("To register the OpenIddict core services, use 'services.AddOpenIddict().AddCore()'.")
                .ToString());

    }
}
