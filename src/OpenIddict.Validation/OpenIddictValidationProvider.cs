/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OAuth.Validation;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Provides the logic necessary to extract and validate tokens from HTTP requests.
    /// Note: this API supports the OpenIddict infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future minor releases.
    /// </summary>
    internal sealed class OpenIddictValidationProvider : OAuthValidationEvents
    {
        private readonly IOpenIddictValidationEventDispatcher _eventDispatcher;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictValidationProvider"/> class.
        /// Note: this API supports the OpenIddict infrastructure and is not intended to be used
        /// directly from your code. This API may change or be removed in future minor releases.
        /// </summary>
        public OpenIddictValidationProvider([NotNull] IOpenIddictValidationEventDispatcher eventDispatcher)
            => _eventDispatcher = eventDispatcher;

        public override Task ApplyChallenge([NotNull] ApplyChallengeContext context)
            => _eventDispatcher.DispatchAsync(new OpenIddictValidationEvents.ApplyChallenge(context));

        public override Task CreateTicket([NotNull] CreateTicketContext context)
            => _eventDispatcher.DispatchAsync(new OpenIddictValidationEvents.CreateTicket(context));

        public override async Task DecryptToken([NotNull] DecryptTokenContext context)
        {
            var options = (OpenIddictValidationOptions) context.Options;
            if (options.UseReferenceTokens)
            {
                // Note: the token manager is deliberately not injected using constructor injection
                // to allow using the validation handler without having to register the core services.
                var manager = context.HttpContext.RequestServices.GetService<IOpenIddictTokenManager>();
                if (manager == null)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The core services must be registered when enabling reference tokens support.")
                        .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                        .Append("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                        .ToString());
                }

                // Retrieve the token entry from the database. If it
                // cannot be found, assume the token is not valid.
                var token = await manager.FindByReferenceIdAsync(context.Token);
                if (token == null)
                {
                    context.Fail("Authentication failed because the access token cannot be found in the database.");

                    return;
                }

                // Optimization: avoid extracting/decrypting the token payload if the token is not an access token.
                var type = await manager.GetTypeAsync(token);
                if (string.IsNullOrEmpty(type))
                {
                    context.Fail("Authentication failed because the token type associated with the entry is missing.");

                    return;
                }

                if (!string.Equals(type, OpenIddictConstants.TokenTypes.AccessToken, StringComparison.OrdinalIgnoreCase))
                {
                    context.Fail("Authentication failed because the specified token is not an access token.");

                    return;
                }

                // Extract the encrypted payload from the token. If it's null or empty,
                // assume the token is not a reference token and consider it as invalid.
                var payload = await manager.GetPayloadAsync(token);
                if (string.IsNullOrEmpty(payload))
                {
                    context.Fail("Authentication failed because the access token is not a reference token.");

                    return;
                }

                var ticket = context.DataFormat.Unprotect(payload);
                if (ticket == null)
                {
                    context.Fail("Authentication failed because the reference token cannot be decrypted. " +
                                 "This may indicate that the token entry is corrupted or tampered.");

                    return;
                }

                // Dynamically set the creation and expiration dates.
                ticket.Properties.IssuedUtc = await manager.GetCreationDateAsync(token);
                ticket.Properties.ExpiresUtc = await manager.GetExpirationDateAsync(token);

                // Restore the token and authorization identifiers attached with the database entry.
                ticket.Properties.SetProperty(OpenIddictConstants.Properties.InternalTokenId, await manager.GetIdAsync(token));
                ticket.Properties.SetProperty(OpenIddictConstants.Properties.InternalAuthorizationId,
                    await manager.GetAuthorizationIdAsync(token));

                context.Principal = ticket.Principal;
                context.Properties = ticket.Properties;
                context.Success();
            }

            await _eventDispatcher.DispatchAsync(new OpenIddictValidationEvents.DecryptToken(context));
        }

        public override Task RetrieveToken([NotNull] RetrieveTokenContext context)
            => _eventDispatcher.DispatchAsync(new OpenIddictValidationEvents.RetrieveToken(context));

        public override async Task ValidateToken([NotNull] ValidateTokenContext context)
        {
            var options = (OpenIddictValidationOptions) context.Options;
            if (options.UseReferenceTokens)
            {
                // Note: the token manager is deliberately not injected using constructor injection
                // to allow using the validation handler without having to register the core services.
                var manager = context.HttpContext.RequestServices.GetService<IOpenIddictTokenManager>();
                if (manager == null)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The core services must be registered when enabling reference tokens support.")
                        .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                        .Append("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                        .ToString());
                }

                var identifier = context.Properties.GetProperty(OpenIddictConstants.Properties.InternalTokenId);
                Debug.Assert(!string.IsNullOrEmpty(identifier), "The authentication ticket should contain a token identifier.");

                // Ensure the access token is still valid (i.e was not marked as revoked).
                var token = await manager.FindByIdAsync(identifier);
                if (token == null || !await manager.IsValidAsync(token))
                {
                    context.Fail("Authentication failed because the access token was no longer valid.");

                    return;
                }
            }

            if (options.EnableAuthorizationValidation)
            {
                // Note: the authorization manager is deliberately not injected using constructor injection
                // to allow using the validation handler without having to register the OpenIddict core services.
                var manager = context.HttpContext.RequestServices.GetService<IOpenIddictAuthorizationManager>();
                if (manager == null)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The core services must be registered when enabling authorization validation.")
                        .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                        .Append("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                        .ToString());
                }

                var identifier = context.Properties.GetProperty(OpenIddictConstants.Properties.InternalAuthorizationId);
                if (!string.IsNullOrEmpty(identifier))
                {
                    var authorization = await manager.FindByIdAsync(identifier);
                    if (authorization == null || !await manager.IsValidAsync(authorization))
                    {
                        context.Fail("Authentication failed because the authorization " +
                                     "associated with the access token was not longer valid.");

                        return;
                    }
                }
            }

            await _eventDispatcher.DispatchAsync(new OpenIddictValidationEvents.ValidateToken(context));
        }
    }
}
