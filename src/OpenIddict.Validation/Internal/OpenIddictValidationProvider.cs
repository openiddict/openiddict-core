/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OAuth.Validation;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace OpenIddict.Validation.Internal
{
    /// <summary>
    /// Provides the logic necessary to extract and validate tokens from HTTP requests.
    /// Note: this API supports the OpenIddict infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future minor releases.
    /// </summary>
    public sealed class OpenIddictValidationProvider : OAuthValidationEvents
    {
        public override Task ApplyChallenge([NotNull] ApplyChallengeContext context)
            => GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictValidationEvents.ApplyChallenge(context));

        public override Task CreateTicket([NotNull] CreateTicketContext context)
            => GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictValidationEvents.CreateTicket(context));

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

                var logger = GetLogger(context.HttpContext.RequestServices);

                // Retrieve the token entry from the database. If it
                // cannot be found, assume the token is not valid.
                var token = await manager.FindByReferenceIdAsync(context.Token);
                if (token == null)
                {
                    logger.LogError("Authentication failed because the access token cannot be found in the database.");

                    context.HandleResponse();
                    return;
                }

                // Extract the encrypted payload from the token. If it's null or empty,
                // assume the token is not a reference token and consider it as invalid.
                var payload = await manager.GetPayloadAsync(token);
                if (string.IsNullOrEmpty(payload))
                {
                    logger.LogError("Authentication failed because the access token is not a reference token.");

                    context.HandleResponse();
                    return;
                }

                // Ensure the access token is still valid (i.e was not marked as revoked).
                if (!await manager.IsValidAsync(token))
                {
                    logger.LogError("Authentication failed because the access token was no longer valid.");

                    context.HandleResponse();
                    return;
                }

                var ticket = context.DataFormat.Unprotect(payload);
                if (ticket == null)
                {
                    logger.LogError("Authentication failed because the reference token cannot be decrypted. " +
                                    "This may indicate that the token entry is corrupted or tampered.");

                    context.HandleResponse();
                    return;
                }

                // Dynamically set the creation and expiration dates.
                ticket.Properties.IssuedUtc = await manager.GetCreationDateAsync(token);
                ticket.Properties.ExpiresUtc = await manager.GetExpirationDateAsync(token);

                // Restore the token and authorization identifiers attached with the database entry.
                ticket.Properties.SetProperty(OpenIddictConstants.Properties.InternalTokenId, await manager.GetIdAsync(token));
                ticket.Properties.SetProperty(OpenIddictConstants.Properties.InternalAuthorizationId,
                    await manager.GetAuthorizationIdAsync(token));

                context.Ticket = ticket;
                context.HandleResponse();
            }

            await GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictValidationEvents.DecryptToken(context));
        }

        public override Task RetrieveToken([NotNull] RetrieveTokenContext context)
            => GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictValidationEvents.RetrieveToken(context));

        public override async Task ValidateToken([NotNull] ValidateTokenContext context)
        {
            var options = (OpenIddictValidationOptions) context.Options;
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

                var logger = GetLogger(context.HttpContext.RequestServices);

                var identifier = context.Ticket.Properties.GetProperty(OpenIddictConstants.Properties.InternalAuthorizationId);
                if (!string.IsNullOrEmpty(identifier))
                {
                    var authorization = await manager.FindByIdAsync(identifier);
                    if (authorization == null || !await manager.IsValidAsync(authorization))
                    {
                        logger.LogError("Authentication failed because the authorization " +
                                        "associated with the access token was not longer valid.");

                        context.Ticket = null;
                        return;
                    }
                }
            }

            await GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictValidationEvents.ValidateToken(context));
        }

        private static ILogger GetLogger(IServiceProvider provider)
            => provider.GetRequiredService<ILogger<OpenIddictValidationProvider>>();

        private static IOpenIddictValidationEventService GetEventService(IServiceProvider provider)
            => provider.GetRequiredService<IOpenIddictValidationEventService>();
    }
}
