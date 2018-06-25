/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OAuth.Validation;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OAuth2 requests.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictValidationProvider : OAuthValidationEvents
    {
        private readonly IOpenIddictValidationEventService _eventService;

        public OpenIddictValidationProvider([NotNull] IOpenIddictValidationEventService eventService)
            => _eventService = eventService;

        public override Task ApplyChallenge([NotNull] ApplyChallengeContext context)
            => _eventService.PublishAsync(new OpenIddictValidationEvents.ApplyChallenge(context));

        public override Task CreateTicket([NotNull] CreateTicketContext context)
            => _eventService.PublishAsync(new OpenIddictValidationEvents.CreateTicket(context));

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
                        .Append("To register the OpenIddict core services, use 'services.AddOpenIddict().AddCore()'.")
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

            await _eventService.PublishAsync(new OpenIddictValidationEvents.DecryptToken(context));
        }

        public override Task RetrieveToken([NotNull] RetrieveTokenContext context)
            => _eventService.PublishAsync(new OpenIddictValidationEvents.RetrieveToken(context));

        public override Task ValidateToken([NotNull] ValidateTokenContext context)
            => _eventService.PublishAsync(new OpenIddictValidationEvents.ValidateToken(context));
    }
}
