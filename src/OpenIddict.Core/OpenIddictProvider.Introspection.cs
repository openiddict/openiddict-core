/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict {
    public partial class OpenIddictProvider<TUser, TApplication> : OpenIdConnectServerProvider where TUser : class where TApplication : class {
        public override async Task ValidateIntrospectionRequest([NotNull] ValidateIntrospectionRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TUser, TApplication>>>();

            // Note: ASOS supports both GET and POST introspection requests but OpenIddict only accepts POST requests.
            if (!string.Equals(context.HttpContext.Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                logger.LogWarning("The method '{Method}' is not supported for introspection request.", context.HttpContext.Request.Method);
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Introspection requests must use HTTP POST.");

                return;
            }

            // Note: ASOS supports unauthenticated introspection requests but OpenIddict uses
            // a stricter policy preventing unauthenticated/public applications from using
            // the introspection endpoint, as required by the specifications.
            // See https://tools.ietf.org/html/rfc7662 for more information.
            if (string.IsNullOrEmpty(context.ClientId) || string.IsNullOrEmpty(context.ClientSecret)) {
                logger.LogWarning("Unsupported introspection request from unauthenticated application client_id '{ClientId}'.", context.ClientId);
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Clients must be authenticated to use the introspection endpoint.");

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await services.Applications.FindApplicationByIdAsync(context.ClientId);
            if (application == null) {
                logger.LogDebug("There was an error finding application for client_id '{ClientId}', the current application is null.", context.ClientId);
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct.");

                return;
            }

            // Reject non-confidential applications.
            if (await services.Applications.IsPublicApplicationAsync(application)) {
                logger.LogDebug("Public application '{ClientId}' is not allowed to use the introspection endpoint.", context.ClientId);
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Public applications are not allowed to use the introspection endpoint.");

                return;
            }

            // Validate the client credentials.
            if (!await services.Applications.ValidateSecretAsync(application, context.ClientSecret)) {
                logger.LogDebug("Failed to validate credentials from application '{ClientId}', ensure that you specified a correct client_secret.", context.ClientId);
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid credentials: ensure that you specified a correct client_secret.");

                return;
            }

            context.Validate();
            logger.LogInformation("The introspection request was successfully validated.");
        }

        public override async Task HandleIntrospectionRequest([NotNull] HandleIntrospectionRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<IdentityOptions>>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TUser, TApplication>>>();

            // If the user manager doesn't support security
            // stamps, skip the additional validation logic.
            if (!services.Users.SupportsUserSecurityStamp) {
                logger.LogDebug("The current provider does not supports user security stamps, skipping introspection request.");
                return;
            }

            var principal = context.Ticket?.Principal;
            if (principal == null) {
                logger.LogDebug("The AuthenticationTicket's principal is null, throwing exception.");
                throw new InvalidOperationException("The current principal is null");
            }

            var user = await services.Users.GetUserAsync(principal);
            if (user == null) {
                logger.LogWarning("Unable to retrieve user from the current principal '{NameIdentifier}', ensure the user was not removed from the database.", principal.FindFirstValue(ClaimTypes.NameIdentifier));
                context.Active = false;
                return;
            }

            var identifier = principal.GetClaim(options.Value.ClaimsIdentity.SecurityStampClaimType);
            if (!string.IsNullOrEmpty(identifier) &&
                !string.Equals(identifier, await services.Users.GetSecurityStampAsync(user), StringComparison.Ordinal)) {
                context.Active = false;
                logger.LogWarning("Security stamp does not match for the user '{NameIdentifier}'.", principal.FindFirstValue(ClaimTypes.NameIdentifier));
                return;
            }

            logger.LogInformation("The introspection request was successfully handled.");
        }
    }
}