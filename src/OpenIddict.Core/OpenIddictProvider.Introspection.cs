/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpenIddict {
    public partial class OpenIddictProvider<TUser, TApplication> : OpenIdConnectServerProvider where TUser : class where TApplication : class {
        public override async Task ValidateIntrospectionRequest([NotNull] ValidateIntrospectionRequestContext context) {
            var manager = context.HttpContext.RequestServices.GetRequiredService<OpenIddictManager<TUser, TApplication>>();

            // Note: ASOS supports both GET and POST introspection requests but OpenIddict only accepts POST requests.
            if (!string.Equals(context.HttpContext.Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
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
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Clients must be authenticated to use the introspection endpoint.");

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await manager.FindApplicationByIdAsync(context.ClientId);
            if (application == null) {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct.");

                return;
            }

            // Reject non-confidential applications.
            if (await manager.IsPublicApplicationAsync(application)) {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Public applications are not allowed to use the introspection endpoint.");

                return;
            }

            // Validate the client credentials.
            if (!await manager.ValidateSecretAsync(application, context.ClientSecret)) {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid credentials: ensure that you specified a correct client_secret.");

                return;
            }

            context.Validate();
        }

        public override async Task HandleIntrospectionRequest([NotNull] HandleIntrospectionRequestContext context) {
            var manager = context.HttpContext.RequestServices.GetRequiredService<OpenIddictManager<TUser, TApplication>>();
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<IdentityOptions>>();

            // If the user manager doesn't support security
            // stamps, skip the additional validation logic.
            if (!manager.SupportsUserSecurityStamp) {
                return;
            }

            var principal = context.Ticket?.Principal;
            Debug.Assert(principal != null);

            var user = await manager.GetUserAsync(principal);
            if (user == null) {
                context.Active = false;

                return;
            }

            var identifier = principal.GetClaim(options.Value.ClaimsIdentity.SecurityStampClaimType);
            if (!string.IsNullOrEmpty(identifier) &&
                !string.Equals(identifier, await manager.GetSecurityStampAsync(user), StringComparison.Ordinal)) {
                context.Active = false;

                return;
            }
        }
    }
}