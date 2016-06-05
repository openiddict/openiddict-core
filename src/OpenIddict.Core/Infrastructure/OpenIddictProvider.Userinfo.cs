/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json.Linq;

namespace OpenIddict.Infrastructure {
    public partial class OpenIddictProvider<TUser, TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TUser : class where TApplication : class where TAuthorization : class where TScope : class where TToken : class {
        public override async Task HandleUserinfoRequest([NotNull] HandleUserinfoRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>>();

            // Note: user may be null if the user was removed after
            // the initial check made by ValidateUserinfoRequest.
            // In this case, throw an exception to abort the request.
            var user = await services.Users.GetUserAsync(context.Ticket.Principal);
            if (user == null) {
                throw new InvalidOperationException("The userinfo request was aborted because the user profile " +
                                                    "corresponding to the access token was not found in the database.");
            }

            // Note: "sub" is a mandatory claim.
            // See http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
            context.Subject = await services.Users.GetUserIdAsync(user);

            // Only add the "preferred_username" claim if the "profile" scope was present in the access token.
            // Note: filtering the username is not needed at this stage as OpenIddictController.Accept
            // and OpenIddictProvider.GrantResourceOwnerCredentials are expected to reject requests that
            // don't include the "email" scope if the username corresponds to the registered email address.
            if (context.Ticket.HasScope(OpenIdConnectConstants.Scopes.Profile)) {
                context.PreferredUsername = await services.Users.GetUserNameAsync(user);

                if (services.Users.SupportsUserClaim) {
                    context.FamilyName = await services.Users.FindClaimAsync(user, ClaimTypes.Surname);
                    context.GivenName = await services.Users.FindClaimAsync(user, ClaimTypes.GivenName);
                    context.BirthDate = await services.Users.FindClaimAsync(user, ClaimTypes.DateOfBirth);
                }
            }

            // Only add the email address details if the "email" scope was present in the access token.
            if (services.Users.SupportsUserEmail && context.Ticket.HasScope(OpenIdConnectConstants.Scopes.Email)) {
                context.Email = await services.Users.GetEmailAsync(user);

                // Only add the "email_verified" claim
                // if the email address is non-null.
                if (!string.IsNullOrEmpty(context.Email)) {
                    context.EmailVerified = await services.Users.IsEmailConfirmedAsync(user);
                }
            };

            // Only add the phone number details if the "phone" scope was present in the access token.
            if (services.Users.SupportsUserPhoneNumber &&
                context.Ticket.HasScope(OpenIdConnectConstants.Scopes.Phone)) {
                context.PhoneNumber = await services.Users.GetPhoneNumberAsync(user);

                // Only add the "phone_number_verified"
                // claim if the phone number is non-null.
                if (!string.IsNullOrEmpty(context.PhoneNumber)) {
                    context.PhoneNumberVerified = await services.Users.IsPhoneNumberConfirmedAsync(user);
                }
            }

            // Only add the roles list if the "roles" scope was present in the access token.
            if (services.Users.SupportsUserRole && context.Ticket.HasScope(OpenIddictConstants.Scopes.Roles)) {
                var roles = await services.Users.GetRolesAsync(user);
                if (roles.Count != 0) {
                    context.Claims[OpenIddictConstants.Claims.Roles] = JArray.FromObject(roles);
                }
            }
        }
    }
}