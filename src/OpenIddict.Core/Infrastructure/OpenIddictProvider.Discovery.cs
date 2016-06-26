/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;

namespace OpenIddict.Infrastructure {
    public partial class OpenIddictProvider<TUser, TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TUser : class where TApplication : class where TAuthorization : class where TScope : class where TToken : class {
        public override Task HandleConfigurationRequest([NotNull] HandleConfigurationRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>>();

            // Note: the "openid" scope is automatically
            // added by the OpenID Connect server middleware.
            context.Scopes.Add(OpenIdConnectConstants.Scopes.Profile);

            // Only add the "email" scope if it's supported
            // by the user manager and the underlying store.
            if (services.Users.SupportsUserEmail) {
                context.Scopes.Add(OpenIdConnectConstants.Scopes.Email);
            }

            // Only add the "phone" scope if it's supported
            // by the user manager and the underlying store.
            if (services.Users.SupportsUserPhoneNumber) {
                context.Scopes.Add(OpenIdConnectConstants.Scopes.Phone);
            }

            // Only add the "roles" scope if it's supported
            // by the user manager and the underlying store.
            if (services.Users.SupportsUserRole) {
                context.Scopes.Add(OpenIddictConstants.Scopes.Roles);
            }

            // Only add the "offline_access" scope if "refresh_token" is listed as a supported grant type.
            if (context.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.RefreshToken)) {
                context.Scopes.Add(OpenIdConnectConstants.Scopes.OfflineAccess);
            }

            return Task.FromResult(0);
        }
    }
}