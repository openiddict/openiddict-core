/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace OpenIddict.Infrastructure {
    public partial class OpenIddictProvider<TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TApplication : class where TAuthorization : class where TScope : class where TToken : class {
        public override Task HandleConfigurationRequest([NotNull] HandleConfigurationRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TApplication, TAuthorization, TScope, TToken>>();

            // Note: though it's natively supported by the OpenID Connect server middleware,
            // OpenIddict disallows the use of the unsecure code_challenge_method=plain method,
            // which must be manually removed from the code_challenge_methods_supported property.
            // See https://tools.ietf.org/html/rfc7636#section-7.2 for more information.
            context.CodeChallengeMethods.Clear();
            context.CodeChallengeMethods.Add(OpenIdConnectConstants.CodeChallengeMethods.Sha256);

            // Note: the OpenID Connect server middleware automatically populates grant_types_supported
            // by determining whether the authorization and token endpoints are enabled or not but
            // OpenIddict uses a different approach and relies on a configurable "supported list".
            context.GrantTypes.Clear();

            // Copy the supported grant types list to the discovery document.
            foreach (var type in services.Options.GrantTypes) {
                context.GrantTypes.Add(type);
            }

            // Note: the "openid" scope is automatically
            // added by the OpenID Connect server middleware.
            context.Scopes.Add(OpenIdConnectConstants.Scopes.Profile);
            context.Scopes.Add(OpenIdConnectConstants.Scopes.Email);
            context.Scopes.Add(OpenIdConnectConstants.Scopes.Phone);
            context.Scopes.Add(OpenIddictConstants.Scopes.Roles);

            // Only add the "offline_access" scope if the refresh
            // token flow is enabled in the OpenIddict options.
            if (services.Options.IsRefreshTokenFlowEnabled()) {
                context.Scopes.Add(OpenIdConnectConstants.Scopes.OfflineAccess);
            }

            return Task.FromResult(0);
        }
    }
}