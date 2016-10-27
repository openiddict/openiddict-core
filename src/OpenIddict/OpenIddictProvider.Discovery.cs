/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Linq;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using OpenIddict.Core;

namespace OpenIddict {
    public partial class OpenIddictProvider<TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TApplication : class where TAuthorization : class where TScope : class where TToken : class {
        public override Task HandleConfigurationRequest([NotNull] HandleConfigurationRequestContext context) {
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<OpenIddictOptions>>();

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
            foreach (var type in options.Value.GrantTypes) {
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
            if (options.Value.IsRefreshTokenFlowEnabled()) {
                context.Scopes.Add(OpenIdConnectConstants.Scopes.OfflineAccess);
            }

            context.Metadata[OpenIddictConstants.Metadata.ExternalProvidersSupported] = JArray.FromObject(
                from provider in context.HttpContext.Authentication.GetAuthenticationSchemes()
                where !string.IsNullOrEmpty(provider.DisplayName)
                select provider.AuthenticationScheme);

            return Task.FromResult(0);
        }
    }
}