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
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json.Linq;
using OpenIddict.Core;

namespace OpenIddict
{
    public partial class OpenIddictProvider<TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TApplication : class where TAuthorization : class where TScope : class where TToken : class
    {
        public override async Task HandleConfigurationRequest([NotNull] HandleConfigurationRequestContext context)
        {
            var options = (OpenIddictOptions) context.Options;

            // Note: though it's natively supported by the OpenID Connect server middleware,
            // OpenIddict disallows the use of the unsecure code_challenge_method=plain method,
            // which is manually removed from the code_challenge_methods_supported property.
            // See https://tools.ietf.org/html/rfc7636#section-7.2 for more information.
            context.CodeChallengeMethods.Remove(OpenIdConnectConstants.CodeChallengeMethods.Plain);

            // Note: the OpenID Connect server middleware automatically populates grant_types_supported
            // by determining whether the authorization and token endpoints are enabled or not but
            // OpenIddict uses a different approach and relies on a configurable "grants list".
            context.GrantTypes.Clear();
            context.GrantTypes.UnionWith(options.GrantTypes);

            // Only return the scopes configured by the developer.
            context.Scopes.Clear();
            context.Scopes.UnionWith(options.Scopes);

            // Note: the optional "claims" parameter is not supported by OpenIddict,
            // so a "false" flag is returned to encourage clients not to use it.
            context.Metadata[OpenIdConnectConstants.Metadata.ClaimsParameterSupported] = false;

            var schemes = context.HttpContext.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();

            context.Metadata[OpenIddictConstants.Metadata.ExternalProvidersSupported] = new JArray(
                from provider in await schemes.GetAllSchemesAsync()
                where !string.IsNullOrEmpty(provider.DisplayName)
                select provider.Name);
        }
    }
}