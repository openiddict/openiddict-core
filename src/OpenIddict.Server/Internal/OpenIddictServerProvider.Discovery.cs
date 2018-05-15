/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Newtonsoft.Json.Linq;

namespace OpenIddict.Server
{
    public partial class OpenIddictServerProvider : OpenIdConnectServerProvider
    {
        public override Task HandleConfigurationRequest([NotNull] HandleConfigurationRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

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

            // Note: claims_supported is a recommended parameter but is not strictly required.
            // If no claim was registered, the claims_supported property will be automatically
            // excluded from the response by the OpenID Connect server middleware.
            context.Metadata[OpenIdConnectConstants.Metadata.ClaimsSupported] = new JArray(options.Claims);

            // Note: the optional claims/request/request_uri parameters are not supported
            // by OpenIddict, so "false" is returned to encourage clients not to use them.
            context.Metadata[OpenIdConnectConstants.Metadata.ClaimsParameterSupported] = false;
            context.Metadata[OpenIdConnectConstants.Metadata.RequestParameterSupported] = false;
            context.Metadata[OpenIdConnectConstants.Metadata.RequestUriParameterSupported] = false;

            return base.HandleConfigurationRequest(context);
        }
    }
}