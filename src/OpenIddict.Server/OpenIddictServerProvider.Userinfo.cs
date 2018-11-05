/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;

namespace OpenIddict.Server
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
    /// </summary>
    internal sealed partial class OpenIddictServerProvider : OpenIdConnectServerProvider
    {
        public override Task ExtractUserinfoRequest([NotNull] ExtractUserinfoRequestContext context)
        {
            // Note: when enabling the userinfo endpoint, OpenIddict users are intended
            // to handle the userinfo requests in their own code (e.g in a MVC controller).
            // To avoid validating the access token twice, the default logic enforced by
            // the OpenID Connect server is bypassed using the ExtractUserinfoRequest event,
            // which is invoked before the access token is extracted from the userinfo request.

            // Invoke the rest of the pipeline to allow
            // the user code to handle the userinfo request.
            context.SkipHandler();

            return _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ExtractUserinfoRequest(context));
        }

        public override Task ValidateUserinfoRequest([NotNull] ValidateUserinfoRequestContext context)
            => _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ValidateUserinfoRequest(context));

        public override Task HandleUserinfoRequest([NotNull] HandleUserinfoRequestContext context)
            => _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.HandleUserinfoRequest(context));

        public override Task ApplyUserinfoResponse([NotNull] ApplyUserinfoResponseContext context)
            => _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ApplyUserinfoResponse(context));
    }
}
