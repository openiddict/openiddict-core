/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;

namespace OpenIddict.Infrastructure {
    public partial class OpenIddictProvider<TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TApplication : class where TAuthorization : class where TScope : class where TToken : class {
        public override Task HandleUserinfoRequest([NotNull] HandleUserinfoRequestContext context) {
            // Invoke the rest of the pipeline to allow
            // the user code to handle the userinfo request.
            context.SkipToNextMiddleware();

            return Task.FromResult(0);
        }
    }
}