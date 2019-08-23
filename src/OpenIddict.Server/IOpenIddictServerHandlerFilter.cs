/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using JetBrains.Annotations;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server
{
    public interface IOpenIddictServerHandlerFilter<in TContext> where TContext : BaseContext
    {
        ValueTask<bool> IsActiveAsync([NotNull] TContext context);
    }
}
