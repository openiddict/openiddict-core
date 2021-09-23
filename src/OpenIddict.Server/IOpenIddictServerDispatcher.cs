/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server;

public interface IOpenIddictServerDispatcher
{
    ValueTask DispatchAsync<TContext>(TContext context) where TContext : BaseContext;
}
