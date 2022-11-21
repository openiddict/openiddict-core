/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Server;

[EditorBrowsable(EditorBrowsableState.Never)]
public interface IOpenIddictServerFactory
{
    ValueTask<OpenIddictServerTransaction> CreateTransactionAsync();
}
