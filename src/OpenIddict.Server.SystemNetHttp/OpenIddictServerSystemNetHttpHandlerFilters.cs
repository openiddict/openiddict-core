/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Server.SystemNetHttp;

[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictServerSystemNetHttpHandlerFilters
{
    /// <summary>
    /// Represents a filter that excludes the associated handlers
    /// if CIMD support was not enabled in the server options.
    /// </summary>
    public sealed class RequireClientIdMetadataDocumentSupportEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            return new(context.Options.EnableClientIdMetadataDocumentSupport);
        }
    }
}
