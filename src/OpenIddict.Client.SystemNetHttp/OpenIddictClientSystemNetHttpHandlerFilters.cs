/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Client.SystemNetHttp;

[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictClientSystemNetHttpHandlerFilters
{
    /// <summary>
    /// Represents a filter that excludes the associated handlers if the metadata address of the issuer is not available.
    /// </summary>
    public class RequireHttpMetadataAddress : IOpenIddictClientHandlerFilter<BaseExternalContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseExternalContext context!!)
            => new(string.Equals(context.Address?.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(context.Address?.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase));
    }
}
