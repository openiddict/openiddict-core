/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Validation.SystemNetHttp;

[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictValidationSystemNetHttpHandlerFilters
{
    /// <summary>
    /// Represents a filter that excludes the associated handlers if the metadata URI of the issuer is not available.
    /// </summary>
    public sealed class RequireHttpMetadataUri : IOpenIddictValidationHandlerFilter<BaseExternalContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseExternalContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(
                string.Equals(context.RemoteUri?.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(context.RemoteUri?.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase));
        }
    }
}
