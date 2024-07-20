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
    /// Represents a filter that excludes the associated handlers if the URI is not an HTTP or HTTPS address.
    /// </summary>
    [Obsolete("This filter is obsolete and will be removed in a future version.")]
    public sealed class RequireHttpMetadataUri : IOpenIddictClientHandlerFilter<BaseExternalContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseExternalContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(
                string.Equals(context.RemoteUri?.Scheme, Uri.UriSchemeHttp,  StringComparison.OrdinalIgnoreCase) ||
                string.Equals(context.RemoteUri?.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the URI is not an HTTP or HTTPS address.
    /// </summary>
    public sealed class RequireHttpUri : IOpenIddictClientHandlerFilter<BaseExternalContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseExternalContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(
                string.Equals(context.RemoteUri?.Scheme, Uri.UriSchemeHttp,  StringComparison.OrdinalIgnoreCase) ||
                string.Equals(context.RemoteUri?.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase));
        }
    }
}
