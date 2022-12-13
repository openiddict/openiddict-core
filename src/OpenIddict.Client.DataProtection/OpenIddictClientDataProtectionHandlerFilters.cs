/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Client.DataProtection;

[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictClientDataProtectionHandlerFilters
{
    /// <summary>
    /// Represents a filter that excludes the associated handlers if
    /// the selected token format is not ASP.NET Core Data Protection.
    /// </summary>
    public sealed class RequireDataProtectionTokenFormat : IOpenIddictClientHandlerFilter<GenerateTokenContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(GenerateTokenContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.TokenFormat is TokenFormats.Private.DataProtection);
        }
    }
}
