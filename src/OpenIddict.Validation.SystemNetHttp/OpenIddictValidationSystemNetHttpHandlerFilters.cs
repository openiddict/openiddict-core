/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Threading.Tasks;
using JetBrains.Annotations;
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace OpenIddict.Validation.SystemNetHttp
{
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public static class OpenIddictValidationSystemNetHttpHandlerFilters
    {
        /// <summary>
        /// Represents a filter that excludes the associated handlers if the metadata address of the issuer is not available.
        /// </summary>
        public class RequireHttpMetadataAddress : IOpenIddictValidationHandlerFilter<BaseContext>
        {
            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(
                    string.Equals(context.Options.MetadataAddress?.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(context.Options.MetadataAddress?.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase));
            }
        }
    }
}
