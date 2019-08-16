/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Options;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.DataProtection
{
    /// <summary>
    /// Contains a collection of event handler filters commonly used by the Data Protection handlers.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public static class OpenIddictServerDataProtectionHandlerFilters
    {
        /// <summary>
        /// Represents a filter that excludes the associated handlers if OpenIddict was not configured to issue Data Protection tokens.
        /// </summary>
        public class RequirePreferDataProtectionFormatEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public RequirePreferDataProtectionFormatEnabled([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(_options.CurrentValue.PreferDataProtectionFormat);
            }
        }
    }
}
