/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Threading.Tasks;
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
        /// Represents a filter that excludes the associated handlers if OpenIddict
        /// was not configured to issue ASP.NET Core Data Protection access tokens.
        /// </summary>
        public class RequireDataProtectionAccessTokenFormatEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public RequireDataProtectionAccessTokenFormatEnabled(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            public ValueTask<bool> IsActiveAsync(BaseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(!_options.CurrentValue.PreferDefaultAccessTokenFormat);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if OpenIddict
        /// was not configured to issue ASP.NET Core Data Protection authorization codes.
        /// </summary>
        public class RequireDataProtectionAuthorizationCodeFormatEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public RequireDataProtectionAuthorizationCodeFormatEnabled(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            public ValueTask<bool> IsActiveAsync(BaseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(!_options.CurrentValue.PreferDefaultAuthorizationCodeFormat);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if OpenIddict
        /// was not configured to issue ASP.NET Core Data Protection device codes.
        /// </summary>
        public class RequireDataProtectionDeviceCodeFormatEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public RequireDataProtectionDeviceCodeFormatEnabled(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            public ValueTask<bool> IsActiveAsync(BaseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(!_options.CurrentValue.PreferDefaultDeviceCodeFormat);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if OpenIddict
        /// was not configured to issue ASP.NET Core Data Protection refresh tokens.
        /// </summary>
        public class RequireDataProtectionRefreshTokenFormatEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public RequireDataProtectionRefreshTokenFormatEnabled(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            public ValueTask<bool> IsActiveAsync(BaseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(!_options.CurrentValue.PreferDefaultRefreshTokenFormat);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if OpenIddict
        /// was not configured to issue ASP.NET Core Data Protection user codes.
        /// </summary>
        public class RequireDataProtectionUserCodeFormatEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public RequireDataProtectionUserCodeFormatEnabled(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            public ValueTask<bool> IsActiveAsync(BaseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(!_options.CurrentValue.PreferDefaultUserCodeFormat);
            }
        }
    }
}
