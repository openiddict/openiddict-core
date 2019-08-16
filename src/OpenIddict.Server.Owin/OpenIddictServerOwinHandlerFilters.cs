/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Options;
using Owin;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.Owin
{
    /// <summary>
    /// Contains a collection of event handler filters commonly used by the OWIN handlers.
    /// </summary>
    public static class OpenIddictServerOwinHandlerFilters
    {
        /// <summary>
        /// Represents a filter that excludes the associated handlers if the
        /// pass-through mode was not enabled for the authorization endpoint.
        /// </summary>
        public class RequireAuthorizationEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

            public RequireAuthorizationEndpointPassthroughEnabled([NotNull] IOptionsMonitor<OpenIddictServerOwinOptions> options)
                => _options = options;

            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(_options.CurrentValue.EnableAuthorizationEndpointPassthrough);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if error pass-through was not enabled.
        /// </summary>
        public class RequireErrorPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

            public RequireErrorPassthroughEnabled([NotNull] IOptionsMonitor<OpenIddictServerOwinOptions> options)
                => _options = options;

            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(_options.CurrentValue.EnableErrorPassthrough);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if no OWIN request can be found.
        /// </summary>
        public class RequireOwinRequest : IOpenIddictServerHandlerFilter<BaseContext>
        {
            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(context.Transaction.GetOwinRequest() != null);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if the HTTPS requirement was disabled.
        /// </summary>
        public class RequireTransportSecurityRequirementEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

            public RequireTransportSecurityRequirementEnabled([NotNull] IOptionsMonitor<OpenIddictServerOwinOptions> options)
                => _options = options;

            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(!_options.CurrentValue.DisableTransportSecurityRequirement);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if request caching was not enabled.
        /// </summary>
        public class RequireRequestCachingEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

            public RequireRequestCachingEnabled([NotNull] IOptionsMonitor<OpenIddictServerOwinOptions> options)
                => _options = options;

            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(_options.CurrentValue.EnableRequestCaching);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if the
        /// pass-through mode was not enabled for the authorization endpoint.
        /// </summary>
        public class RequireTokenEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

            public RequireTokenEndpointPassthroughEnabled([NotNull] IOptionsMonitor<OpenIddictServerOwinOptions> options)
                => _options = options;

            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(_options.CurrentValue.EnableTokenEndpointPassthrough);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if the
        /// pass-through mode was not enabled for the userinfo endpoint.
        /// </summary>
        public class RequireUserinfoEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

            public RequireUserinfoEndpointPassthroughEnabled([NotNull] IOptionsMonitor<OpenIddictServerOwinOptions> options)
                => _options = options;

            public Task<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return Task.FromResult(_options.CurrentValue.EnableUserinfoEndpointPassthrough);
            }
        }
    }
}
