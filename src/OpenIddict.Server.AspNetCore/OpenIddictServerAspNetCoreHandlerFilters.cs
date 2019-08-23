/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore;
using Microsoft.Extensions.Options;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.AspNetCore
{
    /// <summary>
    /// Contains a collection of event handler filters commonly used by the ASP.NET Core handlers.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public static class OpenIddictServerAspNetCoreHandlerFilters
    {
        /// <summary>
        /// Represents a filter that excludes the associated handlers if the
        /// pass-through mode was not enabled for the authorization endpoint.
        /// </summary>
        public class RequireAuthorizationEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

            public RequireAuthorizationEndpointPassthroughEnabled([NotNull] IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
                => _options = options;

            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(_options.CurrentValue.EnableAuthorizationEndpointPassthrough);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if error pass-through was not enabled.
        /// </summary>
        public class RequireErrorPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

            public RequireErrorPassthroughEnabled([NotNull] IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
                => _options = options;

            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(_options.CurrentValue.EnableErrorPassthrough);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if no ASP.NET Core request can be found.
        /// </summary>
        public class RequireHttpRequest : IOpenIddictServerHandlerFilter<BaseContext>
        {
            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(context.Transaction.GetHttpRequest() != null);
            }
        }
        /// <summary>
        /// Represents a filter that excludes the associated handlers if the
        /// pass-through mode was not enabled for the logout endpoint.
        /// </summary>
        public class RequireLogoutEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

            public RequireLogoutEndpointPassthroughEnabled([NotNull] IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
                => _options = options;

            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(_options.CurrentValue.EnableLogoutEndpointPassthrough);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if the HTTPS requirement was disabled.
        /// </summary>
        public class RequireTransportSecurityRequirementEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

            public RequireTransportSecurityRequirementEnabled([NotNull] IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
                => _options = options;

            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(!_options.CurrentValue.DisableTransportSecurityRequirement);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if request caching was not enabled.
        /// </summary>
        public class RequireRequestCachingEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

            public RequireRequestCachingEnabled([NotNull] IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
                => _options = options;

            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(_options.CurrentValue.EnableRequestCaching);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if status code pages support was not enabled.
        /// </summary>
        public class RequireStatusCodePagesIntegrationEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

            public RequireStatusCodePagesIntegrationEnabled([NotNull] IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
                => _options = options;

            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(_options.CurrentValue.EnableStatusCodePagesIntegration);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if the
        /// pass-through mode was not enabled for the authorization endpoint.
        /// </summary>
        public class RequireTokenEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

            public RequireTokenEndpointPassthroughEnabled([NotNull] IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
                => _options = options;

            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(_options.CurrentValue.EnableTokenEndpointPassthrough);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if the
        /// pass-through mode was not enabled for the userinfo endpoint.
        /// </summary>
        public class RequireUserinfoEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

            public RequireUserinfoEndpointPassthroughEnabled([NotNull] IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
                => _options = options;

            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(_options.CurrentValue.EnableUserinfoEndpointPassthrough);
            }
        }
    }
}
