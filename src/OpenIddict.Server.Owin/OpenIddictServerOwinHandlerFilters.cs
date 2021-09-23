/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Owin;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.Owin;

/// <summary>
/// Contains a collection of event handler filters commonly used by the OWIN handlers.
/// </summary>
public static class OpenIddictServerOwinHandlerFilters
{
    /// <summary>
    /// Represents a filter that excludes the associated handlers if authorization request caching was not enabled.
    /// </summary>
    public class RequireAuthorizationRequestCachingEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

        public RequireAuthorizationRequestCachingEnabled(IOptionsMonitor<OpenIddictServerOwinOptions> options)
            => _options = options;

        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(_options.CurrentValue.EnableAuthorizationRequestCaching);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the
    /// pass-through mode was not enabled for the authorization endpoint.
    /// </summary>
    public class RequireAuthorizationEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

        public RequireAuthorizationEndpointPassthroughEnabled(IOptionsMonitor<OpenIddictServerOwinOptions> options)
            => _options = options;

        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
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
        private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

        public RequireErrorPassthroughEnabled(IOptionsMonitor<OpenIddictServerOwinOptions> options)
            => _options = options;

        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(_options.CurrentValue.EnableErrorPassthrough);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if logout request caching was not enabled.
    /// </summary>
    public class RequireLogoutRequestCachingEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

        public RequireLogoutRequestCachingEnabled(IOptionsMonitor<OpenIddictServerOwinOptions> options)
            => _options = options;

        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(_options.CurrentValue.EnableLogoutRequestCaching);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the
    /// pass-through mode was not enabled for the logout endpoint.
    /// </summary>
    public class RequireLogoutEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

        public RequireLogoutEndpointPassthroughEnabled(IOptionsMonitor<OpenIddictServerOwinOptions> options)
            => _options = options;

        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(_options.CurrentValue.EnableLogoutEndpointPassthrough);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no OWIN request can be found.
    /// </summary>
    public class RequireOwinRequest : IOpenIddictServerHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(context.Transaction.GetOwinRequest() is not null);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the HTTPS requirement was disabled.
    /// </summary>
    public class RequireTransportSecurityRequirementEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

        public RequireTransportSecurityRequirementEnabled(IOptionsMonitor<OpenIddictServerOwinOptions> options)
            => _options = options;

        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(!_options.CurrentValue.DisableTransportSecurityRequirement);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the
    /// pass-through mode was not enabled for the authorization endpoint.
    /// </summary>
    public class RequireTokenEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

        public RequireTokenEndpointPassthroughEnabled(IOptionsMonitor<OpenIddictServerOwinOptions> options)
            => _options = options;

        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
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
        private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

        public RequireUserinfoEndpointPassthroughEnabled(IOptionsMonitor<OpenIddictServerOwinOptions> options)
            => _options = options;

        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(_options.CurrentValue.EnableUserinfoEndpointPassthrough);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the
    /// pass-through mode was not enabled for the verification endpoint.
    /// </summary>
    public class RequireVerificationEndpointPassthroughEnabled : IOpenIddictServerHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

        public RequireVerificationEndpointPassthroughEnabled(IOptionsMonitor<OpenIddictServerOwinOptions> options)
            => _options = options;

        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new ValueTask<bool>(_options.CurrentValue.EnableVerificationEndpointPassthrough);
        }
    }
}
