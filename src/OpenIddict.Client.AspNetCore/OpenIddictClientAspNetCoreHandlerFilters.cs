/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.AspNetCore;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client.AspNetCore;

/// <summary>
/// Contains a collection of event handler filters commonly used by the ASP.NET Core handlers.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictClientAspNetCoreHandlerFilters
{
    /// <summary>
    /// Represents a filter that excludes the associated handlers if error pass-through was not enabled.
    /// </summary>
    public sealed class RequireErrorPassthroughEnabled : IOpenIddictClientHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientAspNetCoreOptions> _options;

        public RequireErrorPassthroughEnabled(IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(_options.CurrentValue.EnableErrorPassthrough);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no ASP.NET Core request can be found.
    /// </summary>
    public sealed class RequireHttpRequest : IOpenIddictClientHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.Transaction.GetHttpRequest() is not null);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the
    /// pass-through mode was not enabled for the post-logout redirection endpoint.
    /// </summary>
    public sealed class RequirePostLogoutRedirectionEndpointPassthroughEnabled : IOpenIddictClientHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientAspNetCoreOptions> _options;

        public RequirePostLogoutRedirectionEndpointPassthroughEnabled(IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(_options.CurrentValue.EnablePostLogoutRedirectionEndpointPassthrough);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the
    /// pass-through mode was not enabled for the redirection endpoint.
    /// </summary>
    public sealed class RequireRedirectionEndpointPassthroughEnabled : IOpenIddictClientHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientAspNetCoreOptions> _options;

        public RequireRedirectionEndpointPassthroughEnabled(IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(_options.CurrentValue.EnableRedirectionEndpointPassthrough);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if status code pages support was not enabled.
    /// </summary>
    public sealed class RequireStatusCodePagesIntegrationEnabled : IOpenIddictClientHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientAspNetCoreOptions> _options;

        public RequireStatusCodePagesIntegrationEnabled(IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(_options.CurrentValue.EnableStatusCodePagesIntegration);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if the HTTPS requirement was disabled.
    /// </summary>
    public sealed class RequireTransportSecurityRequirementEnabled : IOpenIddictClientHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientAspNetCoreOptions> _options;

        public RequireTransportSecurityRequirementEnabled(IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!_options.CurrentValue.DisableTransportSecurityRequirement);
        }
    }
}
