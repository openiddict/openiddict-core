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
    /// Represents a filter that excludes the associated handlers if the
    /// pass-through mode was not enabled for the authorization endpoint.
    /// </summary>
    public class RequireRedirectionEndpointPassthroughEnabled : IOpenIddictClientHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientAspNetCoreOptions> _options;

        public RequireRedirectionEndpointPassthroughEnabled(IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options!!)
            => _options = options;

        public ValueTask<bool> IsActiveAsync(BaseContext context!!)
            => new(_options.CurrentValue.EnableRedirectionEndpointPassthrough);
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if error pass-through was not enabled.
    /// </summary>
    public class RequireErrorPassthroughEnabled : IOpenIddictClientHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientAspNetCoreOptions> _options;

        public RequireErrorPassthroughEnabled(IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options!!)
            => _options = options;

        public ValueTask<bool> IsActiveAsync(BaseContext context!!)
            => new(_options.CurrentValue.EnableErrorPassthrough);
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no ASP.NET Core request can be found.
    /// </summary>
    public class RequireHttpRequest : IOpenIddictClientHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context!!)
            => new(context.Transaction.GetHttpRequest() is not null);
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if status code pages support was not enabled.
    /// </summary>
    public class RequireStatusCodePagesIntegrationEnabled : IOpenIddictClientHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientAspNetCoreOptions> _options;

        public RequireStatusCodePagesIntegrationEnabled(IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options!!)
            => _options = options;

        public ValueTask<bool> IsActiveAsync(BaseContext context!!)
            => new(_options.CurrentValue.EnableStatusCodePagesIntegration);
    }
}
