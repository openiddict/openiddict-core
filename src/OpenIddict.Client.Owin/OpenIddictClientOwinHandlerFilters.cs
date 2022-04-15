/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.Options;
using Owin;

namespace OpenIddict.Client.Owin;

/// <summary>
/// Contains a collection of event handler filters commonly used by the OWIN handlers.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictClientOwinHandlerFilters
{
    /// <summary>
    /// Represents a filter that excludes the associated handlers if the
    /// pass-through mode was not enabled for the authorization endpoint.
    /// </summary>
    public class RequireRedirectionEndpointPassthroughEnabled : IOpenIddictClientHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientOwinOptions> _options;

        public RequireRedirectionEndpointPassthroughEnabled(IOptionsMonitor<OpenIddictClientOwinOptions> options!!)
            => _options = options;

        public ValueTask<bool> IsActiveAsync(BaseContext context!!)
            => new(_options.CurrentValue.EnableRedirectionEndpointPassthrough);
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if error pass-through was not enabled.
    /// </summary>
    public class RequireErrorPassthroughEnabled : IOpenIddictClientHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientOwinOptions> _options;

        public RequireErrorPassthroughEnabled(IOptionsMonitor<OpenIddictClientOwinOptions> options!!)
            => _options = options;

        public ValueTask<bool> IsActiveAsync(BaseContext context!!)
            => new(_options.CurrentValue.EnableErrorPassthrough);
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no OWIN request can be found.
    /// </summary>
    public class RequireOwinRequest : IOpenIddictClientHandlerFilter<BaseContext>
    {
        public ValueTask<bool> IsActiveAsync(BaseContext context!!)
            => new(context.Transaction.GetOwinRequest() is not null);
    }
}
