/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Owin;

namespace OpenIddict.Validation.Owin;

/// <summary>
/// Contains a collection of event handler filters commonly used by the OWIN handlers.
/// </summary>
public static class OpenIddictValidationOwinHandlerFilters
{
    /// <summary>
    /// Represents a filter that excludes the associated handlers if no OWIN request can be found.
    /// </summary>
    public sealed class RequireOwinRequest : IOpenIddictValidationHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.Transaction.GetOwinRequest() is not null);
        }
    }
}
