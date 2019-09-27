/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Owin;
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace OpenIddict.Validation.Owin
{
    /// <summary>
    /// Contains a collection of event handler filters commonly used by the OWIN handlers.
    /// </summary>
    public static class OpenIddictValidationOwinHandlerFilters
    {
        /// <summary>
        /// Represents a filter that excludes the associated handlers if no OWIN request can be found.
        /// </summary>
        public class RequireOwinRequest : IOpenIddictValidationHandlerFilter<BaseContext>
        {
            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(context.Transaction.GetOwinRequest() != null);
            }
        }
    }
}
