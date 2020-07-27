/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace OpenIddict.Validation.AspNetCore
{
    /// <summary>
    /// Contains a collection of event handler filters commonly used by the ASP.NET Core handlers.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public static class OpenIddictValidationAspNetCoreHandlerFilters
    {
        /// <summary>
        /// Represents a filter that excludes the associated handlers if no ASP.NET Core request can be found.
        /// </summary>
        public class RequireHttpRequest : IOpenIddictValidationHandlerFilter<BaseContext>
        {
            public ValueTask<bool> IsActiveAsync(BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(context.Transaction.GetHttpRequest() != null);
            }
        }
    }
}
