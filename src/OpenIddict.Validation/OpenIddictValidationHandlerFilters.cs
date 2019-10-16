/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Threading.Tasks;
using JetBrains.Annotations;
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace OpenIddict.Validation
{
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public static class OpenIddictValidationHandlerFilters
    {
        /// <summary>
        /// Represents a filter that excludes the associated handlers if authorization validation was not enabled.
        /// </summary>
        public class RequireAuthorizationValidationEnabled : IOpenIddictValidationHandlerFilter<BaseContext>
        {
            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(context.Options.EnableAuthorizationValidation);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if reference access tokens are disabled.
        /// </summary>
        public class RequireReferenceAccessTokensEnabled : IOpenIddictValidationHandlerFilter<BaseContext>
        {
            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(context.Options.UseReferenceAccessTokens);
            }
        }
    }
}
