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
        public class RequireAuthorizationEntryValidationEnabled : IOpenIddictValidationHandlerFilter<BaseContext>
        {
            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(context.Options.EnableAuthorizationEntryValidation);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if local validation is not used.
        /// </summary>
        public class RequireLocalValidation : IOpenIddictValidationHandlerFilter<BaseContext>
        {
            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(context.Options.ValidationType == OpenIddictValidationType.Direct);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if introspection is not used.
        /// </summary>
        public class RequireIntrospectionValidation : IOpenIddictValidationHandlerFilter<BaseContext>
        {
            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(context.Options.ValidationType == OpenIddictValidationType.Introspection);
            }
        }

        /// <summary>
        /// Represents a filter that excludes the associated handlers if token validation was not enabled.
        /// </summary>
        public class RequireTokenEntryValidationEnabled : IOpenIddictValidationHandlerFilter<BaseContext>
        {
            public ValueTask<bool> IsActiveAsync([NotNull] BaseContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                return new ValueTask<bool>(context.Options.EnableTokenEntryValidation);
            }
        }
    }
}
