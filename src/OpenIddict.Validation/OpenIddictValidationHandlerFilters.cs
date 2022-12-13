/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Validation;

[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictValidationHandlerFilters
{
    /// <summary>
    /// Represents a filter that excludes the associated handlers if no access token is extracted.
    /// </summary>
    public sealed class RequireAccessTokenExtracted : IOpenIddictValidationHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ExtractAccessToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no access token is validated.
    /// </summary>
    public sealed class RequireAccessTokenValidated : IOpenIddictValidationHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.ValidateAccessToken);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if authorization validation was not enabled.
    /// </summary>
    public sealed class RequireAuthorizationEntryValidationEnabled : IOpenIddictValidationHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.Options.EnableAuthorizationEntryValidation);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no authorization identifier is resolved from the token.
    /// </summary>
    public sealed class RequireAuthorizationIdResolved : IOpenIddictValidationHandlerFilter<ValidateTokenContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ValidateTokenContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!string.IsNullOrEmpty(context.AuthorizationId));
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if local validation is not used.
    /// </summary>
    public sealed class RequireLocalValidation : IOpenIddictValidationHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.Options.ValidationType is OpenIddictValidationType.Direct);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if introspection is not used.
    /// </summary>
    public sealed class RequireIntrospectionValidation : IOpenIddictValidationHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.Options.ValidationType is OpenIddictValidationType.Introspection);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no token identifier is resolved from the token.
    /// </summary>
    public sealed class RequireTokenIdResolved : IOpenIddictValidationHandlerFilter<ValidateTokenContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ValidateTokenContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!string.IsNullOrEmpty(context.TokenId));
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if token validation was not enabled.
    /// </summary>
    public sealed class RequireTokenEntryValidationEnabled : IOpenIddictValidationHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.Options.EnableTokenEntryValidation);
        }
    }
}
