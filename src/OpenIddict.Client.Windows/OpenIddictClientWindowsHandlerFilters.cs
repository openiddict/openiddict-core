/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Client.Windows;

/// <summary>
/// Contains a collection of event handler filters commonly used by the Windows handlers.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictClientWindowsHandlerFilters
{
    /// <summary>
    /// Represents a filter that excludes the associated handlers
    /// if no explicit nonce was attached to the authentication context.
    /// </summary>
    public sealed class RequireAuthenticationNonce : IOpenIddictClientHandlerFilter<ProcessAuthenticationContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(!string.IsNullOrEmpty(context.Nonce));
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no interactive user session was detected.
    /// </summary>
    public sealed class RequireInteractiveSession : IOpenIddictClientHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(Environment.UserInteractive);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no Windows activation was found.
    /// </summary>
    public sealed class RequireWindowsActivation : IOpenIddictClientHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.Transaction.GetWindowsActivation() is not null);
        }
    }
}
