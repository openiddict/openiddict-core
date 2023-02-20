/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client.SystemIntegration;

/// <summary>
/// Contains a collection of event handler filters commonly used by the system integration handlers.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictClientSystemIntegrationHandlerFilters
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
    /// Represents a filter that excludes the associated handlers if no HTTP listener context can be found.
    /// </summary>
    public sealed class RequireHttpListenerContext : IOpenIddictClientHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.Transaction.GetHttpListenerContext() is not null);
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
    /// Represents a filter that excludes the associated handlers if no protocol activation was found.
    /// </summary>
    public sealed class RequireProtocolActivation : IOpenIddictClientHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return new(context.Transaction.GetProtocolActivation() is not null);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers
    /// if the system browser integration was not enabled.
    /// </summary>
    public sealed class RequireSystemBrowser : IOpenIddictClientHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> _options;

        public RequireSystemBrowser(IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (!context.Transaction.Properties.TryGetValue(
                typeof(OpenIddictClientSystemIntegrationAuthenticationMode).FullName!, out var result) ||
                result is not OpenIddictClientSystemIntegrationAuthenticationMode mode)
            {
                mode = _options.CurrentValue.AuthenticationMode.GetValueOrDefault();
            }

            return new(mode is OpenIddictClientSystemIntegrationAuthenticationMode.SystemBrowser);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if
    /// the web authentication broker integration was not enabled.
    /// </summary>
    public sealed class RequireWebAuthenticationBroker : IOpenIddictClientHandlerFilter<BaseContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> _options;

        public RequireWebAuthenticationBroker(IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

#if SUPPORTS_WINDOWS_RUNTIME
            if (OpenIddictClientSystemIntegrationHelpers.IsWindowsRuntimeSupported())
            {
                if (!context.Transaction.Properties.TryGetValue(
                    typeof(OpenIddictClientSystemIntegrationAuthenticationMode).FullName!, out var result) ||
                    result is not OpenIddictClientSystemIntegrationAuthenticationMode mode)
                {
                    mode = _options.CurrentValue.AuthenticationMode.GetValueOrDefault();
                }

                return new(mode is OpenIddictClientSystemIntegrationAuthenticationMode.WebAuthenticationBroker);
            }
#endif

            return new(false);
        }
    }

    /// <summary>
    /// Represents a filter that excludes the associated handlers if no
    /// web authentication operation was triggered during the transaction.
    /// </summary>
    public sealed class RequireWebAuthenticationResult : IOpenIddictClientHandlerFilter<BaseContext>
    {
        /// <inheritdoc/>
        public ValueTask<bool> IsActiveAsync(BaseContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

#if SUPPORTS_WINDOWS_RUNTIME
            if (OpenIddictClientSystemIntegrationHelpers.IsWindowsRuntimeSupported())
            {
                return new(ContainsWebAuthenticationResult(context.Transaction));
            }

            [MethodImpl(MethodImplOptions.NoInlining)]
            static bool ContainsWebAuthenticationResult(OpenIddictClientTransaction transaction)
                => transaction.GetWebAuthenticationResult() is not null;
#endif
            return new(false);
        }
    }
}
