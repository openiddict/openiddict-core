/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using OpenIddict.Extensions;

namespace OpenIddict.Client.SystemIntegration;

/// <summary>
/// Represents a generic platform callback.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientSystemIntegrationPlatformCallback
{
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSystemIntegrationPlatformCallback"/> class.
    /// </summary>
    /// <param name="uri">The callback URI.</param>
    /// <param name="parameters">The callback parameters.</param>
    /// <exception cref="ArgumentNullException"><paramref name="uri"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="parameters"/> is <see langword="null"/>.</exception>
    public OpenIddictClientSystemIntegrationPlatformCallback(
        Uri uri, IReadOnlyDictionary<string, OpenIddictParameter> parameters)
    {
        if (uri is null)
        {
            throw new ArgumentNullException(nameof(uri));
        }

        if (!uri.IsAbsoluteUri || OpenIddictHelpers.IsImplicitFileUri(uri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(uri));
        }

        if (parameters is null)
        {
            throw new ArgumentNullException(nameof(parameters));
        }

        CallbackUri = uri;
        Parameters = parameters.ToImmutableDictionary();
    }

    /// <summary>
    /// Gets the callback URI.
    /// </summary>
    public Uri CallbackUri { get; }

    /// <summary>
    /// Gets the parameters attached to this instance.
    /// </summary>
    public ImmutableDictionary<string, OpenIddictParameter> Parameters { get; }

    /// <summary>
    /// Gets the additional properties attached to this instance.
    /// </summary>
    public Dictionary<string, object> Properties { get; } = new(StringComparer.Ordinal);
}
