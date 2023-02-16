/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Client.SystemIntegration;

/// <summary>
/// Represents a protocol activation.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientSystemIntegrationActivation
{
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSystemIntegrationActivation"/> class.
    /// </summary>
    /// <param name="uri">The protocol activation URI.</param>
    /// <exception cref="ArgumentNullException"><paramref name="uri"/> is <see langword="null"/>.</exception>
    public OpenIddictClientSystemIntegrationActivation(Uri uri)
    {
        if (uri is null)
        {
            throw new ArgumentNullException(nameof(uri));
        }

        if (!uri.IsAbsoluteUri || !uri.IsWellFormedOriginalString())
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(uri));
        }

        ActivationUri = uri;
    }

    /// <summary>
    /// Gets the protocol activation URI.
    /// </summary>
    public Uri ActivationUri { get; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the activation
    /// was redirected from another instance of the application.
    /// </summary>
    public bool IsActivationRedirected { get; set; }
}
