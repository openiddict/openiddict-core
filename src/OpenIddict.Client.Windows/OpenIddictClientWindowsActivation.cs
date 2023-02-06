/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Client.Windows;

/// <summary>
/// Represents a Windows application activation.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientWindowsActivation
{
    /// <summary>
    /// Gets or sets the activation URI used to activate the application.
    /// </summary>
    public Uri? ActivationUri { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the activation
    /// was redirected from another instance of the application.
    /// </summary>
    public bool IsActivationRedirected { get; set; }
}
