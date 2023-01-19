/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.Windows;

/// <summary>
/// Exposes companion extensions for the OpenIddict/Windows integration.
/// </summary>
public static class OpenIddictClientWindowsHelpers
{
    /// <summary>
    /// Gets the <see cref="OpenIddictClientWindowsActivation"/> associated with the current context.
    /// </summary>
    /// <param name="transaction">The transaction instance.</param>
    /// <returns>The <see cref="OpenIddictClientWindowsActivation"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static OpenIddictClientWindowsActivation? GetWindowsActivation(this OpenIddictClientTransaction transaction)
        => transaction.GetProperty<OpenIddictClientWindowsActivation>(typeof(OpenIddictClientWindowsActivation).FullName!);
}
