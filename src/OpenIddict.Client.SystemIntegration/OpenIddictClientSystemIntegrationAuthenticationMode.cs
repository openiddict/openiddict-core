/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Runtime.Versioning;

namespace OpenIddict.Client.SystemIntegration;

/// <summary>
/// Provides various settings needed to configure the OpenIddict client system integration.
/// </summary>
public enum OpenIddictClientSystemIntegrationAuthenticationMode
{
    /// <summary>
    /// Browser-based authentication.
    /// </summary>
    SystemBrowser = 0,

    /// <summary>
    /// Windows web authentication broker-based authentication.
    /// </summary>
    /// <remarks>
    /// Note: the web authentication broker is only supported in UWP applications
    /// and its use is generally not recommended due to its inherent limitations.
    /// </remarks>
    [SupportedOSPlatform("windows10.0.17763")]
    WebAuthenticationBroker = 1
}
