/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Runtime.Versioning;

namespace OpenIddict.Client.SystemIntegration;

/// <summary>
/// Represents the authentication mode used to start interactive authentication and logout flows.
/// </summary>
public enum OpenIddictClientSystemIntegrationAuthenticationMode
{
    /// <summary>
    /// Browser-based authentication and logout.
    /// </summary>
    SystemBrowser = 0,

    /// <summary>
    /// Windows web authentication broker-based authentication and logout.
    /// </summary>
    /// <remarks>
    /// Note: the web authentication broker is only supported in UWP applications
    /// and its use is generally not recommended due to its inherent limitations.
    /// </remarks>
    [SupportedOSPlatform("windows10.0.17763")]
    WebAuthenticationBroker = 1,

    /// <summary>
    /// AS web authentication session-based authentication and logout.
    /// </summary>
    [SupportedOSPlatform("ios12.0")]
    [SupportedOSPlatform("maccatalyst13.1")]
    [SupportedOSPlatform("macos10.15")]
    ASWebAuthenticationSession = 2,

    /// <summary>
    /// Custom tabs intent-based authentication and logout.
    /// </summary>
    [SupportedOSPlatform("android21.0")]
    CustomTabsIntent = 3
}
