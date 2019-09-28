/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client;

/// <summary>
/// Represents the type of an OpenIddict client handler.
/// </summary>
public enum OpenIddictClientHandlerType
{
    /// <summary>
    /// The handler is of an unspecified type.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// The handler is a built-in handler, provided as part of the official OpenIddict packages.
    /// </summary>
    BuiltIn = 1,

    /// <summary>
    /// The handler is a custom handler, registered by the end user or a third-party package.
    /// </summary>
    Custom = 2
}
