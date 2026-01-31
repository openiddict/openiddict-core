/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Text.Json;

namespace OpenIddict.Server.SystemNetHttp;

/// <summary>
/// Provides a scoped context for Client ID Metadata Document (CIMD) support.
/// This context is used to store the fetched metadata document and the synthesized
/// virtual application for the current request.
/// </summary>
public sealed class OpenIddictServerSystemNetHttpCimdContext
{
    /// <summary>
    /// Gets or sets the client identifier (CIMD URL) for the current request.
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// Gets or sets the parsed CIMD metadata document for the current request.
    /// </summary>
    public JsonDocument? MetadataDocument { get; set; }

    /// <summary>
    /// Gets or sets the synthesized virtual application for the current request.
    /// This is used as a per-request cache to avoid re-creating the virtual application
    /// on each call to <c>FindByClientIdAsync</c>.
    /// </summary>
    public object? VirtualApplication { get; set; }
}
