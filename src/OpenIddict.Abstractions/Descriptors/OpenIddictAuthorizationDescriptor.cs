using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Represents an OpenIddict authorization descriptor.
/// </summary>
public class OpenIddictAuthorizationDescriptor
{
    /// <summary>
    /// Gets or sets the application identifier associated with the authorization.
    /// </summary>
    public string? ApplicationId { get; set; }

    /// <summary>
    /// Gets or sets the creation date associated with the authorization.
    /// </summary>
    public DateTimeOffset? CreationDate { get; set; }

    /// <summary>
    /// Gets or sets the optional principal associated with the authorization.
    /// Note: this property is not stored by the default authorization stores.
    /// </summary>
    public ClaimsPrincipal? Principal { get; set; }

    /// <summary>
    /// Gets the additional properties associated with the authorization.
    /// </summary>
    public Dictionary<string, JsonElement> Properties { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the scopes associated with the authorization.
    /// </summary>
    public HashSet<string> Scopes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets or sets the status associated with the authorization.
    /// </summary>
    public string? Status { get; set; }

    /// <summary>
    /// Gets or sets the subject associated with the authorization.
    /// </summary>
    public string? Subject { get; set; }

    /// <summary>
    /// Gets or sets the type of the authorization.
    /// </summary>
    public string? Type { get; set; }
}
