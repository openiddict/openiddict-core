/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

namespace OpenIddict.Server.SystemNetHttp;

/// <summary>
/// Provides various settings needed to configure the OpenIddict server/System.Net.Http integration.
/// </summary>
public sealed class OpenIddictServerSystemNetHttpOptions
{
    /// <summary>
    /// Gets or sets the timeout applied to the HTTP requests sent to client notification and back-channel logout endpoints.
    /// The default value is 30 seconds.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets or sets the product information used in the "User-Agent" header that is
    /// attached to the HTTP requests sent to client notification endpoints.
    /// </summary>
    public ProductInfoHeaderValue? ProductInformation { get; set; }

    /// <summary>
    /// Gets the user-defined actions used to amend the <see cref="HttpClient"/>
    /// instances created by the OpenIddict server/System.Net.Http integration.
    /// </summary>
    public List<Action<HttpClient>> HttpClientActions { get; } = [];

    /// <summary>
    /// Gets the user-defined actions used to amend the <see cref="HttpClientHandler"/>
    /// instances created by the OpenIddict server/System.Net.Http integration.
    /// </summary>
    public List<Action<HttpClientHandler>> HttpClientHandlerActions { get; } = [];

    /// <summary>
    /// Gets the media types accepted for request objects passed by reference.
    /// By default, only "application/oauth-authz-req+jwt" (RFC 9101, section 10.2.1) is accepted.
    /// </summary>
    public HashSet<string> RequestObjectContentTypes { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "application/oauth-authz-req+jwt"
    };

    /// <summary>
    /// Gets or sets the delegate used to determine whether a request object can be retrieved from the specified
    /// remote IP address. By default, only public unicast addresses are allowed (loopback, link-local, private,
    /// shared, documentation, multicast and reserved ranges are rejected), which mitigates SSRF attacks.
    /// </summary>
    /// <remarks>
    /// Note: all the addresses resolved for the host must be allowed for the request object to be retrieved.
    /// </remarks>
    public Func<IPAddress, bool> RemoteAddressFilter { get; set; } = OpenIddictServerSystemNetHttpHelpers.IsPublicAddress;

    /// <summary>
    /// Gets or sets the maximum amount of time allowed to retrieve a request object. The default value is 5 seconds.
    /// </summary>
    public TimeSpan RequestObjectTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Gets or sets the maximum size, in bytes, of a request object passed by reference. The default value is 64 KiB.
    /// </summary>
    public int MaximumRequestObjectSize { get; set; } = 64 * 1024;

    /// <summary>
    /// Gets or sets the maximum duration during which retrieved request objects are cached. Request objects are only
    /// cached when the response explicitly allows it (Cache-Control max-age or Expires, without no-store/no-cache),
    /// for no longer than the freshness lifetime returned by the server. The default value is 5 minutes.
    /// Setting this property to <see cref="TimeSpan.Zero"/> disables caching.
    /// </summary>
    public TimeSpan MaximumRequestObjectCacheLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the time provider used to compute the cache expiration dates.
    /// If not set, <see cref="TimeProvider.System"/> is used.
    /// </summary>
    public TimeProvider? TimeProvider { get; set; }
}
