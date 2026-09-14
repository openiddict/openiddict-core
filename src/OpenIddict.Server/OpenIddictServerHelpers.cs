/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;

namespace OpenIddict.Server;

/// <summary>
/// Exposes extensions simplifying the integration with the OpenIddict server services.
/// </summary>
public static class OpenIddictServerHelpers
{
    /// <summary>
    /// Retrieves a property value from the server transaction using the specified name.
    /// </summary>
    /// <typeparam name="TProperty">The type of the property.</typeparam>
    /// <param name="transaction">The server transaction.</param>
    /// <param name="name">The property name.</param>
    /// <returns>The property value or <see langword="null"/> if it couldn't be found.</returns>
    public static TProperty? GetProperty<TProperty>(
        this OpenIddictServerTransaction transaction, string name) where TProperty : class
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentException.ThrowIfNullOrEmpty(name);

        if (transaction.Properties.TryGetValue(name, out var property) && property is TProperty result)
        {
            return result;
        }

        return null;
    }

    /// <summary>
    /// Sets a property in the server transaction using the specified name and value.
    /// </summary>
    /// <typeparam name="TProperty">The type of the property.</typeparam>
    /// <param name="transaction">The server transaction.</param>
    /// <param name="name">The property name.</param>
    /// <param name="value">The property value.</param>
    /// <returns>The server transaction, so that calls can be easily chained.</returns>
    public static OpenIddictServerTransaction SetProperty<TProperty>(
        this OpenIddictServerTransaction transaction,
        string name, TProperty? value) where TProperty : class
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentException.ThrowIfNullOrEmpty(name);

        if (value is null)
        {
            transaction.Properties.Remove(name);
        }

        else
        {
            transaction.Properties[name] = value;
        }

        return transaction;
    }
    /// <summary>
    /// Computes the expiration date of a session from the configured idle timeout and absolute lifetime.
    /// </summary>
    /// <param name="options">The server options.</param>
    /// <param name="date">The date of the last activity.</param>
    /// <param name="creationDate">The creation date of the session, if available.</param>
    /// <returns>The expiration date or <see langword="null"/> if the session doesn't expire.</returns>
    public static DateTimeOffset? ComputeSessionExpirationDate(
        OpenIddictServerOptions options, DateTimeOffset date, DateTimeOffset? creationDate)
    {
        ArgumentNullException.ThrowIfNull(options);

        DateTimeOffset? expiration = options.SessionIdleTimeout is TimeSpan timeout ? date + timeout : null;

        if (options.SessionLifetime is TimeSpan lifetime)
        {
            var limit = (creationDate ?? date) + lifetime;
            if (expiration is null || expiration > limit)
            {
                expiration = limit;
            }
        }

        return expiration;
    }

    /// <summary>
    /// Computes the "session_state" value defined by OpenID Connect Session Management 1.0 using a random salt.
    /// </summary>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="origin">The origin of the redirect_uri (scheme, host and port).</param>
    /// <param name="browserState">The OP browser state.</param>
    /// <returns>The session state.</returns>
    public static string ComputeSessionState(string clientId, string origin, string browserState)
        => ComputeSessionState(clientId, origin, browserState, CreateRandomHexString(16));

    /// <summary>
    /// Computes the "session_state" value defined by OpenID Connect Session Management 1.0:
    /// hex(SHA-256(client_id + " " + origin + " " + browser_state + " " + salt)) + "." + salt.
    /// </summary>
    /// <remarks>
    /// See https://openid.net/specs/openid-connect-session-1_0.html#CreatingUpdatingSessions for more information.
    /// </remarks>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="origin">The origin of the redirect_uri (scheme, host and port).</param>
    /// <param name="browserState">The OP browser state.</param>
    /// <param name="salt">The salt.</param>
    /// <returns>The session state.</returns>
    public static string ComputeSessionState(string clientId, string origin, string browserState, string salt)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);
        ArgumentException.ThrowIfNullOrEmpty(origin);
        ArgumentNullException.ThrowIfNull(browserState);
        ArgumentException.ThrowIfNullOrEmpty(salt);

        return string.Concat(ComputeSha256HexString(string.Concat(clientId, " ", origin, " ", browserState, " ", salt)), ".", salt);
    }

    /// <summary>
    /// Creates a new opaque OP browser state bound to the specified subject.
    /// </summary>
    /// <param name="subject">The subject of the authenticated user, if available.</param>
    /// <returns>The browser state.</returns>
    public static string CreateBrowserState(string? subject)
    {
        var value = CreateRandomHexString(16);

        return string.Concat(value, ".", ComputeBrowserStateBinding(value, subject));
    }

    /// <summary>
    /// Determines whether the specified OP browser state was created for the specified subject.
    /// </summary>
    /// <param name="state">The browser state.</param>
    /// <param name="subject">The subject of the authenticated user, if available.</param>
    /// <returns><see langword="true"/> if the browser state is bound to the subject, <see langword="false"/> otherwise.</returns>
    public static bool ValidateBrowserState(string? state, string? subject)
    {
        if (string.IsNullOrEmpty(state))
        {
            return false;
        }

        var index = state.IndexOf('.');
        if (index <= 0 || index == state.Length - 1)
        {
            return false;
        }

        return string.Equals(state.Substring(index + 1),
            ComputeBrowserStateBinding(state.Substring(0, index), subject), StringComparison.Ordinal);
    }

    /// <summary>
    /// Creates the HTML page served by the check session iframe endpoint, as defined by
    /// OpenID Connect Session Management 1.0 (https://openid.net/specs/openid-connect-session-1_0.html#OPiframe).
    /// </summary>
    /// <param name="cookieName">The name of the cookie storing the OP browser state.</param>
    /// <param name="nonce">The nonce used in the Content-Security-Policy header to allow the inline script.</param>
    /// <returns>The HTML page.</returns>
    public static string CreateCheckSessionIframePage(string cookieName, string nonce)
    {
        ArgumentException.ThrowIfNullOrEmpty(cookieName);
        ArgumentException.ThrowIfNullOrEmpty(nonce);

        // Note: the message posted by the RP iframe is "client_id session_state" and the response is "changed",
        // "unchanged" or "error". The OP browser state is read from a cookie accessible to scripts.
        var builder = new StringBuilder();
        builder.AppendLine("<!DOCTYPE html>");
        builder.AppendLine("<html>");
        builder.AppendLine("<head><meta charset=\"utf-8\"><title>Check session</title></head>");
        builder.AppendLine("<body>");
        builder.Append("<script nonce=\"").Append(HtmlEncoder.Default.Encode(nonce)).AppendLine("\">");
        builder.AppendLine("(function () {");
        builder.Append("  var name = \"").Append(JavaScriptEncoder.Default.Encode(cookieName)).AppendLine("\";");
        builder.AppendLine("  function getBrowserState() {");
        builder.AppendLine("    var cookies = document.cookie ? document.cookie.split(\";\") : [];");
        builder.AppendLine("    for (var i = 0; i < cookies.length; i++) {");
        builder.AppendLine("      var cookie = cookies[i].replace(/^\\s+/, \"\");");
        builder.AppendLine("      if (cookie.indexOf(name + \"=\") === 0) { return decodeURIComponent(cookie.substring(name.length + 1)); }");
        builder.AppendLine("    }");
        builder.AppendLine("    return \"\";");
        builder.AppendLine("  }");
        builder.AppendLine("  function toHex(buffer) {");
        builder.AppendLine("    var bytes = new Uint8Array(buffer), result = \"\";");
        builder.AppendLine("    for (var i = 0; i < bytes.length; i++) { result += (bytes[i] < 16 ? \"0\" : \"\") + bytes[i].toString(16); }");
        builder.AppendLine("    return result;");
        builder.AppendLine("  }");
        builder.AppendLine("  window.addEventListener(\"message\", function (e) {");
        builder.AppendLine("    if (!e.source || typeof e.data !== \"string\") { return; }");
        builder.AppendLine("    var parts = e.data.split(\" \"), index = parts.length === 2 ? parts[1].lastIndexOf(\".\") : -1;");
        builder.AppendLine("    if (index < 0 || !window.crypto || !window.crypto.subtle || !window.TextEncoder) { e.source.postMessage(\"error\", e.origin); return; }");
        builder.AppendLine("    var salt = parts[1].substring(index + 1);");
        builder.AppendLine("    var data = new TextEncoder().encode(parts[0] + \" \" + e.origin + \" \" + getBrowserState() + \" \" + salt);");
        builder.AppendLine("    window.crypto.subtle.digest(\"SHA-256\", data).then(function (hash) {");
        builder.AppendLine("      e.source.postMessage(toHex(hash) + \".\" + salt === parts[1] ? \"unchanged\" : \"changed\", e.origin);");
        builder.AppendLine("    }, function () { e.source.postMessage(\"error\", e.origin); });");
        builder.AppendLine("  }, false);");
        builder.AppendLine("})();");
        builder.AppendLine("</script>");
        builder.AppendLine("</body>");
        builder.AppendLine("</html>");

        return builder.ToString();
    }

    /// <summary>
    /// Creates an HTML page loading the specified front-channel logout URIs in hidden iframes and redirecting the
    /// user agent once all the iframes are loaded (or after 3 seconds), as defined by OpenID Connect Front-Channel
    /// Logout 1.0 (https://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout).
    /// </summary>
    /// <param name="uris">The front-channel logout URIs.</param>
    /// <param name="redirectUri">The URI the user agent is redirected to, if applicable.</param>
    /// <param name="nonce">The nonce used in the Content-Security-Policy header to allow the inline script.</param>
    /// <returns>The HTML page.</returns>
    public static string CreateFrontchannelLogoutPage(IEnumerable<Uri> uris, string? redirectUri, string nonce)
    {
        ArgumentNullException.ThrowIfNull(uris);
        ArgumentException.ThrowIfNullOrEmpty(nonce);

        var builder = new StringBuilder();
        builder.AppendLine("<!DOCTYPE html>");
        builder.AppendLine("<html>");
        builder.AppendLine("<head>");
        builder.AppendLine("<meta charset=\"utf-8\">");
        builder.AppendLine("<title>Signing out</title>");

        if (!string.IsNullOrEmpty(redirectUri))
        {
            builder.Append("<noscript><meta http-equiv=\"refresh\" content=\"0;url=")
                   .Append(HtmlEncoder.Default.Encode(redirectUri))
                   .AppendLine("\"></noscript>");
        }

        builder.AppendLine("</head>");
        builder.AppendLine("<body>");

        foreach (var uri in uris)
        {
            builder.Append("<iframe hidden width=\"0\" height=\"0\" src=\"")
                   .Append(HtmlEncoder.Default.Encode(uri.AbsoluteUri))
                   .AppendLine("\"></iframe>");
        }

        if (!string.IsNullOrEmpty(redirectUri))
        {
            builder.Append("<script nonce=\"").Append(HtmlEncoder.Default.Encode(nonce)).AppendLine("\">");
            builder.Append("(function () { var uri = \"").Append(JavaScriptEncoder.Default.Encode(redirectUri)).AppendLine("\";");
            builder.AppendLine("  var frames = document.getElementsByTagName(\"iframe\"), pending = frames.length, done = false;");
            builder.AppendLine("  function redirect() { if (!done) { done = true; window.location.replace(uri); } }");
            builder.AppendLine("  for (var i = 0; i < frames.length; i++) { frames[i].addEventListener(\"load\", function () { if (--pending <= 0) { redirect(); } }); }");
            builder.AppendLine("  if (pending === 0) { redirect(); }");
            builder.AppendLine("  window.setTimeout(redirect, 3000);");
            builder.AppendLine("})();");
            builder.AppendLine("</script>");
        }

        builder.AppendLine("</body>");
        builder.AppendLine("</html>");

        return builder.ToString();
    }

    /// <summary>
    /// Creates the Content-Security-Policy header value used when rendering the front-channel logout page.
    /// </summary>
    /// <param name="uris">The front-channel logout URIs.</param>
    /// <param name="nonce">The nonce allowing the inline script.</param>
    /// <returns>The Content-Security-Policy header value.</returns>
    public static string CreateFrontchannelLogoutContentSecurityPolicy(IEnumerable<Uri> uris, string nonce)
    {
        ArgumentNullException.ThrowIfNull(uris);
        ArgumentException.ThrowIfNullOrEmpty(nonce);

        var origins = uris.Select(static uri => uri.GetLeftPart(UriPartial.Authority)).Distinct(StringComparer.OrdinalIgnoreCase);

        return $"default-src 'none'; frame-src {string.Join(' ', origins)}; script-src 'nonce-{nonce}'";
    }

    /// <summary>
    /// Creates a random nonce suitable for a Content-Security-Policy header.
    /// </summary>
    /// <returns>The nonce.</returns>
    public static string CreateContentSecurityPolicyNonce() => CreateRandomHexString(16);

    private static string ComputeBrowserStateBinding(string value, string? subject)
        => ComputeSha256HexString(string.Concat(value, " ", subject)).Substring(0, 32);

    private static string ComputeSha256HexString(string value)
    {
        using var algorithm = SHA256.Create();
        return ToHexString(algorithm.ComputeHash(Encoding.UTF8.GetBytes(value)));
    }

    private static string CreateRandomHexString(int length)
    {
        var buffer = new byte[length];
        using var generator = RandomNumberGenerator.Create();
        generator.GetBytes(buffer);

        return ToHexString(buffer);
    }

    private static string ToHexString(byte[] bytes)
    {
        var builder = new StringBuilder(bytes.Length * 2);
        foreach (var value in bytes)
        {
            builder.Append(value.ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }
}
