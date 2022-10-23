/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net.Http.Json;
using AngleSharp.Html.Parser;
using Microsoft.Extensions.Primitives;
using OpenIddict.Extensions;

namespace OpenIddict.Server.IntegrationTests;

/// <summary>
/// Exposes methods that allow sending OpenID Connect
/// requests and extracting the corresponding responses.
/// </summary>
public class OpenIddictServerIntegrationTestClient : IAsyncDisposable
{
    /// <summary>
    /// Initializes a new instance of the OpenID Connect client.
    /// </summary>
    public OpenIddictServerIntegrationTestClient()
        : this(new HttpClient())
    {
    }

    /// <summary>
    /// Initializes a new instance of the OpenID Connect client.
    /// </summary>
    /// <param name="client">The HTTP client used to communicate with the OpenID Connect server.</param>
    public OpenIddictServerIntegrationTestClient(HttpClient client)
        : this(client, new HtmlParser())
    {
    }

    /// <summary>
    /// Initializes a new instance of the OpenID Connect client.
    /// </summary>
    /// <param name="client">The HTTP client used to communicate with the OpenID Connect server.</param>
    /// <param name="parser">The HTML parser used to parse the responses returned by the OpenID Connect server.</param>
    public OpenIddictServerIntegrationTestClient(HttpClient client, HtmlParser parser)
    {
        HttpClient = client ?? throw new ArgumentNullException(nameof(client));
        HtmlParser = parser ?? throw new ArgumentNullException(nameof(parser));
    }

    /// <summary>
    /// Gets the underlying HTTP client used to
    /// communicate with the OpenID Connect server.
    /// </summary>
    public HttpClient HttpClient { get; }

    /// <summary>
    /// Gets the underlying HTML parser used to parse the
    /// responses returned by the OpenID Connect server.
    /// </summary>
    public HtmlParser HtmlParser { get; }

    /// <summary>
    /// Sends an empty OpenID Connect request to the given endpoint using GET
    /// and converts the returned response to an OpenID Connect response.
    /// </summary>
    /// <param name="uri">The endpoint to which the request is sent.</param>
    /// <returns>The OpenID Connect response returned by the server.</returns>
    public Task<OpenIddictResponse> GetAsync(string uri)
        => GetAsync(uri, new OpenIddictRequest());

    /// <summary>
    /// Sends an empty OpenID Connect request to the given endpoint using GET
    /// and converts the returned response to an OpenID Connect response.
    /// </summary>
    /// <param name="uri">The endpoint to which the request is sent.</param>
    /// <returns>The OpenID Connect response returned by the server.</returns>
    public Task<OpenIddictResponse> GetAsync(Uri uri)
        => GetAsync(uri, new OpenIddictRequest());

    /// <summary>
    /// Sends a generic OpenID Connect request to the given endpoint using GET
    /// and converts the returned response to an OpenID Connect response.
    /// </summary>
    /// <param name="uri">The endpoint to which the request is sent.</param>
    /// <param name="request">The OpenID Connect request to send.</param>
    /// <returns>The OpenID Connect response returned by the server.</returns>
    public Task<OpenIddictResponse> GetAsync(string uri, OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (string.IsNullOrEmpty(uri))
        {
            throw new ArgumentException("The URL cannot be null or empty.", nameof(uri));
        }

        return GetAsync(new Uri(uri, UriKind.RelativeOrAbsolute), request);
    }

    /// <summary>
    /// Sends a generic OpenID Connect request to the given endpoint using GET
    /// and converts the returned response to an OpenID Connect response.
    /// </summary>
    /// <param name="uri">The endpoint to which the request is sent.</param>
    /// <param name="request">The OpenID Connect request to send.</param>
    /// <returns>The OpenID Connect response returned by the server.</returns>
    public Task<OpenIddictResponse> GetAsync(Uri uri, OpenIddictRequest request)
        => SendAsync(HttpMethod.Get, uri, request);

    /// <summary>
    /// Sends a generic OpenID Connect request to the given endpoint using POST
    /// and converts the returned response to an OpenID Connect response.
    /// </summary>
    /// <param name="uri">The endpoint to which the request is sent.</param>
    /// <param name="request">The OpenID Connect request to send.</param>
    /// <returns>The OpenID Connect response returned by the server.</returns>
    public Task<OpenIddictResponse> PostAsync(string uri, OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (string.IsNullOrEmpty(uri))
        {
            throw new ArgumentException("The URL cannot be null or empty.", nameof(uri));
        }

        return PostAsync(new Uri(uri, UriKind.RelativeOrAbsolute), request);
    }

    /// <summary>
    /// Sends a generic OpenID Connect request to the given endpoint using POST
    /// and converts the returned response to an OpenID Connect response.
    /// </summary>
    /// <param name="uri">The endpoint to which the request is sent.</param>
    /// <param name="request">The OpenID Connect request to send.</param>
    /// <returns>The OpenID Connect response returned by the server.</returns>
    public Task<OpenIddictResponse> PostAsync(Uri uri, OpenIddictRequest request)
        => SendAsync(HttpMethod.Post, uri, request);

    /// <summary>
    /// Sends a generic OpenID Connect request to the given endpoint and
    /// converts the returned response to an OpenID Connect response.
    /// </summary>
    /// <param name="method">The HTTP method used to send the OpenID Connect request.</param>
    /// <param name="uri">The endpoint to which the request is sent.</param>
    /// <param name="request">The OpenID Connect request to send.</param>
    /// <returns>The OpenID Connect response returned by the server.</returns>
    public Task<OpenIddictResponse> SendAsync(string method, string uri, OpenIddictRequest request)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (string.IsNullOrEmpty(method))
        {
            throw new ArgumentException("The HTTP method cannot be null or empty.", nameof(method));
        }

        if (string.IsNullOrEmpty(uri))
        {
            throw new ArgumentException("The URL cannot be null or empty.", nameof(uri));
        }

        return SendAsync(new HttpMethod(method), uri, request);
    }

    /// <summary>
    /// Sends a generic OpenID Connect request to the given endpoint and
    /// converts the returned response to an OpenID Connect response.
    /// </summary>
    /// <param name="method">The HTTP method used to send the OpenID Connect request.</param>
    /// <param name="uri">The endpoint to which the request is sent.</param>
    /// <param name="request">The OpenID Connect request to send.</param>
    /// <returns>The OpenID Connect response returned by the server.</returns>
    public Task<OpenIddictResponse> SendAsync(HttpMethod method, string uri, OpenIddictRequest request)
    {
        if (method is null)
        {
            throw new ArgumentNullException(nameof(method));
        }

        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (string.IsNullOrEmpty(uri))
        {
            throw new ArgumentException("The URL cannot be null or empty.", nameof(uri));
        }

        return SendAsync(method, new Uri(uri, UriKind.RelativeOrAbsolute), request);
    }

    /// <summary>
    /// Sends a generic OpenID Connect request to the given endpoint and
    /// converts the returned response to an OpenID Connect response.
    /// </summary>
    /// <param name="method">The HTTP method used to send the OpenID Connect request.</param>
    /// <param name="uri">The endpoint to which the request is sent.</param>
    /// <param name="request">The OpenID Connect request to send.</param>
    /// <returns>The OpenID Connect response returned by the server.</returns>
    public virtual async Task<OpenIddictResponse> SendAsync(HttpMethod method, Uri uri, OpenIddictRequest request)
    {
        if (method is null)
        {
            throw new ArgumentNullException(nameof(method));
        }

        if (uri is null)
        {
            throw new ArgumentNullException(nameof(uri));
        }

        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (HttpClient.BaseAddress is null && !uri.IsAbsoluteUri)
        {
            throw new ArgumentException("The address cannot be a relative URI when no base address " +
                                        "is associated with the HTTP client.", nameof(uri));
        }

        using var message = CreateRequestMessage(request, method, uri);
        using var response = await HttpClient.SendAsync(message);

        return await GetResponseAsync(response);
    }

    private HttpRequestMessage CreateRequestMessage(OpenIddictRequest request, HttpMethod method, Uri uri)
    {
        if (!uri.IsAbsoluteUri)
        {
            uri = new Uri(HttpClient.BaseAddress!, uri);
        }

        var message = new HttpRequestMessage(method, uri);
        if (message.Method == HttpMethod.Get && request.Count is not 0)
        {
            message.RequestUri = OpenIddictHelpers.AddQueryStringParameters(message.RequestUri!,
                request.GetParameters().ToDictionary(
                    parameter => parameter.Key,
                    parameter => new StringValues((string?[]?) parameter.Value)));
        }

        if (message.Method != HttpMethod.Get)
        {
            message.Content = new FormUrlEncodedContent(
                from parameter in request.GetParameters()
                let values = (string?[]?) parameter.Value
                where values is not null
                from value in values
                select new KeyValuePair<string?, string?>(parameter.Key, value));
        }

        return message;
    }

    private async Task<OpenIddictResponse> GetResponseAsync(HttpResponseMessage message)
    {
        if (message.Headers.WwwAuthenticate.Count is not 0)
        {
            var parameters = new Dictionary<string, StringValues>(message.Headers.WwwAuthenticate.Count);

            foreach (var header in message.Headers.WwwAuthenticate)
            {
                if (string.IsNullOrEmpty(header.Parameter))
                {
                    continue;
                }

                // Note: while initially not allowed by the core OAuth 2.0 specification, multiple
                // parameters with the same name are used by derived drafts like the OAuth 2.0
                // token exchange specification. For consistency, multiple parameters with the
                // same name are also supported when returned as part of WWW-Authentication headers.

                foreach (var parameter in header.Parameter.Split(Separators.Comma, StringSplitOptions.RemoveEmptyEntries))
                {
                    var values = parameter.Split(Separators.EqualsSign, StringSplitOptions.RemoveEmptyEntries);
                    if (values.Length is not 2)
                    {
                        continue;
                    }

                    var (name, value) = (
                        values[0]?.Trim(Separators.Space[0]),
                        values[1]?.Trim(Separators.Space[0], Separators.DoubleQuote[0]));

                    if (string.IsNullOrEmpty(name))
                    {
                        continue;
                    }

                    parameters[name] = parameters.ContainsKey(name) ?
                        StringValues.Concat(parameters[name], value?.Replace("\\\"", "\"")) :
                        new StringValues(value?.Replace("\\\"", "\""));
                }
            }

            return new OpenIddictResponse(parameters);
        }

        else if (message.Headers.Location is not null)
        {
            var payload = message.Headers.Location.Fragment;
            if (string.IsNullOrEmpty(payload))
            {
                payload = message.Headers.Location.Query;
            }

            if (string.IsNullOrEmpty(payload))
            {
                return new OpenIddictResponse();
            }

            static string? UnescapeDataString(string value)
            {
                if (string.IsNullOrEmpty(value))
                {
                    return null;
                }

                return Uri.UnescapeDataString(value.Replace("+", "%20"));
            }

            // Note: a dictionary is deliberately not used here to allow multiple parameters with the
            // same name to be retrieved. While initially not allowed by the core OAuth2 specification,
            // this is required for derived drafts like the OAuth2 token exchange specification.
            var parameters = new List<KeyValuePair<string, string?>>();

            foreach (var element in new StringTokenizer(payload, Separators.Ampersand))
            {
                var segment = element;
                if (!segment.HasValue || segment.Length is 0)
                {
                    continue;
                }

                // Always skip the first char (# or ?).
                if (segment.Offset is 0)
                {
                    segment = segment.Subsegment(1, segment.Length - 1);
                }

                var index = segment.IndexOf('=');
                if (index is -1)
                {
                    continue;
                }

                var name = UnescapeDataString(segment.Substring(0, index));
                if (string.IsNullOrEmpty(name))
                {
                    continue;
                }

                var value = UnescapeDataString(segment.Substring(index + 1, segment.Length - (index + 1)));

                parameters.Add(new KeyValuePair<string, string?>(name, value));
            }

            return new OpenIddictResponse(
                from parameter in parameters
                group parameter by parameter.Key into grouping
                let values = grouping.Select(parameter => parameter.Value)
                select new KeyValuePair<string, StringValues>(grouping.Key, values.ToArray()));
        }

        else if (string.Equals(message.Content?.Headers?.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
        {
            return (await message.Content!.ReadFromJsonAsync<OpenIddictResponse>())!;
        }

        else if (string.Equals(message.Content?.Headers?.ContentType?.MediaType, "text/html", StringComparison.OrdinalIgnoreCase))
        {
            // Note: this test client is only used with OpenIddict's ASP.NET Core or OWIN hosts,
            // that always return their HTTP responses encoded using UTF-8. As such, the stream
            // returned by ReadAsStreamAsync() is always assumed to contain UTF-8 encoded payloads.
            using var stream = await message.Content!.ReadAsStreamAsync();

            using var document = await HtmlParser.ParseDocumentAsync(stream);
            if (document.Body is null)
            {
                return new OpenIddictResponse();
            }

            // Note: a dictionary is deliberately not used here to allow multiple parameters with the
            // same name to be retrieved. While initially not allowed by the core OAuth2 specification,
            // this is required for derived drafts like the OAuth2 token exchange specification.
            var parameters = new List<KeyValuePair<string, string?>>();

            foreach (var element in document.Body.GetElementsByTagName("input"))
            {
                var name = element.GetAttribute("name");
                if (string.IsNullOrEmpty(name))
                {
                    continue;
                }

                var value = element.GetAttribute("value");

                parameters.Add(new KeyValuePair<string, string?>(name, value));
            }

            return new OpenIddictResponse(
                from parameter in parameters
                group parameter by parameter.Key into grouping
                let values = grouping.Select(parameter => parameter.Value)
                select new KeyValuePair<string, StringValues>(grouping.Key, values.ToArray()));
        }

        else if (string.Equals(message.Content?.Headers?.ContentType?.MediaType, "text/plain", StringComparison.OrdinalIgnoreCase))
        {
            // Note: this test client is only used with OpenIddict's ASP.NET Core or OWIN hosts,
            // that always return their HTTP responses encoded using UTF-8. As such, the stream
            // returned by ReadAsStreamAsync() is always assumed to contain UTF-8 encoded payloads.
            using var stream = await message.Content!.ReadAsStreamAsync();
            using var reader = new StreamReader(stream);

            // Note: a dictionary is deliberately not used here to allow multiple parameters with the
            // same name to be retrieved. While initially not allowed by the core OAuth2 specification,
            // this is required for derived drafts like the OAuth2 token exchange specification.
            var parameters = new List<KeyValuePair<string, string>>();

            for (var line = await reader.ReadLineAsync(); line is not null; line = await reader.ReadLineAsync())
            {
                var index = line.IndexOf(':');
                if (index is -1)
                {
                    continue;
                }

                var name = line.Substring(0, index);
                if (string.IsNullOrEmpty(name))
                {
                    continue;
                }

                var value = line.Substring(index + 1);

                parameters.Add(new KeyValuePair<string, string>(name, value));
            }

            return new OpenIddictResponse(
                from parameter in parameters
                group parameter by parameter.Key into grouping
                let values = grouping.Select(parameter => parameter.Value)
                select new KeyValuePair<string, StringValues>(grouping.Key, values.ToArray()));
        }

        return new OpenIddictResponse();
    }

    public ValueTask DisposeAsync()
    {
        HttpClient.Dispose();

        return default;
    }
}
