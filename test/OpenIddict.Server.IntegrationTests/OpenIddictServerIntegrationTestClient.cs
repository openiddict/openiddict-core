/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
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
            throw new ArgumentException("The URI cannot be null or empty.", nameof(uri));
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
            throw new ArgumentException("The URI cannot be null or empty.", nameof(uri));
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
            throw new ArgumentException("The URI cannot be null or empty.", nameof(uri));
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
            throw new ArgumentException("The URI cannot be null or empty.", nameof(uri));
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
            throw new ArgumentException("The URI cannot be a relative URI when no base URI " +
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
                    static parameter => parameter.Key,
                    static parameter => (StringValues) parameter.Value));
        }

        if (message.Method != HttpMethod.Get)
        {
            message.Content = new FormUrlEncodedContent(
                from parameter in request.GetParameters()
                let values = (ImmutableArray<string?>?) parameter.Value
                where values is not null
                from value in values.GetValueOrDefault()
                select new KeyValuePair<string?, string?>(parameter.Key, value));
        }

        return message;
    }

    private async Task<OpenIddictResponse> GetResponseAsync(HttpResponseMessage message)
    {
        if (message.Headers.WwwAuthenticate.Count is not 0)
        {
            return new OpenIddictResponse(message.Headers.WwwAuthenticate
                .Where(static header => !string.IsNullOrEmpty(header.Parameter))
                .SelectMany(static header => ParseParameters(header.Parameter!)));

            static IEnumerable<KeyValuePair<string, string?>> ParseParameters(string parameter)
            {
                var index = 0;

                while (index < parameter.Length)
                {
                    // Skip leading whitespaces and commas.
                    while (index < parameter.Length && (char.IsWhiteSpace(parameter[index]) || parameter[index] is ','))
                    {
                        index++;
                    }

                    // Parse the parameter key.
                    var start = index;
                    while (index < parameter.Length && parameter[index] is not ('=' or ','))
                    {
                        index++;
                    }

                    if (index >= parameter.Length || parameter[index] is ',')
                    {
                        break;
                    }

                    var key = parameter[start..index].Trim();

                    // Skip the equals sign.
                    index++;
                    while (index < parameter.Length && char.IsWhiteSpace(parameter[index]))
                    {
                        index++;
                    }

                    // Parse the parameter value.
                    string value;
                    if (index < parameter.Length && parameter[index] is '"')
                    {
                        // Skip the opening quote.
                        index++;

                        var builder = new StringBuilder();

                        while (index < parameter.Length)
                        {
                            if (parameter[index] is '\\' && index + 1 < parameter.Length)
                            {
                                builder.Append(parameter[index + 1]);
                                index += 2;
                            }

                            else if (parameter[index] is '"')
                            {
                                // Skip the closing quote.
                                index++;
                                break;
                            }

                            else
                            {
                                builder.Append(parameter[index++]);
                            }
                        }

                        value = builder.ToString();
                    }

                    else
                    {
                        start = index;
                        while (index < parameter.Length && parameter[index] is not ',' && !char.IsWhiteSpace(parameter[index]))
                        {
                            index++;
                        }

                        value = parameter[start..index].Trim();
                    }

                    yield return new KeyValuePair<string, string?>(key, value);
                }
            }
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

                var name = line[..index];
                if (string.IsNullOrEmpty(name))
                {
                    continue;
                }

                var value = line[(index + 1)..];

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
