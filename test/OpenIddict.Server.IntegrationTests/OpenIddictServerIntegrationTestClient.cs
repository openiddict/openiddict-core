/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using AngleSharp.Html.Parser;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;

namespace OpenIddict.Server.FunctionalTests
{
    /// <summary>
    /// Exposes methods that allow sending OpenID Connect
    /// requests and extracting the corresponding responses.
    /// </summary>
    public class OpenIddictServerIntegrationTestClient
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
            if (client == null)
            {
                throw new ArgumentNullException(nameof(client));
            }

            if (parser == null)
            {
                throw new ArgumentNullException(nameof(parser));
            }

            HttpClient = client;
            HtmlParser = parser;
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
            if (request == null)
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
            if (request == null)
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
            if (request == null)
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
            if (method == null)
            {
                throw new ArgumentNullException(nameof(method));
            }

            if (request == null)
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
            if (method == null)
            {
                throw new ArgumentNullException(nameof(method));
            }

            if (uri == null)
            {
                throw new ArgumentNullException(nameof(uri));
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (HttpClient.BaseAddress == null && !uri.IsAbsoluteUri)
            {
                throw new ArgumentException("The address cannot be a relative URI when no base address " +
                                            "is associated with the HTTP client.", nameof(uri));
            }

            return await GetResponseAsync(await HttpClient.SendAsync(CreateRequestMessage(request, method, uri)));
        }

        private HttpRequestMessage CreateRequestMessage(OpenIddictRequest request, HttpMethod method, Uri uri)
        {
            // Note: a dictionary is deliberately not used here to allow multiple parameters with the
            // same name to be specified. While initially not allowed by the core OAuth2 specification,
            // this is required for derived drafts like the OAuth2 token exchange specification.
            var parameters = new List<KeyValuePair<string, string>>();

            foreach (var parameter in request.GetParameters())
            {
                // If the parameter is null or empty, send an empty value.
                if (OpenIddictParameter.IsNullOrEmpty(parameter.Value))
                {
                    parameters.Add(new KeyValuePair<string, string>(parameter.Key, string.Empty));

                    continue;
                }

                var values = (string[]) parameter.Value;
                if (values == null || values.Length == 0)
                {
                    continue;
                }

                foreach (var value in values)
                {
                    parameters.Add(new KeyValuePair<string, string>(parameter.Key, value));
                }
            }

            if (method == HttpMethod.Get && parameters.Count != 0)
            {
                var builder = new StringBuilder();

                foreach (var parameter in parameters)
                {
                    if (builder.Length != 0)
                    {
                        builder.Append('&');
                    }

                    builder.Append(UrlEncoder.Default.Encode(parameter.Key));
                    builder.Append('=');
                    builder.Append(UrlEncoder.Default.Encode(parameter.Value));
                }

                if (!uri.IsAbsoluteUri)
                {
                    uri = new Uri(HttpClient.BaseAddress, uri);
                }

                uri = new UriBuilder(uri) { Query = builder.ToString() }.Uri;
            }

            var message = new HttpRequestMessage(method, uri);

            if (method != HttpMethod.Get)
            {
                message.Content = new FormUrlEncodedContent(parameters);
            }

            return message;
        }

        private async Task<OpenIddictResponse> GetResponseAsync(HttpResponseMessage message)
        {
            if (message.Headers.Location != null)
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

                string UnescapeDataString(string value)
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
                var parameters = new List<KeyValuePair<string, string>>();

                foreach (var element in new StringTokenizer(payload, OpenIddictConstants.Separators.Ampersand))
                {
                    var segment = element;
                    if (segment.Length == 0)
                    {
                        continue;
                    }

                    // Always skip the first char (# or ?).
                    if (segment.Offset == 0)
                    {
                        segment = segment.Subsegment(1, segment.Length - 1);
                    }

                    var index = segment.IndexOf('=');
                    if (index == -1)
                    {
                        continue;
                    }

                    var name = UnescapeDataString(segment.Substring(0, index));
                    if (string.IsNullOrEmpty(name))
                    {
                        continue;
                    }

                    var value = UnescapeDataString(segment.Substring(index + 1, segment.Length - (index + 1)));

                    parameters.Add(new KeyValuePair<string, string>(name, value));
                }

                return new OpenIddictResponse(
                    from parameter in parameters
                    group parameter by parameter.Key into grouping
                    let values = grouping.Select(parameter => parameter.Value)
                    select new KeyValuePair<string, StringValues>(grouping.Key, values.ToArray()));
            }

            else if (string.Equals(message.Content?.Headers?.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = await message.Content.ReadAsStreamAsync();

                return await JsonSerializer.DeserializeAsync<OpenIddictResponse>(stream);
            }

            else if (string.Equals(message.Content?.Headers?.ContentType?.MediaType, "text/html", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = await message.Content.ReadAsStreamAsync();
                using var document = await HtmlParser.ParseDocumentAsync(stream);
                
                // Note: a dictionary is deliberately not used here to allow multiple parameters with the
                // same name to be retrieved. While initially not allowed by the core OAuth2 specification,
                // this is required for derived drafts like the OAuth2 token exchange specification.
                var parameters = new List<KeyValuePair<string, string>>();

                foreach (var element in document.Body.GetElementsByTagName("input"))
                {
                    var name = element.GetAttribute("name");
                    if (string.IsNullOrEmpty(name))
                    {
                        continue;
                    }

                    var value = element.GetAttribute("value");

                    parameters.Add(new KeyValuePair<string, string>(name, value));
                }

                return new OpenIddictResponse(
                    from parameter in parameters
                    group parameter by parameter.Key into grouping
                    let values = grouping.Select(parameter => parameter.Value)
                    select new KeyValuePair<string, StringValues>(grouping.Key, values.ToArray()));
            }

            else if (string.Equals(message.Content?.Headers?.ContentType?.MediaType, "text/plain", StringComparison.OrdinalIgnoreCase))
            {
                using (var stream = await message.Content.ReadAsStreamAsync())
                using (var reader = new StreamReader(stream))
                {
                    // Note: a dictionary is deliberately not used here to allow multiple parameters with the
                    // same name to be retrieved. While initially not allowed by the core OAuth2 specification,
                    // this is required for derived drafts like the OAuth2 token exchange specification.
                    var parameters = new List<KeyValuePair<string, string>>();

                    for (var line = await reader.ReadLineAsync(); line != null; line = await reader.ReadLineAsync())
                    {
                        var index = line.IndexOf(':');
                        if (index == -1)
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
            }

            return new OpenIddictResponse();
        }
    }
}