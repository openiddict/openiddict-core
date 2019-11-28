/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlers;
using static OpenIddict.Validation.SystemNetHttp.OpenIddictValidationSystemNetHttpConstants;
using static OpenIddict.Validation.SystemNetHttp.OpenIddictValidationSystemNetHttpHandlerFilters;

namespace OpenIddict.Validation.SystemNetHttp
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictValidationSystemNetHttpHandlers
    {
        public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authentication processing:
             */
            PopulateTokenValidationParameters.Descriptor);

        /// <summary>
        /// Contains the logic responsible of populating the token validation
        /// parameters using OAuth 2.0/OpenID Connect discovery.
        /// </summary>
        public class PopulateTokenValidationParameters : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            private readonly IMemoryCache _cache;
            private readonly IHttpClientFactory _factory;

            public PopulateTokenValidationParameters(
                [NotNull] IMemoryCache cache,
                [NotNull] IHttpClientFactory factory)
            {
                _cache = cache;
                _factory = factory;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireHttpMetadataAddress>()
                    .UseSingletonHandler<PopulateTokenValidationParameters>()
                    .SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500)
                    .Build();

            public async ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var parameters = await _cache.GetOrCreateAsync(
                    key: string.Concat("af84c073-c27c-49fd-a54f-584fd60320d3", "\x1e", context.Issuer?.AbsoluteUri),
                    factory: async entry =>
                    {
                        entry.SetAbsoluteExpiration(TimeSpan.FromMinutes(30));
                        entry.SetPriority(CacheItemPriority.NeverRemove);

                        return await GetTokenValidationParametersAsync();
                    });

                context.TokenValidationParameters.ValidIssuer = parameters.ValidIssuer;
                context.TokenValidationParameters.IssuerSigningKeys = parameters.IssuerSigningKeys;

                async ValueTask<TokenValidationParameters> GetTokenValidationParametersAsync()
                {
                    using var client = _factory.CreateClient(Clients.Discovery);
                    var response = await SendHttpRequestMessageAsync(client, context.Options.MetadataAddress);

                    // Ensure the JWKS endpoint URL is present and valid.
                    if (!response.TryGetParameter(Metadata.JwksUri, out var endpoint) || OpenIddictParameter.IsNullOrEmpty(endpoint))
                    {
                        throw new InvalidOperationException("A discovery response containing an empty JWKS endpoint URL was returned.");
                    }

                    if (!Uri.TryCreate((string) endpoint, UriKind.Absolute, out Uri uri))
                    {
                        throw new InvalidOperationException("A discovery response containing an invalid JWKS endpoint URL was returned.");
                    }

                    return new TokenValidationParameters
                    {
                        ValidIssuer = (string) response[Metadata.Issuer],
                        IssuerSigningKeys = await GetSigningKeysAsync(client, uri).ToListAsync()
                    };
                }

                static async IAsyncEnumerable<SecurityKey> GetSigningKeysAsync(HttpClient client, Uri address)
                {
                    var response = await SendHttpRequestMessageAsync(client, address);

                    var keys = response[JsonWebKeySetParameterNames.Keys];
                    if (keys == null)
                    {
                        throw new InvalidOperationException("The OAuth 2.0/OpenID Connect cryptography didn't contain any JSON web key");
                    }

                    foreach (var payload in keys.Value.GetParameters())
                    {
                        var type = (string) payload.Value[JsonWebKeyParameterNames.Kty];
                        if (string.IsNullOrEmpty(type))
                        {
                            throw new InvalidOperationException("A JWKS response containing an invalid key was returned.");
                        }

                        var key = type switch
                        {
                            JsonWebAlgorithmsKeyTypes.RSA => new JsonWebKey
                            {
                                Kty = JsonWebAlgorithmsKeyTypes.RSA,
                                E = (string) payload.Value[JsonWebKeyParameterNames.E],
                                N = (string) payload.Value[JsonWebKeyParameterNames.N]
                            },

                            JsonWebAlgorithmsKeyTypes.EllipticCurve => new JsonWebKey
                            {
                                Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve,
                                Crv = (string) payload.Value[JsonWebKeyParameterNames.Crv],
                                X = (string) payload.Value[JsonWebKeyParameterNames.X],
                                Y = (string) payload.Value[JsonWebKeyParameterNames.Y]
                            },

                            _ => throw new InvalidOperationException("A JWKS response containing an unsupported key was returned.")
                        };

                        key.KeyId = (string) payload.Value[JsonWebKeyParameterNames.Kid];
                        key.X5t = (string) payload.Value[JsonWebKeyParameterNames.X5t];
                        key.X5tS256 = (string) payload.Value[JsonWebKeyParameterNames.X5tS256];

                        if (payload.Value.TryGetParameter(JsonWebKeyParameterNames.X5c, out var chain))
                        {
                            foreach (var certificate in chain.GetParameters())
                            {
                                var value = (string) certificate.Value;
                                if (string.IsNullOrEmpty(value))
                                {
                                    throw new InvalidOperationException("A JWKS response containing an invalid key was returned.");
                                }

                                key.X5c.Add(value);
                            }
                        }

                        yield return key;
                    }
                }

                static async ValueTask<OpenIddictResponse> SendHttpRequestMessageAsync(HttpClient client, Uri address)
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, address);
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                    using var response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead);
                    if (!response.IsSuccessStatusCode)
                    {
                        throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture,
                            "The OAuth 2.0/OpenID Connect discovery failed because an invalid response was received:" +
                            "the identity provider returned returned a {0} response with the following payload: {1} {2}.",
                            /* Status: */ response.StatusCode,
                            /* Headers: */ response.Headers.ToString(),
                            /* Body: */ await response.Content.ReadAsStringAsync()));
                    }

                    var media = response.Content?.Headers.ContentType?.MediaType;
                    if (!string.Equals(media, "application/json", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture,
                            "The OAuth 2.0/OpenID Connect discovery failed because an invalid content type was received:" +
                            "the identity provider returned returned a {0} response with the following payload: {1} {2}.",
                            /* Status: */ response.StatusCode,
                            /* Headers: */ response.Headers.ToString(),
                            /* Body: */ await response.Content.ReadAsStringAsync()));
                    }

                    using var stream = await response.Content.ReadAsStreamAsync();
                    return await JsonSerializer.DeserializeAsync<OpenIddictResponse>(stream);
                }
            }
        }
    }
}
