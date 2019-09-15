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
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlers;
using static OpenIddict.Validation.SystemNetHttp.OpenIddictValidationSystemNetHttpConstants;

namespace OpenIddict.Validation.SystemNetHttp
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictValidationSystemNetHttpHandlers
    {
        public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authentication processing:
             */
            PopulateTokenValidationParametersFromMemoryCache.Descriptor,
            PopulateTokenValidationParametersFromProviderConfiguration.Descriptor,
            CacheTokenValidationParameters.Descriptor);

        /// <summary>
        /// Contains the logic responsible of populating the token validation parameters from the memory cache.
        /// </summary>
        public class PopulateTokenValidationParametersFromMemoryCache : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            private readonly IMemoryCache _cache;

            public PopulateTokenValidationParametersFromMemoryCache([NotNull] IMemoryCache cache)
                => _cache = cache;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<PopulateTokenValidationParametersFromMemoryCache>()
                    .SetOrder(PopulateTokenValidationParametersFromProviderConfiguration.Descriptor.Order - 1_000)
                    .Build();

            public ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If token validation parameters were already attached, don't overwrite them.
                if (context.TokenValidationParameters != null)
                {
                    return default;
                }

                // If the metadata address is not an HTTP/HTTPS address, let another handler populate the validation parameters.
                if (!string.Equals(context.Options.MetadataAddress.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(context.Options.MetadataAddress.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                {
                    return default;
                }

                // Resolve the token validation parameters from the memory cache.
                if (_cache.TryGetValue(
                    key: string.Concat("af84c073-c27c-49fd-a54f-584fd60320d3", "\x1e", context.Issuer?.AbsoluteUri),
                    value: out TokenValidationParameters parameters))
                {
                    context.TokenValidationParameters = parameters;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of populating the token validation
        /// parameters using OAuth 2.0/OpenID Connect discovery.
        /// </summary>
        public class PopulateTokenValidationParametersFromProviderConfiguration : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            private readonly IHttpClientFactory _factory;

            public PopulateTokenValidationParametersFromProviderConfiguration([NotNull] IHttpClientFactory factory)
                => _factory = factory;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<PopulateTokenValidationParametersFromProviderConfiguration>()
                    .SetOrder(ValidateTokenValidationParameters.Descriptor.Order - 1_000)
                    .Build();

            public async ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If token validation parameters were already attached, don't overwrite them.
                if (context.TokenValidationParameters != null)
                {
                    return;
                }

                // If the metadata address is not an HTTP/HTTPS address, let another handler populate the validation parameters.
                if (!string.Equals(context.Options.MetadataAddress.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(context.Options.MetadataAddress.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                using var client = _factory.CreateClient(Clients.Discovery);
                var response = await SendHttpRequestMessageAsync(context.Options.MetadataAddress);

                // Ensure the JWKS endpoint URL is present and valid.
                if (!response.TryGetParameter(Metadata.JwksUri, out var endpoint) || OpenIddictParameter.IsNullOrEmpty(endpoint))
                {
                    throw new InvalidOperationException("A discovery response containing an empty JWKS endpoint URL was returned.");
                }

                if (!Uri.TryCreate((string) endpoint, UriKind.Absolute, out Uri uri))
                {
                    throw new InvalidOperationException("A discovery response containing an invalid JWKS endpoint URL was returned.");
                }

                context.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = (string) response[Metadata.Issuer],
                    IssuerSigningKeys = await GetSigningKeysAsync(uri).ToListAsync()
                };

                async IAsyncEnumerable<SecurityKey> GetSigningKeysAsync(Uri address)
                {
                    var response = await SendHttpRequestMessageAsync(address);

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

                async ValueTask<OpenIddictResponse> SendHttpRequestMessageAsync(Uri address)
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
                    using var reader = new JsonTextReader(new StreamReader(stream));

                    var serializer = JsonSerializer.CreateDefault();
                    return serializer.Deserialize<OpenIddictResponse>(reader);
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of caching the token validation parameters.
        /// </summary>
        public class CacheTokenValidationParameters : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            private readonly IMemoryCache _cache;

            public CacheTokenValidationParameters([NotNull] IMemoryCache cache)
                => _cache = cache;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<CacheTokenValidationParameters>()
                    .SetOrder(ValidateTokenValidationParameters.Descriptor.Order + 500)
                    .Build();

            public ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.TokenValidationParameters == null)
                {
                    return default;
                }

                // If the metadata address is not an HTTP/HTTPS address, let another handler populate the validation parameters.
                if (!string.Equals(context.Options.MetadataAddress.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(context.Options.MetadataAddress.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                {
                    return default;
                }

                // Store the token validation parameters in the memory cache.
                _ = _cache.GetOrCreate(
                    key: string.Concat("af84c073-c27c-49fd-a54f-584fd60320d3", "\x1e", context.Issuer?.AbsoluteUri),
                    factory: entry =>
                    {
                        entry.SetAbsoluteExpiration(TimeSpan.FromMinutes(30));
                        entry.SetPriority(CacheItemPriority.NeverRemove);

                        return context.TokenValidationParameters;
                    });

                return default;
            }
        }
    }
}
