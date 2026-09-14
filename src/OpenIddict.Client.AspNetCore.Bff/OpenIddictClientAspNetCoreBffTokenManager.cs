/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Concurrent;
using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using static OpenIddict.Client.AspNetCore.Bff.OpenIddictClientAspNetCoreBffModels;
using Properties = OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants.Properties;
using Tokens = OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants.Tokens;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Manages the user and client access tokens used by the OpenIddict backend-for-frontend (BFF) components.
/// </summary>
public class OpenIddictClientAspNetCoreBffTokenManager
{
    private readonly ConcurrentDictionary<string, AccessToken> _clientTokens = new(StringComparer.Ordinal);
    private readonly OpenIddictClientAspNetCoreBffKeyedOperations<AccessToken> _clientOperations = new();
    private readonly OpenIddictClientAspNetCoreBffKeyedOperations<RefreshResult> _refreshOperations = new();
    private readonly ILogger<OpenIddictClientAspNetCoreBffTokenManager> _logger;
    private readonly IOptionsMonitor<OpenIddictClientAspNetCoreBffOptions> _options;
    private readonly IOptionsMonitor<OpenIddictClientOptions> _clientOptions;
    private readonly OpenIddictClientService _service;
    private readonly IServiceProvider? _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientAspNetCoreBffTokenManager"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="options">The BFF options.</param>
    /// <param name="clientOptions">The OpenIddict client options.</param>
    /// <param name="service">The OpenIddict client service.</param>
    public OpenIddictClientAspNetCoreBffTokenManager(
        ILogger<OpenIddictClientAspNetCoreBffTokenManager> logger,
        IOptionsMonitor<OpenIddictClientAspNetCoreBffOptions> options,
        IOptionsMonitor<OpenIddictClientOptions> clientOptions,
        OpenIddictClientService service)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _clientOptions = clientOptions ?? throw new ArgumentNullException(nameof(clientOptions));
        _service = service ?? throw new ArgumentNullException(nameof(service));
    }

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientAspNetCoreBffTokenManager"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="options">The BFF options.</param>
    /// <param name="clientOptions">The OpenIddict client options.</param>
    /// <param name="service">The OpenIddict client service.</param>
    /// <param name="provider">The service provider, used to resolve the distributed cache when distributed caching is enabled.</param>
    public OpenIddictClientAspNetCoreBffTokenManager(
        ILogger<OpenIddictClientAspNetCoreBffTokenManager> logger,
        IOptionsMonitor<OpenIddictClientAspNetCoreBffOptions> options,
        IOptionsMonitor<OpenIddictClientOptions> clientOptions,
        OpenIddictClientService service,
        IServiceProvider provider)
        : this(logger, options, clientOptions, service)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <summary>
    /// Refreshes the access token stored in the authentication ticket if it is about to expire and a refresh token
    /// is available. When the refresh token is rejected by the authorization server, the principal is rejected.
    /// </summary>
    /// <remarks>
    /// This method is automatically invoked by the cookie authentication handler, unless
    /// <see cref="AuthenticationSchemeOptions.EventsType"/> is used, in which case
    /// it must be manually called from <see cref="CookieAuthenticationEvents.ValidatePrincipal"/>.
    /// </remarks>
    /// <param name="context">The cookie validation context.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    public virtual async ValueTask ValidatePrincipalAsync(CookieValidatePrincipalContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var options = _options.CurrentValue;
        if (options.DisableAutomaticTokenRefresh || context.Principal is null)
        {
            return;
        }

        var token = context.Properties.GetTokenValue(Tokens.RefreshToken);
        if (string.IsNullOrEmpty(token))
        {
            return;
        }

        // Only refresh the access token if it is missing or about to expire. If the access token
        // is present but its expiration date is unknown, it is assumed to still be valid.
        if (!string.IsNullOrEmpty(context.Properties.GetTokenValue(Tokens.BackchannelAccessToken)))
        {
            if (!TryParseDate(context.Properties.GetTokenValue(Tokens.BackchannelAccessTokenExpirationDate), out var date) ||
                date - options.AccessTokenRefreshMargin > _clientOptions.CurrentValue.TimeProvider.GetUtcNow())
            {
                return;
            }
        }

        _logger.LogDebug(6317, SR.GetResourceString(SR.ID6317));

        var registration = GetRegistrationId(context.Principal, context.Properties);

        RefreshResult result;

        try
        {
            // Note: the operation is keyed by the hash of the refresh token so that concurrent requests
            // carrying the same authentication cookie share the same token request (which is required
            // when the authorization server uses rolling refresh tokens) without keeping the raw token.
            var hash = ComputeHash(token);

            result = await _refreshOperations.RunAsync(
                key: hash,
                factory: () => options.EnableDistributedCaching
                    ? RefreshWithDistributedCacheAsync(hash, token, registration, options)
                    : RefreshAsync(token, registration),
                retention: options.TokenRefreshResultRetentionPeriod,
                provider: _clientOptions.CurrentValue.TimeProvider).WaitAsync(context.HttpContext.RequestAborted);
        }

        catch (ProtocolException exception) when (string.Equals(exception.Error, Errors.InvalidGrant, StringComparison.Ordinal))
        {
            _logger.LogInformation(6318, SR.GetResourceString(SR.ID6318), exception.Error, exception.ErrorDescription);

            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(context.Scheme.Name);

            return;
        }

        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _logger.LogWarning(6319, exception, SR.GetResourceString(SR.ID6319));

            return;
        }

        var tokens = context.Properties.GetTokens().ToList();

        SetToken(tokens, Tokens.BackchannelAccessToken, result.AccessToken);
        SetToken(tokens, Tokens.BackchannelAccessTokenExpirationDate,
            result.ExpirationDate?.ToString("o", CultureInfo.InvariantCulture));
        SetToken(tokens, Tokens.BackchannelAccessTokenType, result.TokenType);

        // Only replace the refresh and identity tokens if new tokens were returned (and, for identity
        // tokens, if an identity token was initially stored in the ticket, to avoid increasing its size).
        if (!string.IsNullOrEmpty(result.RefreshToken))
        {
            SetToken(tokens, Tokens.RefreshToken, result.RefreshToken);
        }

        if (!string.IsNullOrEmpty(result.IdentityToken) &&
            tokens.Exists(static token => string.Equals(token.Name, Tokens.BackchannelIdentityToken, StringComparison.Ordinal)))
        {
            SetToken(tokens, Tokens.BackchannelIdentityToken, result.IdentityToken);
        }

        context.Properties.StoreTokens(tokens);
        context.ShouldRenew = true;

        static void SetToken(List<AuthenticationToken> tokens, string name, string? value)
        {
            tokens.RemoveAll(token => string.Equals(token.Name, name, StringComparison.Ordinal));

            if (!string.IsNullOrEmpty(value))
            {
                tokens.Add(new AuthenticationToken { Name = name, Value = value });
            }
        }
    }

    /// <summary>
    /// Sends a refresh token request and returns the resulting tokens.
    /// </summary>
    /// <param name="token">The refresh token.</param>
    /// <param name="registration">The client registration identifier, if available.</param>
    /// <returns>The result of the refresh operation.</returns>
    private async Task<RefreshResult> RefreshAsync(string token, string? registration)
    {
        // Note: the operation may be shared by multiple requests: the cancellation
        // token of the request that initiated it is deliberately not flowed.
        var result = await _service.AuthenticateWithRefreshTokenAsync(new()
        {
            DisableUserInfo = true,
            RefreshToken = token,
            RegistrationId = registration
        });

        return new RefreshResult(
            AccessToken: result.AccessToken,
            ExpirationDate: result.AccessTokenExpirationDate,
            TokenType: result.TokenResponse.TokenType,
            RefreshToken: result.RefreshToken,
            IdentityToken: result.IdentityToken);
    }

    /// <summary>
    /// Sends a refresh token request and returns the resulting tokens, using the distributed cache to share
    /// the result with the other instances of the application that use the same refresh token.
    /// </summary>
    /// <param name="hash">The hash of the refresh token.</param>
    /// <param name="token">The refresh token.</param>
    /// <param name="registration">The client registration identifier, if available.</param>
    /// <param name="options">The BFF options.</param>
    /// <returns>The result of the refresh operation.</returns>
    private async Task<RefreshResult> RefreshWithDistributedCacheAsync(
        string hash, string token, string? registration, OpenIddictClientAspNetCoreBffOptions options)
    {
        var cache = _provider?.GetService<IDistributedCache>() ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0988));

        // Note: refresh token results contain access, refresh and identity tokens and are always
        // protected using ASP.NET Core Data Protection before being stored in the distributed cache.
        var protector = _provider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(OpenIddictClientAspNetCoreBffConstants.Purposes.RefreshResult);

        var provider = _clientOptions.CurrentValue.TimeProvider;

        var result = string.Concat(OpenIddictClientAspNetCoreBffConstants.CacheKeys.RefreshResult, hash);
        var @lock = string.Concat(OpenIddictClientAspNetCoreBffConstants.CacheKeys.RefreshLock, hash);

        if (await GetResultAsync() is RefreshResult value)
        {
            return value;
        }

        // If another instance is already sending a refresh token request for the same refresh token
        // (which would be rejected by authorization servers using rolling refresh tokens if it was
        // sent twice), wait until its result is available, the lock is released or the timeout elapses.
        //
        // Note: distributed caches don't offer atomic "add" operations, so two instances starting
        // a refresh operation at exactly the same time may still both send a token request.
        var deadline = provider.GetUtcNow() + options.DistributedTokenRefreshLockTimeout;

        while (await cache.GetAsync(@lock) is not null && provider.GetUtcNow() < deadline)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(100), provider);

            if (await GetResultAsync() is RefreshResult shared)
            {
                return shared;
            }
        }

        await cache.SetAsync(@lock, [1], new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = options.DistributedTokenRefreshLockTimeout
        });

        try
        {
            var refreshed = await RefreshAsync(token, registration);

            if (options.TokenRefreshResultRetentionPeriod > TimeSpan.Zero)
            {
                await cache.SetAsync(result, protector.Protect(refreshed.Serialize()),
                    new DistributedCacheEntryOptions
                    {
                        AbsoluteExpirationRelativeToNow = options.TokenRefreshResultRetentionPeriod
                    });
            }

            return refreshed;
        }

        finally
        {
            await cache.RemoveAsync(@lock);
        }

        async Task<RefreshResult?> GetResultAsync()
        {
            if (await cache.GetAsync(result) is not byte[] payload)
            {
                return null;
            }

            try
            {
                return RefreshResult.Deserialize(protector.Unprotect(payload));
            }

            // Ignore the entries that can't be decrypted or deserialized (e.g entries protected using a revoked key).
            catch (Exception exception) when (exception is CryptographicException or FormatException or JsonException)
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Resolves the access token of the user authenticated using the BFF cookie scheme, if available.
    /// If the access token is about to expire, it is automatically refreshed by the cookie handler.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>The access token, or <see langword="null"/> if no user access token is available.</returns>
    public virtual async ValueTask<AccessToken?> GetUserAccessTokenAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var result = await context.AuthenticateAsync(_options.CurrentValue.CookieScheme);
        if (result is not { Succeeded: true, Properties: AuthenticationProperties properties })
        {
            return null;
        }

        var token = properties.GetTokenValue(Tokens.BackchannelAccessToken);
        if (string.IsNullOrEmpty(token))
        {
            return null;
        }

        return new AccessToken
        {
            ExpirationDate = TryParseDate(properties.GetTokenValue(Tokens.BackchannelAccessTokenExpirationDate), out var date) ? date : null,
            RegistrationId = GetRegistrationId(result.Principal, properties),
            TokenType = properties.GetTokenValue(Tokens.BackchannelAccessTokenType),
            Value = token
        };
    }

    /// <summary>
    /// Resolves an access token using the client credentials grant. Tokens are cached in memory
    /// until they are about to expire and concurrent requests share the same token request.
    /// </summary>
    /// <param name="request">The client access token request.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The access token.</returns>
    public virtual async ValueTask<AccessToken> GetClientAccessTokenAsync(
        ClientAccessTokenRequest? request = null, CancellationToken cancellationToken = default)
    {
        request ??= new();

        var key = string.Join("\n",
            request.RegistrationId ?? string.Empty,
            string.Join(' ', (IEnumerable<string>?) request.Scopes?.Order(StringComparer.Ordinal) ?? []),
            string.Join(' ', (IEnumerable<string>?) request.Resources?.Order(StringComparer.Ordinal) ?? []));

        var provider = _clientOptions.CurrentValue.TimeProvider;

        if (_clientTokens.TryGetValue(key, out var token) && !IsExpiring(token))
        {
            return token;
        }

        return await _clientOperations.RunAsync(key, async () =>
        {
            var result = await _service.AuthenticateWithClientCredentialsAsync(new()
            {
                RegistrationId = request.RegistrationId,
                Resources = request.Resources,
                Scopes = request.Scopes
            });

            var token = new AccessToken
            {
                ExpirationDate = result.AccessTokenExpirationDate,
                RegistrationId = request.RegistrationId,
                TokenType = result.TokenResponse.TokenType,
                Value = result.AccessToken
            };

            // Tokens whose expiration date is unknown are never cached.
            if (token.ExpirationDate is not null)
            {
                _clientTokens[key] = token;
            }

            return token;
        }, retention: TimeSpan.Zero, provider).WaitAsync(cancellationToken);

        bool IsExpiring(AccessToken token) => token.ExpirationDate is not DateTimeOffset date ||
            date - _options.CurrentValue.AccessTokenRefreshMargin <= provider.GetUtcNow();
    }

    /// <summary>
    /// Attaches the specified access token to the HTTP request, using the "DPoP" authentication
    /// scheme and a DPoP proof when the token is a DPoP-bound token, or the "Bearer" scheme otherwise.
    /// </summary>
    /// <param name="request">The HTTP request.</param>
    /// <param name="token">The access token.</param>
    /// <param name="uri">The absolute target URI, if different from <see cref="HttpRequestMessage.RequestUri"/>.</param>
    /// <param name="nonce">The DPoP nonce returned by the resource server, if applicable.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    public virtual async ValueTask AttachAccessTokenAsync(HttpRequestMessage request, AccessToken token,
        Uri? uri = null, string? nonce = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(token);

        request.Headers.Remove(OpenIddictClientAspNetCoreBffConstants.Headers.DPoP);

        if (!string.Equals(token.TokenType, TokenTypes.DPoP, StringComparison.OrdinalIgnoreCase))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(Schemes.Bearer, token.Value);

            return;
        }

        uri ??= request.RequestUri;

        if (uri is not { IsAbsoluteUri: true })
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(uri));
        }

        var registration = !string.IsNullOrEmpty(token.RegistrationId)
            ? await _service.GetClientRegistrationByIdAsync(token.RegistrationId, cancellationToken)
            : (await _service.GetClientRegistrationsAsync(cancellationToken)) switch
            {
                [OpenIddictClientRegistration value] => value,
                [] => throw new InvalidOperationException(SR.GetResourceString(SR.ID0304)),
                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0305))
            };

        var proof = await _service.CreateDPoPProofAsync(registration, request.Method.Method,
            uri, token.Value, nonce, cancellationToken);

        request.Headers.Authorization = new AuthenticationHeaderValue(Schemes.DPoP, token.Value);
        request.Headers.TryAddWithoutValidation(OpenIddictClientAspNetCoreBffConstants.Headers.DPoP, proof);
    }

    /// <summary>
    /// Resolves the client registration identifier associated with the specified ticket.
    /// </summary>
    internal static string? GetRegistrationId(ClaimsPrincipal? principal, AuthenticationProperties? properties)
        => principal?.FindFirst(Claims.Private.RegistrationId)?.Value is { Length: > 0 } identifier ? identifier :
           properties?.Items.TryGetValue(Properties.RegistrationId, out var value) is true && !string.IsNullOrEmpty(value) ? value : null;

    private static bool TryParseDate(string? value, out DateTimeOffset date)
        => DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out date);

    private static string ComputeHash(string token)
        => Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    /// <summary>
    /// Represents the result of a refresh token request.
    /// </summary>
    private sealed record class RefreshResult(
        string AccessToken,
        DateTimeOffset? ExpirationDate,
        string? TokenType,
        string? RefreshToken,
        string? IdentityToken)
    {
        public byte[] Serialize()
        {
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                writer.WriteString(nameof(AccessToken), AccessToken);

                if (ExpirationDate is DateTimeOffset date)
                {
                    writer.WriteNumber(nameof(ExpirationDate), date.ToUnixTimeMilliseconds());
                }

                writer.WriteString(nameof(TokenType), TokenType);
                writer.WriteString(nameof(RefreshToken), RefreshToken);
                writer.WriteString(nameof(IdentityToken), IdentityToken);
                writer.WriteEndObject();
            }

            return stream.ToArray();
        }

        public static RefreshResult? Deserialize(byte[] payload)
        {
            using var document = JsonDocument.Parse(payload);
            var root = document.RootElement;

            if (root.ValueKind is not JsonValueKind.Object ||
                !root.TryGetProperty(nameof(AccessToken), out var token) || token.GetString() is not { Length: > 0 } value)
            {
                return null;
            }

            return new RefreshResult(
                AccessToken: value,
                ExpirationDate: root.TryGetProperty(nameof(ExpirationDate), out var date) && date.ValueKind is JsonValueKind.Number
                    ? DateTimeOffset.FromUnixTimeMilliseconds(date.GetInt64()) : null,
                TokenType: GetString(root, nameof(TokenType)),
                RefreshToken: GetString(root, nameof(RefreshToken)),
                IdentityToken: GetString(root, nameof(IdentityToken)));

            static string? GetString(JsonElement element, string name)
                => element.TryGetProperty(name, out var property) && property.ValueKind is JsonValueKind.String ? property.GetString() : null;
        }
    }
}
