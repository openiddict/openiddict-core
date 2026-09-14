/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.Server;

/// <summary>
/// Provides high-level APIs for performing server-side operations that are not tied to an HTTP request,
/// like completing Client-Initiated Backchannel Authentication (CIBA) requests once approved by the end user.
/// </summary>
public class OpenIddictServerService
{
    /// <summary>
    /// Gets the name of the transaction property indicating that tokens are generated to be
    /// delivered to the client notification endpoint using the CIBA push token delivery mode.
    /// </summary>
    internal const string BackchannelPushDeliveryProperty = ".backchannel_push_delivery";

    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerService"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictServerService(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <summary>
    /// Lists the pending backchannel authentication requests associated with the specified subject.
    /// </summary>
    /// <param name="subject">The subject (typically, the user identifier).</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The pending backchannel authentication requests.</returns>
    public virtual IAsyncEnumerable<OpenIddictServerBackchannelAuthenticationRequest> ListPendingBackchannelAuthenticationRequestsAsync(
        string subject, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        var options = _provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;
        var manager = _provider.GetService<IOpenIddictTokenManager>()
            ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<OpenIddictServerBackchannelAuthenticationRequest> ExecuteAsync(
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var token in manager.FindBySubjectAsync(subject, cancellationToken))
            {
                var request = await GetPendingRequestAsync(options, manager, token, cancellationToken);
                if (request is not null)
                {
                    yield return request;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves the pending backchannel authentication request corresponding to the specified identifier.
    /// </summary>
    /// <param name="identifier">The identifier of the backchannel authentication request.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The pending request or <see langword="null"/> if no pending request corresponds to the identifier.</returns>
    public virtual async ValueTask<OpenIddictServerBackchannelAuthenticationRequest?> GetPendingBackchannelAuthenticationRequestAsync(
        string identifier, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var options = _provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;
        var manager = _provider.GetService<IOpenIddictTokenManager>()
            ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        return await manager.FindByIdAsync(identifier, cancellationToken) switch
        {
            object token => await GetPendingRequestAsync(options, manager, token, cancellationToken),
            null         => null
        };
    }

    /// <summary>
    /// Approves the specified backchannel authentication request, which allows the client application
    /// to redeem the authentication request identifier using the CIBA grant.
    /// </summary>
    /// <param name="identifier">The identifier of the backchannel authentication request.</param>
    /// <param name="principal">
    /// The principal used to create the tokens returned to the client application. If this parameter
    /// is <see langword="null"/>, the principal attached to the backchannel authentication request is used.
    /// The principal must contain the same subject as the one attached to the backchannel authentication request.
    /// </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// <see langword="true"/> if the request was approved, <see langword="false"/> if it was not found,
    /// is no longer pending or was concurrently updated (in which case, the operation can be retried).
    /// </returns>
    public virtual async ValueTask<bool> ApproveBackchannelAuthenticationRequestAsync(
        string identifier, ClaimsPrincipal? principal = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var options = _provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;
        var manager = _provider.GetService<IOpenIddictTokenManager>()
            ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        var token = await manager.FindByIdAsync(identifier, cancellationToken);
        if (token is null || await GetPendingRequestAsync(options, manager, token, cancellationToken) is not { } request)
        {
            return false;
        }

        principal ??= request.Principal;

        if (principal is not { Identity.IsAuthenticated: true } ||
            !string.Equals(principal.GetClaim(Claims.Subject), request.Subject, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0534));
        }

        // Create a new principal containing only the filtered claims.
        var result = principal.Clone(static claim =>
            !string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(claim.Type, Claims.Confirmation, StringComparison.OrdinalIgnoreCase));

        // Restore the internal claims (e.g presenters or scopes) attached to the initial request, unless overridden.
        foreach (var claims in request.Principal.Claims
            .Where(static claim => claim.Type.StartsWith(Claims.Prefixes.Private, StringComparison.Ordinal))
            .GroupBy(static claim => claim.Type, StringComparer.Ordinal))
        {
            if (!result.HasClaim(claims.Key) && result.Identity is ClaimsIdentity identity)
            {
                identity.AddClaims(claims);
            }
        }

        result.SetCreationDate(request.CreationDate ?? options.TimeProvider.GetUtcNow())
              .SetExpirationDate(request.ExpirationDate)
              .SetTokenId(identifier)
              .SetClaim(Claims.Private.Issuer, (options.Issuer ?? throw new InvalidOperationException(
                  SR.GetResourceString(SR.ID0529))).AbsoluteUri);

        var transaction = new OpenIddictServerTransaction
        {
            CancellationToken = cancellationToken,
            Options = options,
            ServiceProvider = _provider
        };

        var context = new OpenIddictServerEvents.GenerateTokenContext(transaction)
        {
            ClientId = request.ClientId,
            CreateTokenEntry = false,
            IsReferenceToken = false,
            PersistTokenPayload = false,
            Principal = result,
            TokenFormat = TokenFormats.Private.JsonWebToken,
            TokenType = TokenTypeIdentifiers.Private.AuthenticationRequestId
        };

        await _provider.GetRequiredService<IOpenIddictServerDispatcher>().DispatchAsync(context);

        if (context.IsRejected || string.IsNullOrEmpty(context.Token))
        {
            throw new InvalidOperationException(SR.FormatID0535(context.Error, context.ErrorDescription));
        }

        var notification = await ResolveBackchannelNotificationAsync(transaction, manager, token);

        var descriptor = new OpenIddictTokenDescriptor();
        await manager.PopulateAsync(descriptor, token, cancellationToken);

        descriptor.Payload = context.Token;
        descriptor.Principal = result;
        descriptor.Status = Statuses.Valid;
        descriptor.Subject = request.Subject;

        try
        {
            await manager.UpdateAsync(token, descriptor, cancellationToken);
        }

        catch (ConcurrencyException)
        {
            return false;
        }

        if (notification is not null)
        {
            await SendBackchannelNotificationAsync(options, request, notification, result, cancellationToken);
        }

        return true;
    }

    /// <summary>
    /// Rejects the specified backchannel authentication request, which causes the
    /// token requests sent by the client application to be rejected with an access_denied error.
    /// </summary>
    /// <param name="identifier">The identifier of the backchannel authentication request.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the request was rejected, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> RejectBackchannelAuthenticationRequestAsync(
        string identifier, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var options = _provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;
        var manager = _provider.GetService<IOpenIddictTokenManager>()
            ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        var token = await manager.FindByIdAsync(identifier, cancellationToken);
        if (token is null || await GetPendingRequestAsync(options, manager, token, cancellationToken) is not { } request)
        {
            return false;
        }

        var notification = await ResolveBackchannelNotificationAsync(new OpenIddictServerTransaction
        {
            CancellationToken = cancellationToken,
            Options = options,
            ServiceProvider = _provider
        }, manager, token);

        if (!await manager.TryRejectAsync(token, cancellationToken))
        {
            return false;
        }

        if (notification is not null)
        {
            await SendBackchannelNotificationAsync(options, request, notification, principal: null, cancellationToken);
        }

        return true;
    }

    /// <summary>
    /// Creates the encrypted token containing the information needed to send a ping or push notification.
    /// </summary>
    internal static async ValueTask<string> CreateBackchannelNotificationPayloadAsync(OpenIddictServerTransaction transaction,
        string identifier, string token, string mode, DateTimeOffset? expiration)
    {
        var credentials = await OpenIddictServerKeyRing.ResolveCredentialsAsync(transaction);
        var now = transaction.Options.TimeProvider.GetUtcNow();

        return transaction.Options.JsonWebTokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [Claims.AuthReqId] = identifier,
                [Claims.Private.ClientNotificationToken] = token,
                [Claims.Private.TokenDeliveryMode] = mode
            },
            EncryptingCredentials = credentials.EncryptionCredentials[0],
            Expires = expiration is DateTimeOffset date && date > now ? date.UtcDateTime : null,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            SigningCredentials = credentials.SigningCredentials[0],
            TokenType = JsonWebTokenTypes.Private.BackchannelNotification
        });
    }

    private static async ValueTask<OpenIddictServerBackchannelNotification?> ResolveBackchannelNotificationAsync(
        OpenIddictServerTransaction transaction, IOpenIddictTokenManager manager, object token)
    {
        var properties = await manager.GetPropertiesAsync(token, transaction.CancellationToken);
        if (!properties.TryGetValue(Properties.BackchannelNotification, out JsonElement element) ||
            element.ValueKind is not JsonValueKind.String || element.GetString() is not { Length: > 0 } payload)
        {
            return null;
        }

        var credentials = await OpenIddictServerKeyRing.ResolveCredentialsAsync(transaction);

        var parameters = transaction.Options.TokenValidationParameters.Clone();
        parameters.IssuerSigningKeys = from signing in credentials.SigningCredentials select signing.Key;
        parameters.TokenDecryptionKeys = from encryption in credentials.EncryptionCredentials select encryption.Key;
        parameters.ValidateAudience = false;
        parameters.ValidateIssuer = false;
        parameters.ValidateLifetime = false;
        parameters.ValidTypes = [JsonWebTokenTypes.Private.BackchannelNotification];

        var result = await transaction.Options.JsonWebTokenHandler.ValidateTokenAsync(payload, parameters);
        if (!result.IsValid)
        {
            transaction.ServiceProvider.GetRequiredService<ILogger<OpenIddictServerDispatcher>>()
                .LogWarning(6406, result.Exception, SR.GetResourceString(SR.ID6406));

            return null;
        }

        var identity = result.ClaimsIdentity;
        if (identity.FindFirst(Claims.AuthReqId)?.Value is not { Length: > 0 } identifier ||
            identity.FindFirst(Claims.Private.ClientNotificationToken)?.Value is not { Length: > 0 } value ||
            identity.FindFirst(Claims.Private.TokenDeliveryMode)?.Value is not { } mode ||
            mode is not (BackchannelTokenDeliveryModes.Ping or BackchannelTokenDeliveryModes.Push))
        {
            return null;
        }

        return new(identifier, value, mode);
    }

    private async ValueTask SendBackchannelNotificationAsync(OpenIddictServerOptions options,
        OpenIddictServerBackchannelAuthenticationRequest request, OpenIddictServerBackchannelNotification notification,
        ClaimsPrincipal? principal, CancellationToken cancellationToken)
    {
        var logger = _provider.GetRequiredService<ILogger<OpenIddictServerDispatcher>>();

        if (string.IsNullOrEmpty(request.ClientId))
        {
            return;
        }

        var manager = _provider.GetService<IOpenIddictApplicationManager>()
            ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        // Note: the client notification endpoint is resolved when the notification is sent so that
        // an updated endpoint is used if the client registration was changed in the meantime.
        var application = await manager.FindByClientIdAsync(request.ClientId, cancellationToken);
        if (application is null)
        {
            logger.LogWarning(6403, SR.GetResourceString(SR.ID6403), request.ClientId);

            return;
        }

        var settings = await manager.GetSettingsAsync(application, cancellationToken);
        if (!settings.TryGetValue(Settings.BackchannelAuthentication.ClientNotificationEndpoint, out string? value) ||
            !Uri.TryCreate(value, UriKind.Absolute, out Uri? endpoint) ||
            !string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            logger.LogWarning(6403, SR.GetResourceString(SR.ID6403), request.ClientId);

            return;
        }

        var payload = notification.TokenDeliveryMode switch
        {
            // In ping mode, only the authentication request identifier is sent, whether the request was approved or not.
            //
            // See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2.
            BackchannelTokenDeliveryModes.Ping => new OpenIddictResponse
            {
                AuthReqId = notification.AuthenticationRequestId
            },

            // In push mode, the tokens are sent when the request was approved and an error payload is sent otherwise.
            //
            // See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3
            // and https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12.
            BackchannelTokenDeliveryModes.Push when principal is not null
                => await GenerateBackchannelPushPayloadAsync(options, request, notification, principal, cancellationToken),

            _ => new OpenIddictResponse
            {
                AuthReqId = notification.AuthenticationRequestId,
                Error = Errors.AccessDenied,
                ErrorDescription = SR.GetResourceString(SR.ID2305)
            }
        };

        var dispatcher = _provider.GetRequiredService<IOpenIddictServerDispatcher>();

        for (var attempt = 1; ; attempt++)
        {
            var context = new OpenIddictServerEvents.SendBackchannelNotificationContext(new OpenIddictServerTransaction
            {
                CancellationToken = cancellationToken,
                Options = options,
                ServiceProvider = _provider
            })
            {
                Attempt = attempt,
                ClientId = request.ClientId,
                ClientNotificationEndpoint = endpoint,
                ClientNotificationToken = notification.ClientNotificationToken,
                Notification = payload,
                TokenDeliveryMode = notification.TokenDeliveryMode
            };

            await dispatcher.DispatchAsync(context);

            if (context.IsRequestHandled)
            {
                logger.LogInformation(6407, SR.GetResourceString(SR.ID6407),
                    notification.TokenDeliveryMode, request.ClientId, endpoint, attempt);

                return;
            }

            // If no handler processed the notification, this indicates that no transport was registered.
            if (!context.IsRejected)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0603));
            }

            if (attempt > options.BackchannelNotificationRetryCount)
            {
                logger.LogError(6408, SR.GetResourceString(SR.ID6408), notification.TokenDeliveryMode,
                    request.ClientId, endpoint, attempt, context.Error, context.ErrorDescription);

                return;
            }

            logger.LogWarning(6409, SR.GetResourceString(SR.ID6409), notification.TokenDeliveryMode,
                request.ClientId, endpoint, attempt, context.Error, context.ErrorDescription);

            if (options.BackchannelNotificationRetryDelay > TimeSpan.Zero)
            {
#if NET
                await Task.Delay(options.BackchannelNotificationRetryDelay, options.TimeProvider, cancellationToken);
#else
                await Task.Delay(options.BackchannelNotificationRetryDelay, cancellationToken);
#endif
            }
        }
    }

    private async ValueTask<OpenIddictResponse> GenerateBackchannelPushPayloadAsync(OpenIddictServerOptions options,
        OpenIddictServerBackchannelAuthenticationRequest request, OpenIddictServerBackchannelNotification notification,
        ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        // Note: the tokens are generated using the sign-in pipeline of the token endpoint, as if the client
        // application had sent a grant_type=urn:openid:params:grant-type:ciba token request, which ensures
        // the same tokens are returned whatever the token delivery mode is and the token entry is redeemed.
        var transaction = new OpenIddictServerTransaction
        {
            CancellationToken = cancellationToken,
            EndpointType = OpenIddictServerEndpointType.Token,
            Options = options,
            Request = new OpenIddictRequest
            {
                AuthReqId = notification.AuthenticationRequestId,
                ClientId = request.ClientId,
                GrantType = GrantTypes.Ciba
            },
            Response = new OpenIddictResponse(),
            ServiceProvider = _provider
        };

        transaction.Properties[BackchannelPushDeliveryProperty] = true;
        transaction.SetProperty(typeof(OpenIddictServerEvents.ProcessAuthenticationContext).FullName!,
            new OpenIddictServerEvents.ProcessAuthenticationContext(transaction)
            {
                AuthenticationRequestIdPrincipal = principal
            });

        var context = new OpenIddictServerEvents.ProcessSignInContext(transaction)
        {
            Principal = principal.Clone(static _ => true),
            Response = transaction.Response
        };

        await _provider.GetRequiredService<IOpenIddictServerDispatcher>().DispatchAsync(context);

        if (context.IsRejected)
        {
            _provider.GetRequiredService<ILogger<OpenIddictServerDispatcher>>().LogError(6410,
                SR.GetResourceString(SR.ID6410), request.Identifier, context.Error, context.ErrorDescription);

            return new OpenIddictResponse
            {
                AuthReqId = notification.AuthenticationRequestId,
                Error = Errors.TransactionFailed,
                ErrorDescription = SR.GetResourceString(SR.ID2306)
            };
        }

        var response = new OpenIddictResponse();

        foreach (var parameter in context.Response.GetParameters())
        {
            response.SetParameter(parameter.Key, parameter.Value);
        }

        response.AuthReqId = notification.AuthenticationRequestId;

        return response;
    }

    /// <summary>
    /// Terminates the specified server-side session: the session and all the valid sessions sharing its login identifier
    /// are revoked alongside their tokens (and their authorizations when <see cref="OpenIddictServerOptions.RevokeAuthorizationsOnSessionTermination"/>
    /// is enabled) and back-channel logout requests are sent when <see cref="OpenIddictServerOptions.EnableBackchannelLogout"/> is enabled.
    /// </summary>
    /// <param name="identifier">The identifier of the session entry.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The termination result or <see langword="null"/> if the session couldn't be found.</returns>
    public virtual async ValueTask<OpenIddictServerSessionTerminationResult?> TerminateSessionAsync(
        string identifier, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var options = _provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

        return await ProcessSessionTerminationAsync(options, identifier, context =>
        {
            context.RevokeSessions = true;
            context.RevokeAuthorizations = options.RevokeAuthorizationsOnSessionTermination;
            context.SendBackchannelLogoutRequests = options.EnableBackchannelLogout;
            context.ResolveFrontchannelLogoutUris = options.EnableFrontchannelLogout;
        }, cancellationToken);
    }

    /// <summary>
    /// Resolves the front-channel logout URIs (including the "iss" and "sid" parameters) of the client applications
    /// that participated in the specified session, without terminating it. This method is typically used by hosts
    /// rendering their own logout page before signing out, as defined by OpenID Connect Front-Channel Logout 1.0.
    /// </summary>
    /// <param name="identifier">The identifier of the session entry.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The front-channel logout URIs.</returns>
    public virtual async ValueTask<ImmutableArray<Uri>> GetFrontchannelLogoutUrisAsync(
        string identifier, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var options = _provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

        var result = await ProcessSessionTerminationAsync(options, identifier,
            static context => context.ResolveFrontchannelLogoutUris = true, cancellationToken);

        return result?.FrontchannelLogoutUris ?? [];
    }

    private async ValueTask<OpenIddictServerSessionTerminationResult?> ProcessSessionTerminationAsync(
        OpenIddictServerOptions options, string identifier,
        Action<OpenIddictServerEvents.ProcessSessionTerminationContext> configuration, CancellationToken cancellationToken)
    {
        if (options.EnableDegradedMode)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0721));
        }

        var transaction = new OpenIddictServerTransaction
        {
            CancellationToken = cancellationToken,
            Options = options,
            ServiceProvider = _provider
        };

        var context = new OpenIddictServerEvents.ProcessSessionTerminationContext(transaction)
        {
            SessionId = identifier
        };

        configuration(context);

        await _provider.GetRequiredService<IOpenIddictServerDispatcher>().DispatchAsync(context);

        if (context.IsRejected)
        {
            return null;
        }

        return new OpenIddictServerSessionTerminationResult
        {
            FailedParticipants = [.. context.FailedParticipants],
            FrontchannelLogoutUris = [.. context.FrontchannelLogoutUris],
            NotifiedParticipants = [.. context.NotifiedParticipants],
            Participants = [.. context.Participants],
            SessionIds = [.. await Task.WhenAll(context.Sessions.Select(async session =>
                (await _provider.GetRequiredService<IOpenIddictSessionManager>().GetIdAsync(session, cancellationToken))!))]
        };
    }

    private static async ValueTask<OpenIddictServerBackchannelAuthenticationRequest?> GetPendingRequestAsync(
        OpenIddictServerOptions options, IOpenIddictTokenManager manager, object token, CancellationToken cancellationToken)
    {
        if (!await manager.HasTypeAsync(token, TokenTypeIdentifiers.Private.AuthenticationRequestId, cancellationToken) ||
            !await manager.HasStatusAsync(token, Statuses.Inactive, cancellationToken))
        {
            return null;
        }

        var date = await manager.GetExpirationDateAsync(token, cancellationToken);
        if (date is not null && date < options.TimeProvider.GetUtcNow())
        {
            return null;
        }

        var payload = await manager.GetPayloadAsync(token, cancellationToken);
        if (string.IsNullOrEmpty(payload))
        {
            return null;
        }

        // Note: the payload is validated using the server token validation parameters (and not using the generic
        // token validation pipeline) to avoid rejecting the token because its status is still marked as inactive.
        var parameters = options.TokenValidationParameters.Clone();
        parameters.ValidateLifetime = false;
        parameters.ValidIssuer = options.Issuer?.AbsoluteUri;
        parameters.ValidateIssuer = parameters.ValidIssuer is not null;
        parameters.ValidTypes = [JsonWebTokenTypes.Private.AuthenticationRequestId];

        var result = await options.JsonWebTokenHandler.ValidateTokenAsync(payload, parameters);
        if (!result.IsValid)
        {
            return null;
        }

        var principal = new ClaimsPrincipal(result.ClaimsIdentity);

        // Restore the claim destinations from the special oi_cl_dstn claim (represented as a dictionary/JSON object).
        var jwt = (JsonWebToken) result.SecurityToken;
        if ((jwt.InnerToken ?? jwt).TryGetPayloadValue(Claims.Private.ClaimDestinationsMap, out Dictionary<string, string[]> destinations))
        {
            var builder = ImmutableDictionary.CreateBuilder<string, ImmutableArray<string>>(StringComparer.Ordinal);

            foreach (var destination in destinations)
            {
                builder.Add(destination.Key, [.. destination.Value]);
            }

            principal.SetDestinations(builder.ToImmutable());
        }

        return new OpenIddictServerBackchannelAuthenticationRequest
        {
            BindingMessage = principal.GetClaim(Claims.Private.BindingMessage),
            ClientId = principal.GetPresenters().FirstOrDefault(),
            CreationDate = await manager.GetCreationDateAsync(token, cancellationToken),
            ExpirationDate = date,
            Identifier = (await manager.GetIdAsync(token, cancellationToken))!,
            Principal = principal,
            Scopes = principal.GetScopes(),
            Subject = principal.GetClaim(Claims.Subject)
        };
    }
}

/// <summary>
/// Represents a pending backchannel authentication request.
/// </summary>
public sealed class OpenIddictServerBackchannelAuthenticationRequest
{
    /// <summary>
    /// Gets the binding message specified by the client application, if applicable.
    /// </summary>
    public string? BindingMessage { get; init; }

    /// <summary>
    /// Gets the identifier of the client application that initiated the request.
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// Gets the creation date of the request.
    /// </summary>
    public DateTimeOffset? CreationDate { get; init; }

    /// <summary>
    /// Gets the expiration date of the request.
    /// </summary>
    public DateTimeOffset? ExpirationDate { get; init; }

    /// <summary>
    /// Gets the identifier of the request.
    /// </summary>
    public required string Identifier { get; init; }

    /// <summary>
    /// Gets the principal attached to the request.
    /// </summary>
    public required ClaimsPrincipal Principal { get; init; }

    /// <summary>
    /// Gets the scopes requested by the client application.
    /// </summary>
    public ImmutableArray<string> Scopes { get; init; } = [];

    /// <summary>
    /// Gets the subject of the end user.
    /// </summary>
    public string? Subject { get; init; }
}

/// <summary>
/// Represents the result of a session termination.
/// </summary>
public sealed class OpenIddictServerSessionTerminationResult
{
    /// <summary>
    /// Gets the identifiers of the terminated sessions.
    /// </summary>
    public ImmutableArray<string> SessionIds { get; init; } = [];

    /// <summary>
    /// Gets the client applications that participated in the terminated sessions.
    /// </summary>
    public ImmutableArray<OpenIddictServerLogoutParticipant> Participants { get; init; } = [];

    /// <summary>
    /// Gets the participants that were successfully notified using back-channel logout.
    /// </summary>
    public ImmutableArray<OpenIddictServerLogoutParticipant> NotifiedParticipants { get; init; } = [];

    /// <summary>
    /// Gets the participants whose back-channel logout notification failed.
    /// </summary>
    public ImmutableArray<OpenIddictServerLogoutParticipant> FailedParticipants { get; init; } = [];

    /// <summary>
    /// Gets the front-channel logout URIs of the participants, if front-channel logout is enabled.
    /// </summary>
    public ImmutableArray<Uri> FrontchannelLogoutUris { get; init; } = [];
}

/// <summary>
/// Represents the information needed to send a ping or push notification to a client application.
/// </summary>
internal sealed record class OpenIddictServerBackchannelNotification(
    string AuthenticationRequestId, string ClientNotificationToken, string TokenDeliveryMode);
