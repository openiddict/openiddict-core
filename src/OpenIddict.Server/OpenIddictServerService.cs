/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.Server;

/// <summary>
/// Provides high-level APIs for performing server-side operations that are not tied to an HTTP request,
/// like completing Client-Initiated Backchannel Authentication (CIBA) requests once approved by the end user.
/// </summary>
public class OpenIddictServerService
{
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
        if (token is null || await GetPendingRequestAsync(options, manager, token, cancellationToken) is null)
        {
            return false;
        }

        return await manager.TryRejectAsync(token, cancellationToken);
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
