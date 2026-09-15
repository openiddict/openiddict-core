/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Globalization;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using Parameters = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.Parameters;
using static OpenIddict.Extensions.OpenIddictSamlHelpers;
using static OpenIddict.Server.Saml.OpenIddictServerSamlHelpers;
using static OpenIddict.Server.Saml.OpenIddictServerSamlModels;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Provides the host-agnostic SAML 2.0 identity provider operations: authentication request validation,
/// response and assertion generation and metadata generation.
/// </summary>
public sealed class OpenIddictServerSamlService
{
    private const byte LegacyRequestStateVersion = 2;
    private const byte RequestStateVersion = 3;

    private readonly IOpenIddictServerSamlArtifactStore _artifactStore;
    private readonly ILogger<OpenIddictServerSamlService> _logger;
    private readonly IOptionsMonitor<OpenIddictServerSamlOptions> _options;
    private readonly IOpenIddictServerSamlReplayCache _replayCache;
    private readonly IOpenIddictServerSamlServiceProviderStore _store;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSamlService"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="options">The SAML options.</param>
    /// <param name="store">The service provider store.</param>
    /// <param name="replayCache">The replay cache.</param>
    /// <param name="artifactStore">The artifact store.</param>
    public OpenIddictServerSamlService(
        ILogger<OpenIddictServerSamlService> logger,
        IOptionsMonitor<OpenIddictServerSamlOptions> options,
        IOpenIddictServerSamlServiceProviderStore store,
        IOpenIddictServerSamlReplayCache replayCache,
        IOpenIddictServerSamlArtifactStore artifactStore)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _replayCache = replayCache ?? throw new ArgumentNullException(nameof(replayCache));
        _artifactStore = artifactStore ?? throw new ArgumentNullException(nameof(artifactStore));
    }

    /// <summary>
    /// Resolves and validates a service provider using its entity identifier.
    /// </summary>
    /// <param name="entityId">The entity identifier.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The service provider, or <see langword="null"/> if it cannot be found.</returns>
    /// <exception cref="InvalidOperationException">The service provider returned by the store is invalid.</exception>
    public ValueTask<OpenIddictServerSamlServiceProvider?> FindServiceProviderAsync(string entityId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(entityId);

        return ExecuteAsync(entityId, cancellationToken);

        async ValueTask<OpenIddictServerSamlServiceProvider?> ExecuteAsync(string entityId, CancellationToken cancellationToken)
        {
            var provider = await _store.FindByEntityIdAsync(entityId, cancellationToken);
            if (provider is null)
            {
                return null;
            }

            if (!string.Equals(provider.EntityId, entityId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0574));
            }

            OpenIddictServerSamlConfiguration.ValidateServiceProvider(provider, _options.CurrentValue);

            return provider;
        }
    }

    /// <summary>
    /// Validates an authentication request sent using the HTTP-Redirect binding.
    /// </summary>
    /// <param name="query">The raw (URL-encoded) query string of the request.</param>
    /// <param name="endpoint">The absolute URL of the single sign-on endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation result.</returns>
    public ValueTask<AuthenticationRequestResult> ValidateRedirectAuthenticationRequestAsync(
        string? query, Uri endpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        return ExecuteAsync(query, endpoint, cancellationToken);

        async ValueTask<AuthenticationRequestResult> ExecuteAsync(string? query, Uri endpoint, CancellationToken cancellationToken)
        {
            var options = _options.CurrentValue;

            var parameters = ParseRedirectQueryString(query);
            if (parameters is null)
            {
                return Reject(SR.ID2259);
            }

            parameters.TryGetValue(Parameters.RelayState, out var state);
            var relayState = parameters.ContainsKey(Parameters.RelayState) ? state.Value : null;

            if (!parameters.TryGetValue(Parameters.SamlRequest, out var request) || string.IsNullOrEmpty(request.Value))
            {
                return Reject(SR.ID2266, relayState: relayState);
            }

            if (request.Value.Length > options.MaximumMessageSize * 2)
            {
                return Reject(SR.ID2247, relayState: relayState);
            }

            if (DecodeBase64(request.Value) is not byte[] compressed)
            {
                return Reject(SR.ID2246, relayState: relayState);
            }

            var data = Inflate(compressed, options.MaximumMessageSize, out bool tooLarge);
            if (data is null)
            {
                return Reject(tooLarge ? SR.ID2247 : SR.ID2246, relayState: relayState);
            }

            SignatureValidationResult? result = null;
            (string Octets, string Algorithm, string Signature)? signature = null;

            if (parameters.TryGetValue(Parameters.Signature, out var value))
            {
                if (!parameters.TryGetValue(Parameters.SignatureAlgorithm, out var algorithm))
                {
                    result = SignatureValidationResult.Invalid;
                }

                else
                {
                    // Note: the signed octets are built from the raw values, as received (SAML bindings, 3.4.4.1).
                    var builder = new StringBuilder()
                        .Append(Parameters.SamlRequest).Append('=').Append(request.Raw);

                    if (parameters.ContainsKey(Parameters.RelayState))
                    {
                        builder.Append('&').Append(Parameters.RelayState).Append('=').Append(state.Raw);
                    }

                    builder.Append('&').Append(Parameters.SignatureAlgorithm).Append('=').Append(algorithm.Raw);

                    signature = (builder.ToString(), algorithm.Value, value.Value);
                }
            }

            else
            {
                result = SignatureValidationResult.Missing;
            }

            return await ValidateAsync(data, Bindings.HttpRedirect, relayState, endpoint, result, signature, cancellationToken);
        }
    }

    /// <summary>
    /// Validates an authentication request sent using the HTTP-POST binding.
    /// </summary>
    /// <param name="request">The SAMLRequest form parameter.</param>
    /// <param name="relayState">The RelayState form parameter, if any.</param>
    /// <param name="endpoint">The absolute URL of the single sign-on endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation result.</returns>
    public ValueTask<AuthenticationRequestResult> ValidatePostAuthenticationRequestAsync(
        string? request, string? relayState, Uri endpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        return ExecuteAsync(request, relayState, endpoint, cancellationToken);

        async ValueTask<AuthenticationRequestResult> ExecuteAsync(
            string? request, string? relayState, Uri endpoint, CancellationToken cancellationToken)
        {
            var options = _options.CurrentValue;

            if (string.IsNullOrEmpty(request))
            {
                return Reject(SR.ID2266, relayState: relayState);
            }

            if (request.Length > options.MaximumMessageSize * 2)
            {
                return Reject(SR.ID2247, relayState: relayState);
            }

            if (DecodeBase64(request) is not byte[] data || data.Length is 0)
            {
                return Reject(SR.ID2246, relayState: relayState);
            }

            if (data.Length > options.MaximumMessageSize)
            {
                return Reject(SR.ID2247, relayState: relayState);
            }

            return await ValidateAsync(data, Bindings.HttpPost, relayState, endpoint, result: null, signature: null, cancellationToken);
        }
    }

    /// <summary>
    /// Validates an identity provider-initiated (unsolicited) single sign-on request.
    /// </summary>
    /// <param name="entityId">The entity identifier of the service provider.</param>
    /// <param name="relayState">The relay state, if any.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation result.</returns>
    public ValueTask<AuthenticationRequestResult> ValidateIdentityProviderInitiatedRequestAsync(
        string? entityId, string? relayState, CancellationToken cancellationToken = default)
    {
        return ExecuteAsync(entityId, relayState, cancellationToken);

        async ValueTask<AuthenticationRequestResult> ExecuteAsync(string? entityId, string? relayState, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(entityId) || await FindServiceProviderAsync(entityId, cancellationToken) is not { } provider)
            {
                return Reject(SR.ID2251, relayState: relayState);
            }

            if (!provider.AllowIdentityProviderInitiatedSingleSignOn)
            {
                return Reject(SR.ID2262, provider, relayState: relayState);
            }

            return new AuthenticationRequestResult
            {
                AssertionConsumerServiceUrl = provider.AssertionConsumerServiceUrls[0],
                CanReturnErrorToServiceProvider = true,
                RelayState = relayState,
                ResponseBinding = GetAssertionConsumerServiceBinding(provider, index: 0),
                ServiceProvider = provider
            };
        }
    }

    /// <summary>
    /// Creates the state that must be persisted (and protected) by the host while the user is authenticated.
    /// </summary>
    /// <param name="result">The successful validation result.</param>
    /// <param name="lifetime">The lifetime of the state.</param>
    /// <returns>The request state.</returns>
    public RequestState CreateRequestState(AuthenticationRequestResult result, TimeSpan lifetime)
    {
        ArgumentNullException.ThrowIfNull(result);

        if (!result.Succeeded || result.ServiceProvider?.EntityId is not { Length: > 0 } entityId ||
            result.AssertionConsumerServiceUrl is null)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0576), nameof(result));
        }

        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime));
        }

        var now = _options.CurrentValue.TimeProvider.GetUtcNow();

        return new RequestState
        {
            AssertionConsumerServiceUrl = result.AssertionConsumerServiceUrl,
            // Note: authentication tickets typically store their issuance date with a precision of one second.
            CreationDate = new DateTimeOffset(now.UtcTicks - now.UtcTicks % TimeSpan.TicksPerSecond, TimeSpan.Zero),
            ExpirationDate = now + lifetime,
            Id = CreateIdentifier(),
            RelayState = result.RelayState,
            Request = result.Request,
            ResponseBinding = result.ResponseBinding,
            ServiceProvider = entityId
        };
    }

    /// <summary>
    /// Marks a validated request state as used. When request replay protection is enabled (default), this method must be
    /// called before returning a response to the service provider (ideally once the response was successfully created):
    /// it returns <see langword="false"/> if the state was already used (or the replay cache couldn't store it), in which case
    /// no response must be returned.
    /// </summary>
    /// <param name="state">The request state.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the state can be used, <see langword="false"/> otherwise.</returns>
    public ValueTask<bool> ConsumeRequestStateAsync(RequestState state, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(state);

        if (!_options.CurrentValue.EnableRequestReplayProtection)
        {
            return new(true);
        }

        return ExecuteAsync(state, cancellationToken);

        async ValueTask<bool> ExecuteAsync(RequestState state, CancellationToken cancellationToken)
        {
            if (!await _replayCache.TryAddAsync(GetRequestStateReplayIdentifier(state), state.ExpirationDate, cancellationToken))
            {
                _logger.LogInformation(6643, SR.GetResourceString(SR.ID6643), SR.GetResourceString(SR.ID2263));
                return false;
            }

            return true;
        }
    }

    // Note: states created by the previous version don't have an identifier: to avoid breaking the logins that are in
    // progress during an upgrade, they are bound to a single use using the values identifying the original request
    // (these states are short-lived and can no longer be created, so this fallback only applies during their lifetime).
    private static string GetRequestStateReplayIdentifier(RequestState state)
        => !string.IsNullOrEmpty(state.Id) ? "request-state:" + state.Id : string.Join("\n",
            "legacy-request-state:" + state.ServiceProvider,
            state.AssertionConsumerServiceUrl.AbsoluteUri,
            state.CreationDate.UtcTicks.ToString(CultureInfo.InvariantCulture),
            state.ExpirationDate.UtcTicks.ToString(CultureInfo.InvariantCulture),
            state.Request?.Id);

    /// <summary>
    /// Validates a request state restored by the host after the user was authenticated. The service provider is resolved
    /// again and the assertion consumer service URL, the signature requirement and the identity provider-initiated
    /// single sign-on setting are checked again to ensure the service provider was not updated in the meantime.
    /// </summary>
    /// <param name="state">The request state, or <see langword="null"/> if it couldn't be restored.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation result.</returns>
    public ValueTask<AuthenticationRequestResult> ValidateRequestStateAsync(RequestState? state, CancellationToken cancellationToken = default)
    {
        return ExecuteAsync(state, cancellationToken);

        async ValueTask<AuthenticationRequestResult> ExecuteAsync(RequestState? state, CancellationToken cancellationToken)
        {
            if (state is null || state.ExpirationDate < _options.CurrentValue.TimeProvider.GetUtcNow() ||
                string.IsNullOrEmpty(state.ServiceProvider))
            {
                return Reject(SR.ID2263);
            }

            var binding = state.ResponseBinding ?? Bindings.HttpPost;

            if (await FindServiceProviderAsync(state.ServiceProvider, cancellationToken) is not { } provider ||
                !HasAssertionConsumerService(provider, state.AssertionConsumerServiceUrl, binding) ||
                (binding is Bindings.HttpArtifact && !_options.CurrentValue.EnableArtifactBinding) ||
                (state.Request is null && !provider.AllowIdentityProviderInitiatedSingleSignOn) ||
                (state.Request is { IsSigned: false } && provider.RequireSignedAuthenticationRequests) ||
                (state.Request is not null && !string.Equals(state.Request.Issuer, provider.EntityId, StringComparison.Ordinal)))
            {
                return Reject(SR.ID2263);
            }

            return new AuthenticationRequestResult
            {
                AssertionConsumerServiceUrl = state.AssertionConsumerServiceUrl,
                CanReturnErrorToServiceProvider = true,
                RelayState = state.RelayState,
                Request = state.Request,
                RequestId = state.Request?.Id,
                ResponseBinding = binding,
                ServiceProvider = provider
            };
        }

        static bool HasAssertionConsumerService(OpenIddictServerSamlServiceProvider provider, Uri url, string binding)
        {
            for (var index = 0; index < provider.AssertionConsumerServiceUrls.Count; index++)
            {
                if (IsSameUrl(provider.AssertionConsumerServiceUrls[index], url) &&
                    string.Equals(GetAssertionConsumerServiceBinding(provider, index), binding, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }

    /// <summary>
    /// Serializes a request state (the serialized payload must be protected by the host).
    /// </summary>
    /// <param name="state">The request state.</param>
    /// <returns>The serialized state.</returns>
    public static byte[] SerializeRequestState(RequestState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(RequestStateVersion);
            writer.Write(state.ServiceProvider);
            writer.Write(state.AssertionConsumerServiceUrl.AbsoluteUri);
            WriteNullable(writer, state.RelayState);
            writer.Write(state.CreationDate.UtcTicks);
            writer.Write(state.ExpirationDate.UtcTicks);

            writer.Write(state.Request is not null);
            if (state.Request is AuthenticationRequest request)
            {
                writer.Write(request.Id);
                writer.Write(request.Issuer);
                writer.Write(request.IssueInstant.UtcTicks);
                writer.Write(request.Binding);
                WriteNullable(writer, request.Destination);
                writer.Write(request.ForceAuthentication);
                writer.Write(request.IsPassive);
                WriteNullable(writer, request.NameIdFormat);
                writer.Write(request.IsSigned);
            }

            WriteNullable(writer, state.Id);
            WriteNullable(writer, state.ResponseBinding);
        }

        return stream.ToArray();

        static void WriteNullable(BinaryWriter writer, string? value)
        {
            writer.Write(value is not null);
            if (value is not null)
            {
                writer.Write(value);
            }
        }
    }

    /// <summary>
    /// Deserializes a request state serialized using <see cref="SerializeRequestState(RequestState)"/>.
    /// </summary>
    /// <param name="data">The serialized state.</param>
    /// <returns>The request state, or <see langword="null"/> if the payload is invalid.</returns>
    public static RequestState? DeserializeRequestState(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        try
        {
            using var stream = new MemoryStream(data, writable: false);
            using var reader = new BinaryReader(stream, Encoding.UTF8);

            // Note: states created by the previous version (without identifier and response binding) can still be
            // deserialized and consumed once by ConsumeRequestStateAsync() (see GetRequestStateReplayIdentifier()).
            // States created by this version are not understood by the previous version (rolling upgrades).
            var version = reader.ReadByte();
            if (version is not (RequestStateVersion or LegacyRequestStateVersion))
            {
                return null;
            }

            var provider = reader.ReadString();
            var url = new Uri(reader.ReadString(), UriKind.Absolute);
            var relayState = ReadNullable(reader);
            var creation = new DateTimeOffset(reader.ReadInt64(), TimeSpan.Zero);
            var expiration = new DateTimeOffset(reader.ReadInt64(), TimeSpan.Zero);

            AuthenticationRequest? request = null;
            if (reader.ReadBoolean())
            {
                request = new AuthenticationRequest
                {
                    Id = reader.ReadString(),
                    Issuer = reader.ReadString(),
                    IssueInstant = new DateTimeOffset(reader.ReadInt64(), TimeSpan.Zero),
                    Binding = reader.ReadString(),
                    Destination = ReadNullable(reader),
                    ForceAuthentication = reader.ReadBoolean(),
                    IsPassive = reader.ReadBoolean(),
                    NameIdFormat = ReadNullable(reader),
                    IsSigned = reader.ReadBoolean()
                };
            }

            string? identifier = null, binding = null;
            if (version is RequestStateVersion)
            {
                identifier = ReadNullable(reader);
                binding = ReadNullable(reader);
            }

            if (stream.Position != stream.Length)
            {
                return null;
            }

            return new RequestState
            {
                AssertionConsumerServiceUrl = url,
                CreationDate = creation,
                ExpirationDate = expiration,
                Id = identifier,
                RelayState = relayState,
                Request = request,
                ResponseBinding = binding,
                ServiceProvider = provider
            };
        }

        catch (Exception exception) when (exception is ArgumentException or EndOfStreamException or FormatException or IOException)
        {
            return null;
        }

        static string? ReadNullable(BinaryReader reader) => reader.ReadBoolean() ? reader.ReadString() : null;
    }

    private async ValueTask<AuthenticationRequestResult> ValidateAsync(byte[] data, string binding, string? relayState, Uri endpoint,
        SignatureValidationResult? result, (string Octets, string Algorithm, string Signature)? signature,
        CancellationToken cancellationToken)
    {
        var options = _options.CurrentValue;

        if (LoadDocument(data, options.MaximumMessageSize, out bool containsDocumentType) is not XmlDocument document)
        {
            return Reject(containsDocumentType ? SR.ID2248 : SR.ID2246, relayState: relayState);
        }

        var root = document.DocumentElement!;
        if (!string.Equals(root.LocalName, Elements.AuthnRequest, StringComparison.Ordinal) ||
            !string.Equals(root.NamespaceURI, Namespaces.Protocol, StringComparison.Ordinal) ||
            !string.Equals(root.GetAttribute("Version"), "2.0", StringComparison.Ordinal))
        {
            return Reject(SR.ID2249, relayState: relayState);
        }

        var identifier = root.GetAttribute("ID");
        if (string.IsNullOrEmpty(identifier) || !IsNCName(identifier) ||
            !TryParseInstant(root.GetAttribute("IssueInstant"), out var instant))
        {
            return Reject(SR.ID2249, relayState: relayState);
        }

        var issuers = GetChildElements(root, Elements.Issuer, Namespaces.Assertion);
        if (issuers.Count is not 1 || GetTextContent(issuers[0]) is not { Length: > 0 } issuer)
        {
            return Reject(SR.ID2251, relayState: relayState);
        }

        if (await FindServiceProviderAsync(issuer, cancellationToken) is not { } provider)
        {
            return Reject(SR.ID2251, relayState: relayState);
        }

        // Validate the signature before using any other value of the request.
        if (signature is var (octets, algorithm, value))
        {
            result = ValidateRedirectSignature(octets, algorithm, value, provider.SigningCertificates);
        }

        else if (binding is Bindings.HttpPost)
        {
            result = ValidateRootSignature(root, provider.SigningCertificates);
        }

        switch (result)
        {
            case SignatureValidationResult.Invalid:
                return Reject(SR.ID2254, provider, relayState);

            case SignatureValidationResult.UnsupportedAlgorithm:
                return Reject(SR.ID2255, provider, relayState);

            case SignatureValidationResult.Missing when provider.RequireSignedAuthenticationRequests:
                return Reject(SR.ID2253, provider, relayState);
        }

        var signed = result is SignatureValidationResult.Valid;

        var now = options.TimeProvider.GetUtcNow();
        if (instant > now + options.ClockSkew || instant < now - options.AuthenticationRequestLifetime - options.ClockSkew)
        {
            return Reject(SR.ID2250, provider, relayState);
        }

        var destination = root.HasAttribute("Destination") ? root.GetAttribute("Destination") : null;
        if ((signed && string.IsNullOrEmpty(destination)) || (destination is not null && !IsSameUrl(destination, endpoint)))
        {
            return Reject(SR.ID2252, provider, relayState);
        }

        // Resolve the assertion consumer service URL, that must correspond to a registered URL.
        var url = root.HasAttribute("AssertionConsumerServiceURL") ? root.GetAttribute("AssertionConsumerServiceURL") : null;
        var index = root.HasAttribute("AssertionConsumerServiceIndex") ? root.GetAttribute("AssertionConsumerServiceIndex") : null;
        var protocolBinding = root.HasAttribute("ProtocolBinding") ? root.GetAttribute("ProtocolBinding") : null;

        // Note: AssertionConsumerServiceIndex is mutually exclusive with the AssertionConsumerServiceURL and ProtocolBinding
        // attributes (SAML core, 3.4.1). For compatibility with service providers sending both, requests combining the index
        // with ProtocolBinding are accepted when the binding matches the binding of the indexed endpoint: otherwise, an
        // UnsupportedBinding error is returned to the service provider (see below). Index + URL requests are rejected.
        int? position = (url, index) switch
        {
            (not null, not null) => null,
            (not null, null) => FindAssertionConsumerService(provider, url, protocolBinding),
            (null, not null) => int.TryParse(index, NumberStyles.None, CultureInfo.InvariantCulture, out var number) &&
                number < provider.AssertionConsumerServiceUrls.Count ? number : null,

            // Note: when no endpoint is specified, the default endpoint is used: if a ProtocolBinding
            // is specified, the first endpoint supporting this binding is preferred (SAML profiles, 4.1.4.1).
            _ => FindAssertionConsumerServiceByBinding(provider, protocolBinding) ?? 0
        };

        if (position is not int acsIndex)
        {
            return Reject(SR.ID2256, provider, relayState);
        }

        var acs = provider.AssertionConsumerServiceUrls[acsIndex];

        // Note: the binding used to return the response is the binding of the selected
        // assertion consumer service endpoint (SAML profiles, 4.1.4.1 and SAML metadata, 2.2.3).
        var responseBinding = GetAssertionConsumerServiceBinding(provider, acsIndex);

        // When replay protection is enabled, reject authentication requests whose identifier was already used
        // by the same service provider while the request is still considered fresh (message identifiers are unique
        // per SAML core, 1.3.4). This check is only done once the issuer, signature and destination were validated.
        if (options.EnableRequestReplayProtection && !await _replayCache.TryAddAsync(
            "authentication-request:" + issuer + "\n" + identifier,
            instant + options.AuthenticationRequestLifetime + options.ClockSkew, cancellationToken))
        {
            _logger.LogInformation(6643, SR.GetResourceString(SR.ID6643), SR.GetResourceString(SR.ID2420));

            return Reject(SR.ID2420, provider, relayState);
        }

        // From this point, errors can be returned to the service provider.
        if (protocolBinding is not null && !string.Equals(protocolBinding, responseBinding, StringComparison.Ordinal))
        {
            return Reject(SR.ID2257, provider, relayState, acs, identifier, StatusCodes.Responder, StatusCodes.UnsupportedBinding, responseBinding);
        }

        if (GetChildElements(root, Elements.Subject, Namespaces.Assertion).Count is not 0)
        {
            return Reject(SR.ID2265, provider, relayState, acs, identifier, StatusCodes.Requester, StatusCodes.RequestUnsupported, responseBinding);
        }

        string? format = null;

        var policies = GetChildElements(root, Elements.NameIdPolicy, Namespaces.Protocol);
        if (policies.Count > 1)
        {
            return Reject(SR.ID2249, provider, relayState, acs, identifier, StatusCodes.Requester, binding: responseBinding);
        }

        if (policies.Count is 1 && policies[0].HasAttribute("Format"))
        {
            format = policies[0].GetAttribute("Format");

            if (format is not NameIdFormats.Unspecified && !string.Equals(format, provider.NameIdFormat, StringComparison.Ordinal))
            {
                return Reject(SR.ID2258, provider, relayState, acs, identifier, StatusCodes.Requester, StatusCodes.InvalidNameIdPolicy, responseBinding);
            }
        }

        if (!TryParseBoolean(root, "ForceAuthn", out var force) || !TryParseBoolean(root, "IsPassive", out var passive))
        {
            return Reject(SR.ID2249, provider, relayState, acs, identifier, StatusCodes.Requester, binding: responseBinding);
        }

        return new AuthenticationRequestResult
        {
            AssertionConsumerServiceUrl = acs,
            CanReturnErrorToServiceProvider = true,
            RelayState = relayState,
            RequestId = identifier,
            ResponseBinding = responseBinding,
            Request = new AuthenticationRequest
            {
                Binding = binding,
                Destination = destination,
                ForceAuthentication = force,
                Id = identifier,
                IsPassive = passive,
                IssueInstant = instant,
                Issuer = issuer,
                IsSigned = signed,
                NameIdFormat = format
            },
            ServiceProvider = provider
        };

        static int? FindAssertionConsumerServiceByBinding(OpenIddictServerSamlServiceProvider provider, string? binding)
        {
            if (binding is null)
            {
                return null;
            }

            for (var index = 0; index < provider.AssertionConsumerServiceUrls.Count; index++)
            {
                if (string.Equals(GetAssertionConsumerServiceBinding(provider, index), binding, StringComparison.Ordinal))
                {
                    return index;
                }
            }

            return null;
        }

        static int? FindAssertionConsumerService(OpenIddictServerSamlServiceProvider provider, string url, string? binding)
        {
            int? match = null;

            for (var index = 0; index < provider.AssertionConsumerServiceUrls.Count; index++)
            {
                if (!IsSameUrl(url, provider.AssertionConsumerServiceUrls[index]))
                {
                    continue;
                }

                // Prefer the endpoint registered with the requested binding, if any.
                if (binding is null || string.Equals(GetAssertionConsumerServiceBinding(provider, index), binding, StringComparison.Ordinal))
                {
                    return index;
                }

                match ??= index;
            }

            return match;
        }

        static bool TryParseBoolean(XmlElement element, string name, out bool value)
        {
            value = false;

            if (!element.HasAttribute(name))
            {
                return true;
            }

            switch (element.GetAttribute(name).Trim())
            {
                case "true" or "1":
                    value = true;
                    return true;

                case "false" or "0":
                    return true;

                default: return false;
            }
        }
    }

    private AuthenticationRequestResult Reject(string description, OpenIddictServerSamlServiceProvider? provider = null,
        string? relayState = null, Uri? acs = null, string? identifier = null,
        string status = StatusCodes.Requester, string? secondLevelStatus = null, string? binding = null)
    {
        var message = SR.GetResourceString(description);

        _logger.LogInformation(6324, SR.GetResourceString(SR.ID6324), message);

        return new AuthenticationRequestResult
        {
            AssertionConsumerServiceUrl = acs,
            CanReturnErrorToServiceProvider = acs is not null,
            ErrorDescription = message,
            RelayState = relayState,
            RequestId = identifier,
            ResponseBinding = acs is not null ? binding ?? Bindings.HttpPost : null,
            SecondLevelStatus = secondLevelStatus,
            ServiceProvider = provider,
            Status = status
        };
    }

    /// <summary>
    /// Creates a SAML response containing a signed assertion (for successful responses) or an error status.
    /// </summary>
    /// <param name="descriptor">The response descriptor.</param>
    /// <returns>The serialized XML response (not base64-encoded).</returns>
    public string CreateResponse(ResponseDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);

        var options = _options.CurrentValue;
        var provider = descriptor.ServiceProvider;

        if (descriptor.Assertion is not null && string.IsNullOrEmpty(descriptor.Assertion.NameId))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0575));
        }

        var certificate = GetSigningCertificate(options);
        var now = options.TimeProvider.GetUtcNow();
        var acs = descriptor.AssertionConsumerServiceUrl.AbsoluteUri;

        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };

        var response = document.CreateElement("samlp", Elements.Response, Namespaces.Protocol);
        response.SetAttribute("xmlns:saml", Namespaces.Assertion);
        response.SetAttribute("ID", CreateIdentifier());
        response.SetAttribute("Version", "2.0");
        response.SetAttribute("IssueInstant", FormatInstant(now));
        response.SetAttribute("Destination", acs);

        if (!string.IsNullOrEmpty(descriptor.InResponseTo))
        {
            response.SetAttribute("InResponseTo", descriptor.InResponseTo);
        }

        document.AppendChild(response);

        var issuer = AppendElement(response, "saml", Elements.Issuer, Namespaces.Assertion, options.EntityId);

        var status = AppendElement(response, "samlp", Elements.Status, Namespaces.Protocol);
        var code = AppendElement(status, "samlp", Elements.StatusCode, Namespaces.Protocol);
        code.SetAttribute("Value", descriptor.Assertion is null ? descriptor.Status : StatusCodes.Success);

        if (descriptor.Assertion is null && !string.IsNullOrEmpty(descriptor.SecondLevelStatus))
        {
            AppendElement(code, "samlp", Elements.StatusCode, Namespaces.Protocol).SetAttribute("Value", descriptor.SecondLevelStatus);
        }

        if (descriptor.Assertion is null && !string.IsNullOrEmpty(descriptor.StatusMessage))
        {
            AppendElement(status, "samlp", Elements.StatusMessage, Namespaces.Protocol, descriptor.StatusMessage);
        }

        if (descriptor.Assertion is AssertionDescriptor assertion)
        {
            var expiration = now + (provider.AssertionLifetime ?? options.AssertionLifetime);

            var element = AppendElement(response, "saml", Elements.Assertion, Namespaces.Assertion);
            element.SetAttribute("ID", CreateIdentifier());
            element.SetAttribute("Version", "2.0");
            element.SetAttribute("IssueInstant", FormatInstant(now));

            var assertionIssuer = AppendElement(element, "saml", Elements.Issuer, Namespaces.Assertion, options.EntityId);

            var subject = AppendElement(element, "saml", Elements.Subject, Namespaces.Assertion);
            var name = AppendElement(subject, "saml", Elements.NameId, Namespaces.Assertion, assertion.NameId);
            name.SetAttribute("Format", assertion.NameIdFormat);

            var confirmation = AppendElement(subject, "saml", Elements.SubjectConfirmation, Namespaces.Assertion);
            confirmation.SetAttribute("Method", ConfirmationMethods.Bearer);

            var data = AppendElement(confirmation, "saml", Elements.SubjectConfirmationData, Namespaces.Assertion);
            if (!string.IsNullOrEmpty(descriptor.InResponseTo))
            {
                data.SetAttribute("InResponseTo", descriptor.InResponseTo);
            }

            data.SetAttribute("NotOnOrAfter", FormatInstant(expiration));
            data.SetAttribute("Recipient", acs);

            var conditions = AppendElement(element, "saml", Elements.Conditions, Namespaces.Assertion);
            conditions.SetAttribute("NotBefore", FormatInstant(now));
            conditions.SetAttribute("NotOnOrAfter", FormatInstant(expiration));

            var restriction = AppendElement(conditions, "saml", Elements.AudienceRestriction, Namespaces.Assertion);
            AppendElement(restriction, "saml", Elements.Audience, Namespaces.Assertion, provider.EntityId);

            var statement = AppendElement(element, "saml", Elements.AuthnStatement, Namespaces.Assertion);
            statement.SetAttribute("AuthnInstant", FormatInstant(assertion.AuthenticationInstant ?? now));

            if (!string.IsNullOrEmpty(assertion.SessionIndex))
            {
                statement.SetAttribute("SessionIndex", assertion.SessionIndex);
            }

            var context = AppendElement(statement, "saml", Elements.AuthnContext, Namespaces.Assertion);
            AppendElement(context, "saml", Elements.AuthnContextClassRef, Namespaces.Assertion, assertion.AuthenticationContextClass);

            if (assertion.Attributes.Count is not 0)
            {
                var attributes = AppendElement(element, "saml", Elements.AttributeStatement, Namespaces.Assertion);

                foreach (var attribute in assertion.Attributes)
                {
                    var node = AppendElement(attributes, "saml", Elements.Attribute, Namespaces.Assertion);
                    node.SetAttribute("Name", attribute.Name);
                    node.SetAttribute("NameFormat", attribute.NameFormat);

                    foreach (var value in attribute.Values)
                    {
                        AppendElement(node, "saml", Elements.AttributeValue, Namespaces.Assertion, value);
                    }
                }
            }

            SignElement(element, assertionIssuer, certificate, options.SignatureAlgorithm, options.DigestAlgorithm);

            // When encryption is enabled, the signed assertion is replaced by an EncryptedAssertion element (SAML core, 2.3.4)
            // containing the serialized assertion encrypted for the service provider (sign-then-encrypt, SAML core, 6.2).
            if (provider.EncryptAssertions)
            {
                if (provider.EncryptionCertificate is not X509Certificate2 encryptionCertificate)
                {
                    throw new InvalidOperationException(SR.FormatID0844(provider.EntityId));
                }

                // Note: the assertion is serialized in its own document to ensure the namespaces
                // declared by its ancestors are declared on the assertion element itself.
                var standalone = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
                standalone.AppendChild(standalone.ImportNode(element, deep: true));

                var encrypted = document.CreateElement("saml", Elements.EncryptedAssertion, Namespaces.Assertion);
                encrypted.AppendChild(CreateEncryptedData(document, Encoding.UTF8.GetBytes(standalone.OuterXml), encryptionCertificate,
                    provider.DataEncryptionAlgorithm ?? options.DataEncryptionAlgorithm,
                    provider.KeyTransportAlgorithm ?? options.KeyTransportAlgorithm,
                    provider.EntityId));

                response.ReplaceChild(encrypted, element);

                _logger.LogInformation(6644, SR.GetResourceString(SR.ID6644), provider.EntityId);
            }

            else
            {
                _logger.LogInformation(6325, SR.GetResourceString(SR.ID6325), provider.EntityId);
            }
        }

        else
        {
            _logger.LogInformation(6326, SR.GetResourceString(SR.ID6326), descriptor.Status, provider.EntityId, descriptor.StatusMessage);
        }

        // Note: error responses are always signed, as they don't contain a signed assertion.
        if (descriptor.Assertion is null || (provider.SignResponses ?? options.SignResponses))
        {
            SignElement(response, issuer, certificate, options.SignatureAlgorithm, options.DigestAlgorithm);
        }

        return document.OuterXml;
    }

    /// <summary>
    /// Creates the metadata document (EntityDescriptor) of the identity provider.
    /// </summary>
    /// <param name="endpoint">The absolute URL of the single sign-on endpoint.</param>
    /// <returns>The serialized XML metadata.</returns>
    public string CreateMetadata(Uri endpoint) => CreateMetadata(endpoint, artifactResolutionEndpoint: null);

    /// <summary>
    /// Creates the metadata document (EntityDescriptor) of the identity provider.
    /// </summary>
    /// <param name="endpoint">The absolute URL of the single sign-on endpoint.</param>
    /// <param name="artifactResolutionEndpoint">
    /// The absolute URL of the artifact resolution endpoint, published when the artifact binding is enabled.
    /// </param>
    /// <returns>The serialized XML metadata.</returns>
    public string CreateMetadata(Uri endpoint, Uri? artifactResolutionEndpoint)
        => CreateMetadata(endpoint, artifactResolutionEndpoint, singleLogoutEndpoint: null);

    /// <summary>
    /// Creates the metadata document (EntityDescriptor) of the identity provider.
    /// </summary>
    /// <param name="endpoint">The absolute URL of the single sign-on endpoint.</param>
    /// <param name="artifactResolutionEndpoint">
    /// The absolute URL of the artifact resolution endpoint, published when the artifact binding is enabled.
    /// </param>
    /// <param name="singleLogoutEndpoint">
    /// The absolute URL of the single logout endpoint, published when single logout is enabled.
    /// </param>
    /// <returns>The serialized XML metadata.</returns>
    public string CreateMetadata(Uri endpoint, Uri? artifactResolutionEndpoint, Uri? singleLogoutEndpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        var options = _options.CurrentValue;

        var document = new XmlDocument { XmlResolver = null };

        var descriptor = document.CreateElement("md", Elements.EntityDescriptor, Namespaces.Metadata);
        descriptor.SetAttribute("entityID", options.EntityId);
        document.AppendChild(descriptor);

        // Note: WantAuthnRequestsSigned is an identity provider-wide statement (SAML metadata, 2.4.3). Custom stores
        // cannot be enumerated: unless it is explicitly set, the attribute is only derived from the service providers
        // when they are all known (i.e when the default store, backed by the options, is used). Otherwise, the default
        // requirement of service providers (signed authentication requests) is advertised.
        var signed = options.WantAuthenticationRequestsSigned ?? (_store is not OpenIddictServerSamlServiceProviderStore ||
            options.ServiceProviders.TrueForAll(static provider => provider.RequireSignedAuthenticationRequests));

        var idp = AppendElement(descriptor, "md", Elements.IdpSsoDescriptor, Namespaces.Metadata);
        idp.SetAttribute("WantAuthnRequestsSigned", signed ? "true" : "false");
        idp.SetAttribute("protocolSupportEnumeration", Namespaces.Protocol);

        foreach (var certificate in options.SigningCertificates)
        {
            var key = AppendElement(idp, "md", Elements.KeyDescriptor, Namespaces.Metadata);
            key.SetAttribute("use", "signing");

            var info = AppendElement(key, "ds", Elements.KeyInfo, Namespaces.XmlDsig);
            var data = AppendElement(info, "ds", Elements.X509Data, Namespaces.XmlDsig);
            AppendElement(data, "ds", Elements.X509Certificate, Namespaces.XmlDsig, Convert.ToBase64String(certificate.RawData));
        }

        // Note: ArtifactResolutionService elements must precede NameIDFormat elements (SAML metadata, 2.4.2).
        if (options.EnableArtifactBinding && artifactResolutionEndpoint is not null)
        {
            var service = AppendElement(idp, "md", Elements.ArtifactResolutionService, Namespaces.Metadata);
            service.SetAttribute("Binding", Bindings.Soap);
            service.SetAttribute("Location", artifactResolutionEndpoint.AbsoluteUri);
            service.SetAttribute("index", "0");
            service.SetAttribute("isDefault", "true");
        }

        // Note: SingleLogoutService elements must follow ArtifactResolutionService elements and precede NameIDFormat
        // elements (SAML metadata, 2.4.2). The single logout endpoint supports the HTTP-Redirect, HTTP-POST and SOAP bindings.
        if (options.EnableSingleLogout && singleLogoutEndpoint is not null)
        {
            foreach (var binding in (string[]) [Bindings.HttpRedirect, Bindings.HttpPost, Bindings.Soap])
            {
                var service = AppendElement(idp, "md", Elements.SingleLogoutService, Namespaces.Metadata);
                service.SetAttribute("Binding", binding);
                service.SetAttribute("Location", singleLogoutEndpoint.AbsoluteUri);
            }
        }

        foreach (var format in (string[]) [NameIdFormats.EmailAddress, NameIdFormats.Persistent, NameIdFormats.Transient, NameIdFormats.Unspecified])
        {
            AppendElement(idp, "md", Elements.NameIdFormat, Namespaces.Metadata, format);
        }

        foreach (var binding in (string[]) [Bindings.HttpRedirect, Bindings.HttpPost])
        {
            var service = AppendElement(idp, "md", Elements.SingleSignOnService, Namespaces.Metadata);
            service.SetAttribute("Binding", binding);
            service.SetAttribute("Location", endpoint.AbsoluteUri);
        }

        return document.OuterXml;
    }

    /// <summary>
    /// Stores a SAML response and returns the artifact (type 0x0004) representing it, that must be returned to the
    /// assertion consumer service using the HTTP-Artifact binding (SAML bindings, 3.6). The artifact can be resolved
    /// once, by the service provider the response is intended for, until the configured artifact lifetime elapses.
    /// </summary>
    /// <param name="provider">The service provider the response is intended for.</param>
    /// <param name="response">The serialized XML response returned by <see cref="CreateResponse(ResponseDescriptor)"/>.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The base64-encoded artifact.</returns>
    /// <exception cref="InvalidOperationException">The artifact binding is not enabled.</exception>
    public ValueTask<string> CreateArtifactAsync(OpenIddictServerSamlServiceProvider provider,
        string response, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentException.ThrowIfNullOrEmpty(response);

        if (!_options.CurrentValue.EnableArtifactBinding)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0846));
        }

        return ExecuteAsync(provider, response, cancellationToken);

        async ValueTask<string> ExecuteAsync(OpenIddictServerSamlServiceProvider provider, string response, CancellationToken cancellationToken)
        {
            var options = _options.CurrentValue;

            var artifact = CreateArtifact(options.EntityId!, endpointIndex: 0, out var handle);

            await _artifactStore.AddAsync(Convert.ToBase64String(handle), new ArtifactMessage
            {
                ExpirationDate = options.TimeProvider.GetUtcNow() + options.ArtifactLifetime,
                Message = response,
                ServiceProvider = provider.EntityId!
            }, cancellationToken);

            _logger.LogInformation(6640, SR.GetResourceString(SR.ID6640), provider.EntityId);

            return artifact;
        }
    }

    /// <summary>
    /// Creates the URL used to return an artifact to an assertion consumer service using
    /// the URL encoding of the HTTP-Artifact binding (SAML bindings, 3.6.3.2).
    /// </summary>
    /// <param name="url">The assertion consumer service URL.</param>
    /// <param name="artifact">The artifact returned by <see cref="CreateArtifactAsync"/>.</param>
    /// <param name="relayState">The relay state, if any.</param>
    /// <returns>The URL the user agent must be redirected to (using a 302 or 303 status code).</returns>
    public static Uri CreateArtifactRedirectUrl(Uri url, string artifact, string? relayState)
    {
        ArgumentNullException.ThrowIfNull(url);
        ArgumentException.ThrowIfNullOrEmpty(artifact);

        var builder = new StringBuilder(url.AbsoluteUri);

        builder.Append(url.Query switch
        {
            { Length: > 1 } => "&",
            "?" => string.Empty,
            _ => "?"
        });

        builder.Append(Parameters.SamlArtifact).Append('=').Append(Uri.EscapeDataString(artifact));

        if (relayState is not null)
        {
            builder.Append('&').Append(Parameters.RelayState).Append('=').Append(Uri.EscapeDataString(relayState));
        }

        return new Uri(builder.ToString(), UriKind.Absolute);
    }

    /// <summary>
    /// Processes an artifact resolution request sent using the SOAP binding (SAML core, 3.5 and SAML bindings, 3.2) and
    /// returns the SOAP envelope containing the signed ArtifactResponse or a SOAP fault if the message cannot be processed.
    /// </summary>
    /// <remarks>
    /// The ArtifactResolve message must be signed by the service provider the artifact was issued to: otherwise, and when the
    /// artifact is unknown, expired or was already resolved, an empty response is returned (SAML core, 3.5.3). Artifacts are
    /// removed from the store once an authenticated requester tries to resolve them.
    /// </remarks>
    /// <param name="body">The HTTP request body.</param>
    /// <param name="endpoint">The absolute URL of the artifact resolution endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The artifact resolution result.</returns>
    /// <exception cref="InvalidOperationException">The artifact binding is not enabled.</exception>
    public ValueTask<ArtifactResolutionResult> ResolveArtifactAsync(Stream body, Uri endpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(body);
        ArgumentNullException.ThrowIfNull(endpoint);

        if (!_options.CurrentValue.EnableArtifactBinding)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0846));
        }

        return ExecuteAsync(body, endpoint, cancellationToken);

        async ValueTask<ArtifactResolutionResult> ExecuteAsync(Stream body, Uri endpoint, CancellationToken cancellationToken)
        {
            var options = _options.CurrentValue;

            if (await ReadBodyAsync(body, options.MaximumMessageSize, cancellationToken) is not byte[] data ||
                LoadDocument(data, options.MaximumMessageSize, out _) is not XmlDocument document)
            {
                return CreateFault(SoapFaultCodes.Client, SR.ID2421);
            }

            // Note: the SAML SOAP binding uses SOAP 1.1 (SAML bindings, 3.2.2.1).
            var envelope = document.DocumentElement!;
            if (!string.Equals(envelope.LocalName, Elements.Envelope, StringComparison.Ordinal) ||
                !string.Equals(envelope.NamespaceURI, Namespaces.Soap11, StringComparison.Ordinal) ||
                GetChildElements(envelope, Elements.Body, Namespaces.Soap11) is not [XmlElement soapBody] ||
                GetSoapChildElements(soapBody) is not [XmlElement request])
            {
                return CreateFault(SoapFaultCodes.Client, SR.ID2421);
            }

            // SOAP headers are allowed (SAML bindings, 3.2.2.2) but the headers that must be understood are not supported.
            if (HasMandatorySoapHeaders(envelope))
            {
                return CreateFault(SoapFaultCodes.MustUnderstand, SR.ID2422);
            }

            if (!string.Equals(request.LocalName, Elements.ArtifactResolve, StringComparison.Ordinal) ||
                !string.Equals(request.NamespaceURI, Namespaces.Protocol, StringComparison.Ordinal) ||
                !string.Equals(request.GetAttribute("Version"), "2.0", StringComparison.Ordinal) ||
                request.GetAttribute("ID") is not { Length: > 0 } identifier || !IsNCName(identifier) ||
                !TryParseInstant(request.GetAttribute("IssueInstant"), out var instant) ||
                GetChildElements(request, Elements.Issuer, Namespaces.Assertion) is not [XmlElement issuerElement] ||
                GetTextContent(issuerElement) is not { Length: > 0 } issuer ||
                GetChildElements(request, Elements.Artifact, Namespaces.Protocol) is not [XmlElement artifactElement] ||
                GetTextContent(artifactElement) is not { Length: > 0 } artifact)
            {
                return CreateFault(SoapFaultCodes.Client, SR.ID2421);
            }

            // The requester must be authenticated before the artifact is resolved (SAML bindings, 3.6.5.2).
            if (await FindServiceProviderAsync(issuer, cancellationToken) is not { } provider ||
                ValidateMessageSignature(request, provider.SigningCertificates) is not SignatureValidationResult.Valid)
            {
                return CreateEmptyResponse(identifier, SR.ID2423);
            }

            var now = options.TimeProvider.GetUtcNow();
            if (instant > now + options.ClockSkew || instant < now - options.AuthenticationRequestLifetime - options.ClockSkew ||
                (request.HasAttribute("Destination") && !IsSameUrl(request.GetAttribute("Destination"), endpoint)))
            {
                return CreateEmptyResponse(identifier, SR.ID2424);
            }

            if (ParseArtifact(artifact, options.EntityId!) is not byte[] handle ||
                await _artifactStore.RemoveAsync(Convert.ToBase64String(handle), cancellationToken) is not ArtifactMessage message ||
                message.ExpirationDate < now)
            {
                return CreateEmptyResponse(identifier, SR.ID2425);
            }

            // Note: the artifact is removed even if it was not issued to the requester, to enforce single use (SAML core, 3.5.3).
            if (!string.Equals(message.ServiceProvider, provider.EntityId, StringComparison.Ordinal))
            {
                return CreateEmptyResponse(identifier, SR.ID2426);
            }

            var payload = Encoding.UTF8.GetBytes(message.Message);
            if (LoadDocument(payload, payload.Length, out _) is not XmlDocument embedded)
            {
                return CreateEmptyResponse(identifier, SR.ID2425);
            }

            _logger.LogInformation(6641, SR.GetResourceString(SR.ID6641), provider.EntityId);

            return new ArtifactResolutionResult
            {
                Content = CreateArtifactResponse(options, identifier, embedded.DocumentElement),
                Resolved = true
            };
        }

        ArtifactResolutionResult CreateEmptyResponse(string identifier, string description)
        {
            var message = SR.GetResourceString(description);

            _logger.LogInformation(6642, SR.GetResourceString(SR.ID6642), message);

            return new ArtifactResolutionResult
            {
                Content = CreateArtifactResponse(_options.CurrentValue, identifier, message: null),
                ErrorDescription = message
            };
        }

        ArtifactResolutionResult CreateFault(string code, string description)
        {
            var message = SR.GetResourceString(description);

            _logger.LogInformation(6642, SR.GetResourceString(SR.ID6642), message);

            return new ArtifactResolutionResult { Content = CreateSoapFault(code, message), ErrorDescription = message, IsFault = true };
        }
    }

    private string CreateArtifactResponse(OpenIddictServerSamlOptions options, string inResponseTo, XmlElement? message)
    {
        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };

        var envelope = document.CreateElement("soap", Elements.Envelope, Namespaces.Soap11);
        envelope.SetAttribute("xmlns:soap", Namespaces.Soap11);
        document.AppendChild(envelope);

        var body = AppendElement(envelope, "soap", Elements.Body, Namespaces.Soap11);

        var response = AppendElement(body, "samlp", Elements.ArtifactResponse, Namespaces.Protocol);
        response.SetAttribute("xmlns:samlp", Namespaces.Protocol);
        response.SetAttribute("xmlns:saml", Namespaces.Assertion);
        response.SetAttribute("ID", CreateIdentifier());
        response.SetAttribute("Version", "2.0");
        response.SetAttribute("IssueInstant", FormatInstant(options.TimeProvider.GetUtcNow()));
        response.SetAttribute("InResponseTo", inResponseTo);

        var issuer = AppendElement(response, "saml", Elements.Issuer, Namespaces.Assertion, options.EntityId);

        // Note: the status is always Success, even for empty responses (SAML core, 3.5.3 and SAML bindings, 3.6.6).
        var status = AppendElement(response, "samlp", Elements.Status, Namespaces.Protocol);
        AppendElement(status, "samlp", Elements.StatusCode, Namespaces.Protocol).SetAttribute("Value", StatusCodes.Success);

        if (message is not null)
        {
            response.AppendChild(document.ImportNode(message, deep: true));
        }

        SignElement(response, issuer, GetSigningCertificate(options), options.SignatureAlgorithm, options.DigestAlgorithm);

        return document.OuterXml;
    }

    /// <summary>
    /// Creates an HTML page automatically posting the SAML response to the assertion consumer service.
    /// </summary>
    /// <param name="url">The assertion consumer service URL.</param>
    /// <param name="response">The serialized XML response returned by <see cref="CreateResponse(ResponseDescriptor)"/>.</param>
    /// <param name="relayState">The relay state, if any.</param>
    /// <param name="nonce">The nonce attached to the inline script (that must be allowed by the content security policy).</param>
    /// <returns>The HTML page.</returns>
    public static string CreateFormPostPage(Uri url, string response, string? relayState, string nonce)
    {
        ArgumentNullException.ThrowIfNull(url);
        ArgumentException.ThrowIfNullOrEmpty(response);
        ArgumentException.ThrowIfNullOrEmpty(nonce);

        var fields = new List<KeyValuePair<string, string>>
        {
            new(Parameters.SamlResponse, Convert.ToBase64String(Encoding.UTF8.GetBytes(response)))
        };

        if (relayState is not null)
        {
            fields.Add(new(Parameters.RelayState, relayState));
        }

        return OpenIddict.Extensions.OpenIddictSamlHelpers.CreateFormPostPage(url, fields, nonce);
    }

    internal static X509Certificate2 GetSigningCertificate(OpenIddictServerSamlOptions options)
    {
        var now = options.TimeProvider.GetUtcNow().UtcDateTime;

        return options.SigningCertificates.Find(certificate => certificate.HasPrivateKey &&
                   certificate.NotBefore.ToUniversalTime() <= now && certificate.NotAfter.ToUniversalTime() >= now) ??
               options.SigningCertificates.Find(static certificate => certificate.HasPrivateKey) ??
               throw new InvalidOperationException(SR.GetResourceString(SR.ID0566));
    }

    private static string GetAssertionConsumerServiceBinding(OpenIddictServerSamlServiceProvider provider, int index)
        => provider.AssertionConsumerServiceBindings.TryGetValue(index, out var binding) ? binding : Bindings.HttpPost;
}
