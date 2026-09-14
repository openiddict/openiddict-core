/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static OpenIddict.Client.Saml.OpenIddictClientSamlConstants;
using static OpenIddict.Client.Saml.OpenIddictClientSamlModels;
using static OpenIddict.Extensions.OpenIddictSamlHelpers;
using Parameters = OpenIddict.Client.Saml.OpenIddictClientSamlConstants.Parameters;

namespace OpenIddict.Client.Saml;

/// <summary>
/// Provides the host-agnostic SAML 2.0 service provider operations: registration and identity provider metadata
/// resolution, authentication request generation, response and assertion validation and metadata generation.
/// </summary>
public sealed partial class OpenIddictClientSamlService
{
    private const byte RequestStateVersion = 1;
    private const int MaximumCachedLookups = 4096;
    private const string ListCacheKey = "list";
    private const string IdentifierCacheKeyPrefix = "id:";
    private const string EntityIdCacheKeyPrefix = "entity:";
    private const string ProviderNameCacheKeyPrefix = "name:";

    private readonly ConcurrentDictionary<string, (IdentityProviderConfiguration Configuration, Uri Address, DateTimeOffset ExpirationDate)> _configurations
        = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, (ImmutableArray<OpenIddictClientSamlRegistration> Registrations, DateTimeOffset ExpirationDate)> _lookups
        = new(StringComparer.Ordinal);

    private readonly ILogger<OpenIddictClientSamlService> _logger;
    private readonly IOptionsMonitor<OpenIddictClientSamlOptions> _options;
    private readonly IServiceProvider _provider;
    private ImmutableArray<IOpenIddictClientSamlRegistrationProvider> _registrationProviders;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSamlService"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="options">The SAML options.</param>
    /// <param name="provider">The service provider.</param>
    public OpenIddictClientSamlService(
        ILogger<OpenIddictClientSamlService> logger,
        IOptionsMonitor<OpenIddictClientSamlOptions> options,
        IServiceProvider provider)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <summary>
    /// Gets all the registrations attached to the options or returned by the
    /// registered <see cref="IOpenIddictClientSamlRegistrationProvider"/> instances.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The registrations.</returns>
    /// <remarks>
    /// The results are cached for <see cref="OpenIddictClientSamlOptions.DynamicRegistrationCacheLifetime"/>.
    /// Invalid dynamic registrations are logged and ignored.
    /// </remarks>
    public ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> GetRegistrationsAsync(CancellationToken cancellationToken = default)
        => ResolveRegistrationsAsync(ListCacheKey, static (provider, _, cancellationToken) => provider.ListAsync(cancellationToken),
            state: (object?) null, cancellationToken);

    /// <summary>
    /// Resolves the registrations associated with the specified identity provider entity identifier.
    /// </summary>
    /// <param name="entityId">The entity identifier of the identity provider.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The registrations.</returns>
    /// <remarks>
    /// The results are cached for <see cref="OpenIddictClientSamlOptions.DynamicRegistrationCacheLifetime"/>.
    /// Invalid dynamic registrations are logged and ignored.
    /// </remarks>
    public ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> GetRegistrationsByEntityIdAsync(
        string entityId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(entityId);

        return ResolveRegistrationsAsync(EntityIdCacheKeyPrefix + entityId, static (provider, entityId, cancellationToken) =>
            provider.FindByEntityIdAsync(entityId, cancellationToken), entityId, cancellationToken);
    }

    /// <summary>
    /// Resolves the registrations associated with the specified provider name.
    /// </summary>
    /// <param name="name">The provider name.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The registrations.</returns>
    /// <remarks>
    /// The results (including empty results) are cached for <see cref="OpenIddictClientSamlOptions.DynamicRegistrationCacheLifetime"/>.
    /// Invalid dynamic registrations are logged and ignored.
    /// </remarks>
    public ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> GetRegistrationsByProviderNameAsync(
        string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        return ResolveRegistrationsAsync(ProviderNameCacheKeyPrefix + name, static (provider, name, cancellationToken) =>
            provider.FindByProviderNameAsync(name, cancellationToken), name, cancellationToken);
    }

    /// <summary>
    /// Resolves the registration associated with the specified provider name.
    /// </summary>
    /// <param name="name">The provider name.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The registration.</returns>
    /// <exception cref="InvalidOperationException">No registration or multiple registrations were found.</exception>
    public ValueTask<OpenIddictClientSamlRegistration> GetRegistrationByProviderNameAsync(string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        return ExecuteAsync(name, cancellationToken);

        async ValueTask<OpenIddictClientSamlRegistration> ExecuteAsync(string name, CancellationToken cancellationToken)
            => await GetRegistrationsByProviderNameAsync(name, cancellationToken) switch
            {
                [var registration] => registration,
                [] => throw new InvalidOperationException(SR.GetResourceString(SR.ID0894)),
                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0895))
            };
    }

    /// <summary>
    /// Resolves the registration associated with the specified identifier.
    /// </summary>
    /// <param name="identifier">The registration identifier.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The registration.</returns>
    /// <exception cref="InvalidOperationException">No registration was found or the resolved registration is invalid.</exception>
    /// <remarks>
    /// Dynamic registrations are cached for <see cref="OpenIddictClientSamlOptions.DynamicRegistrationCacheLifetime"/>:
    /// a registration updated or removed by its provider is only taken into account once the cache entry expires,
    /// once another lookup returns the updated registration or once <see cref="ClearCache"/> is called.
    /// </remarks>
    public ValueTask<OpenIddictClientSamlRegistration> GetRegistrationByIdAsync(string identifier, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var options = _options.CurrentValue;

        // Static registrations are always preferred to dynamic registrations.
        if (options.Registrations.Find(registration => string.Equals(
            registration.RegistrationId, identifier, StringComparison.Ordinal)) is OpenIddictClientSamlRegistration registration)
        {
            return new(registration);
        }

        if (TryGetCachedLookup(IdentifierCacheKeyPrefix + identifier, options, out var cached))
        {
            return cached is [var result] ? new(result) : throw new InvalidOperationException(SR.GetResourceString(SR.ID0893));
        }

        return ExecuteAsync(identifier, cancellationToken);

        async ValueTask<OpenIddictClientSamlRegistration> ExecuteAsync(string identifier, CancellationToken cancellationToken)
        {
            foreach (var provider in GetRegistrationProviders())
            {
                if (await provider.FindByIdAsync(identifier, cancellationToken) is not OpenIddictClientSamlRegistration registration)
                {
                    continue;
                }

                registration = InitializeRegistration(registration);

                // Note: the identifier of the resolved registration MUST match the requested identifier
                // (e.g the identifier stored in the request state), as it's used to resolve it in later requests.
                if (!string.Equals(registration.RegistrationId, identifier, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0896));
                }

                CacheLookup(IdentifierCacheKeyPrefix + identifier, [registration]);

                return registration;
            }

            // Note: negative results are also cached (identifiers are typically extracted from protected request states).
            CacheLookup(IdentifierCacheKeyPrefix + identifier, []);

            throw new InvalidOperationException(SR.GetResourceString(SR.ID0893));
        }
    }

    /// <summary>
    /// Removes all the cached registration lookups and identity provider configurations, which forces
    /// the registration providers to be queried and the metadata documents to be retrieved again.
    /// Applications using dynamic registrations should call it when a registration is updated or removed.
    /// </summary>
    public void ClearCache()
    {
        _lookups.Clear();
        _configurations.Clear();
    }

    private async ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> ResolveRegistrationsAsync<TState>(string key,
        Func<IOpenIddictClientSamlRegistrationProvider, TState, CancellationToken, ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>>> resolver,
        TState state, CancellationToken cancellationToken)
    {
        if (TryGetCachedLookup(key, _options.CurrentValue, out var cached))
        {
            return cached;
        }

        var builder = ImmutableArray.CreateBuilder<OpenIddictClientSamlRegistration>();

        foreach (var provider in GetRegistrationProviders())
        {
            foreach (var registration in await resolver(provider, state, cancellationToken))
            {
                if (registration is null)
                {
                    continue;
                }

                OpenIddictClientSamlRegistration result;

                try
                {
                    result = InitializeRegistration(registration);
                }

                // Note: an invalid dynamic registration must not prevent the other registrations from being used.
                catch (InvalidOperationException exception)
                {
                    _logger.LogWarning(6685, exception, SR.GetResourceString(SR.ID6685), registration.RegistrationId);
                    continue;
                }

                // Note: the same registration may be returned by multiple providers.
                if (!Contains(builder, result))
                {
                    builder.Add(result);
                }
            }
        }

        var registrations = builder.ToImmutable();

        CacheLookup(key, registrations);

        // Note: registrations freshly returned by a provider are authoritative and replace the registrations
        // previously cached by identifier, so that updated registrations are used as soon as they are resolved.
        foreach (var registration in registrations)
        {
            if (!string.IsNullOrEmpty(registration.RegistrationId) && !IsStaticRegistration(registration))
            {
                CacheLookup(IdentifierCacheKeyPrefix + registration.RegistrationId, [registration]);
            }
        }

        return registrations;

        static bool Contains(ImmutableArray<OpenIddictClientSamlRegistration>.Builder builder, OpenIddictClientSamlRegistration registration)
        {
            for (var index = 0; index < builder.Count; index++)
            {
                if (ReferenceEquals(builder[index], registration))
                {
                    return true;
                }
            }

            return false;
        }
    }

    private bool TryGetCachedLookup(string key, OpenIddictClientSamlOptions options,
        out ImmutableArray<OpenIddictClientSamlRegistration> registrations)
    {
        if (_lookups.TryGetValue(key, out var entry) && entry.ExpirationDate > options.TimeProvider.GetUtcNow())
        {
            registrations = entry.Registrations;
            return true;
        }

        registrations = default;
        return false;
    }

    private void CacheLookup(string key, ImmutableArray<OpenIddictClientSamlRegistration> registrations)
    {
        var options = _options.CurrentValue;

        if (options.DynamicRegistrationCacheLifetime is not TimeSpan lifetime || lifetime <= TimeSpan.Zero)
        {
            return;
        }

        var now = options.TimeProvider.GetUtcNow();

        if (_lookups.Count >= MaximumCachedLookups)
        {
            foreach (var item in _lookups)
            {
                if (item.Value.ExpirationDate <= now)
                {
                    ((ICollection<KeyValuePair<string, (ImmutableArray<OpenIddictClientSamlRegistration>, DateTimeOffset)>>) _lookups).Remove(item);
                }
            }

            // Note: to prevent unbounded memory consumption (e.g when the entity identifiers of unsolicited
            // responses are attacker-controlled), new lookups are not cached when the cache is full.
            if (_lookups.Count >= MaximumCachedLookups && !_lookups.ContainsKey(key))
            {
                return;
            }
        }

        _lookups[key] = (registrations, now + lifetime);
    }

    private ImmutableArray<IOpenIddictClientSamlRegistrationProvider> GetRegistrationProviders()
    {
        if (_registrationProviders.IsDefault)
        {
            _registrationProviders = [.. _provider.GetServices<IOpenIddictClientSamlRegistrationProvider>()];
        }

        return _registrationProviders;
    }

    private bool IsStaticRegistration(OpenIddictClientSamlRegistration registration)
        => _options.CurrentValue.Registrations.Exists(item => ReferenceEquals(item, registration));

    /// <summary>
    /// Initializes and validates the specified registration returned by a registration provider.
    /// </summary>
    private OpenIddictClientSamlRegistration InitializeRegistration(OpenIddictClientSamlRegistration registration)
    {
        var options = _options.CurrentValue;

        // Note: static registrations are initialized and validated when the options are built.
        if (options.Registrations.Exists(item => ReferenceEquals(item, registration)))
        {
            return registration;
        }

        // Note: dynamic registrations are always validated when they are returned by a provider, as their
        // settings (e.g signing certificates or unsolicited responses support) may have been updated.
        OpenIddictClientSamlConfiguration.ConfigureRegistration(registration);
        OpenIddictClientSamlConfiguration.ValidateRegistration(options, registration, isDynamic: true);

        if (options.Registrations.Exists(item => string.Equals(item.RegistrationId, registration.RegistrationId, StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0897));
        }

        return registration;
    }

    /// <summary>
    /// Resolves the identity provider configuration of the specified registration, importing
    /// (and caching) the identity provider metadata document if a metadata address is set.
    /// </summary>
    /// <param name="registration">The registration.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The identity provider configuration.</returns>
    /// <exception cref="InvalidOperationException">The metadata document cannot be retrieved or is invalid.</exception>
    public ValueTask<IdentityProviderConfiguration> GetIdentityProviderConfigurationAsync(
        OpenIddictClientSamlRegistration registration, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(registration);

        var options = _options.CurrentValue;

        if (registration.MetadataAddress is not Uri address)
        {
            return new(new IdentityProviderConfiguration
            {
                EntityId = registration.IdentityProviderEntityId!,
                SigningCertificates = [.. registration.SigningCertificates],
                SingleSignOnServices = registration.SingleSignOnServiceUrl is Uri url
                    ? ImmutableDictionary.CreateRange(StringComparer.Ordinal, [new KeyValuePair<string, Uri>(registration.AuthenticationRequestBinding, url)])
                    : ImmutableDictionary.Create<string, Uri>(StringComparer.Ordinal)
            });
        }

        var now = options.TimeProvider.GetUtcNow();
        var key = registration.RegistrationId ?? address.AbsoluteUri;

        if (_configurations.TryGetValue(key, out var entry) && entry.ExpirationDate > now && entry.Address == address &&
            !IsExpired(entry.Configuration, now))
        {
            return new(Merge(registration, entry.Configuration));
        }

        return ExecuteAsync(registration, address, key, cancellationToken);

        async ValueTask<IdentityProviderConfiguration> ExecuteAsync(
            OpenIddictClientSamlRegistration registration, Uri address, string key, CancellationToken cancellationToken)
        {
            var options = _options.CurrentValue;
            var retriever = _provider.GetRequiredService<IOpenIddictClientSamlMetadataRetriever>();

            IdentityProviderConfiguration configuration;

            try
            {
                var data = await retriever.RetrieveAsync(address, options.MaximumMetadataSize, cancellationToken);
                configuration = ParseMetadata(registration, data, options);
            }

            catch (Exception exception) when (exception is InvalidOperationException or IOException or
                UnauthorizedAccessException or System.Net.Http.HttpRequestException or TaskCanceledException &&
                !cancellationToken.IsCancellationRequested)
            {
                _logger.LogWarning(6684, exception, SR.GetResourceString(SR.ID6684), registration.RegistrationId);

                // If a previous version of the metadata is available and is not expired (SAML metadata, 2.3.1: validUntil),
                // keep using it and retry later. Expired metadata (and the signing keys it contains) is never trusted.
                var now = options.TimeProvider.GetUtcNow();
                if (_configurations.TryGetValue(key, out var stale) && stale.Address == address && !IsExpired(stale.Configuration, now))
                {
                    var delay = options.MetadataRefreshInterval < TimeSpan.FromMinutes(5) ? options.MetadataRefreshInterval : TimeSpan.FromMinutes(5);
                    _configurations[key] = (stale.Configuration, address, GetCacheExpiration(stale.Configuration, now + delay));

                    return Merge(registration, stale.Configuration);
                }

                _configurations.TryRemove(key, out _);

                throw new InvalidOperationException(SR.FormatID0898(registration.RegistrationId, exception.Message), exception);
            }

            _configurations[key] = (configuration, address, GetCacheExpiration(configuration,
                options.TimeProvider.GetUtcNow() + options.MetadataRefreshInterval));

            return Merge(registration, configuration);
        }

        static DateTimeOffset GetCacheExpiration(IdentityProviderConfiguration configuration, DateTimeOffset date)
            => configuration.ExpirationDate is DateTimeOffset expiration && expiration < date ? expiration : date;

        static bool IsExpired(IdentityProviderConfiguration configuration, DateTimeOffset now)
            => configuration.ExpirationDate is DateTimeOffset expiration && expiration <= now;

        static IdentityProviderConfiguration Merge(OpenIddictClientSamlRegistration registration, IdentityProviderConfiguration configuration)
            => configuration with
            {
                // Note: the values explicitly set in the registration take precedence over the metadata.
                SigningCertificates = registration.SigningCertificates.Count is not 0
                    ? [.. registration.SigningCertificates] : configuration.SigningCertificates,
                SingleSignOnServices = registration.SingleSignOnServiceUrl is Uri url
                    ? configuration.SingleSignOnServices.SetItem(registration.AuthenticationRequestBinding, url)
                    : configuration.SingleSignOnServices
            };
    }

    private static IdentityProviderConfiguration ParseMetadata(
        OpenIddictClientSamlRegistration registration, byte[] data, OpenIddictClientSamlOptions options)
    {
        var now = options.TimeProvider.GetUtcNow();

        if (LoadDocument(data, options.MaximumMetadataSize, out _) is not XmlDocument document)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0904));
        }

        var root = document.DocumentElement!;

        // If metadata signing certificates are configured, the root element MUST be signed using one of them
        // (SAML metadata, 3.1). The signature is validated before any other value is used.
        if (registration.MetadataSigningCertificates.Count is not 0 &&
            ValidateEnvelopedSignature(root, registration.MetadataSigningCertificates, out _) is not SignatureValidationResult.Valid)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0904));
        }

        var entity = FindEntityDescriptor(root, registration.IdentityProviderEntityId, now) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0904));

        var descriptor = GetChildElements(entity, "IDPSSODescriptor", Namespaces.Metadata).Find(element =>
            IsValid(element, now) && element.GetAttribute("protocolSupportEnumeration")
                .Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .Contains(Namespaces.Protocol, StringComparer.Ordinal)) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0904));

        var certificates = ImmutableArray.CreateBuilder<X509Certificate2>();

        foreach (var key in GetChildElements(descriptor, "KeyDescriptor", Namespaces.Metadata))
        {
            // Note: key descriptors without "use" attribute apply to both signing and encryption (SAML metadata, 2.4.1.1).
            if (key.HasAttribute("use") && !string.Equals(key.GetAttribute("use"), "signing", StringComparison.Ordinal))
            {
                continue;
            }

            foreach (var info in GetChildElements(key, "KeyInfo", Namespaces.XmlDsig))
            foreach (var x509 in GetChildElements(info, "X509Data", Namespaces.XmlDsig))
            foreach (var element in GetChildElements(x509, "X509Certificate", Namespaces.XmlDsig))
            {
                if (GetTextContent(element) is { Length: > 0 } text && DecodeBase64(RemoveWhitespace(text)) is byte[] bytes &&
                    LoadCertificate(bytes) is X509Certificate2 certificate)
                {
                    if (IsRsaCertificate(certificate))
                    {
                        certificates.Add(certificate);
                    }

                    else
                    {
                        certificate.Dispose();
                    }
                }
            }
        }

        var services = ImmutableDictionary.CreateBuilder<string, Uri>(StringComparer.Ordinal);

        foreach (var service in GetChildElements(descriptor, "SingleSignOnService", Namespaces.Metadata))
        {
            if (service.GetAttribute("Binding") is { Length: > 0 } binding && !services.ContainsKey(binding) &&
                Uri.TryCreate(service.GetAttribute("Location"), UriKind.Absolute, out var location) &&
                string.IsNullOrEmpty(location.Fragment) && OpenIddictClientSamlConfiguration.IsAllowedEndpointScheme(options, location))
            {
                services[binding] = location;
            }
        }

        if (certificates.Count is 0 && registration.SigningCertificates.Count is 0)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0904));
        }

        // SAML metadata, 2.3.1: validUntil indicates the expiration of the metadata and cacheDuration the maximum length
        // of time it should be cached. The most restrictive values of the descriptor and its ancestors are used.
        DateTimeOffset? expiration = null;

        for (var node = descriptor; node is not null; node = node.ParentNode as XmlElement)
        {
            if (node.HasAttribute("validUntil") && TryParseInstant(node.GetAttribute("validUntil"), out var date) &&
                (expiration is null || date < expiration))
            {
                expiration = date;
            }

            if (node.HasAttribute("cacheDuration"))
            {
                TimeSpan duration;

                try
                {
                    duration = XmlConvert.ToTimeSpan(node.GetAttribute("cacheDuration").Trim());
                }

                catch (Exception exception) when (exception is FormatException or OverflowException)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0904), exception);
                }

                if (duration < TimeSpan.Zero)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0904));
                }

                if (expiration is null || now + duration < expiration)
                {
                    expiration = now + duration;
                }
            }
        }

        return new IdentityProviderConfiguration
        {
            EntityId = entity.GetAttribute("entityID"),
            ExpirationDate = expiration,
            SigningCertificates = certificates.ToImmutable(),
            SingleSignOnServices = services.ToImmutable(),
            WantAuthenticationRequestsSigned = descriptor.GetAttribute("WantAuthnRequestsSigned").Trim() is "true" or "1"
        };

        static XmlElement? FindEntityDescriptor(XmlElement element, string? entityId, DateTimeOffset now)
        {
            if (!string.Equals(element.NamespaceURI, Namespaces.Metadata, StringComparison.Ordinal) || !IsValid(element, now))
            {
                return null;
            }

            if (string.Equals(element.LocalName, "EntityDescriptor", StringComparison.Ordinal))
            {
                var identifier = element.GetAttribute("entityID");

                return !string.IsNullOrEmpty(identifier) &&
                    (entityId is null || string.Equals(identifier, entityId, StringComparison.Ordinal)) ? element : null;
            }

            if (!string.Equals(element.LocalName, "EntitiesDescriptor", StringComparison.Ordinal))
            {
                return null;
            }

            // Note: when an aggregate is used, the entity identifier must be known to select the identity provider,
            // unless the aggregate contains a single identity provider.
            List<XmlElement> candidates = [];

            foreach (XmlNode node in element.ChildNodes)
            {
                if (node is XmlElement child && FindEntityDescriptor(child, entityId, now) is XmlElement candidate &&
                    GetChildElements(candidate, "IDPSSODescriptor", Namespaces.Metadata).Count is not 0)
                {
                    candidates.Add(candidate);
                }
            }

            return candidates.Count is 1 ? candidates[0] : null;
        }

        static bool IsValid(XmlElement element, DateTimeOffset now)
            => !element.HasAttribute("validUntil") ||
               (TryParseInstant(element.GetAttribute("validUntil"), out var date) && date > now);
    }

    /// <summary>
    /// Creates an authentication request for the specified registration.
    /// </summary>
    /// <param name="registration">The registration.</param>
    /// <param name="assertionConsumerServiceUrl">The absolute URL of the assertion consumer service.</param>
    /// <param name="relayState">The relay state (at most 80 bytes, per SAML bindings 3.4.3 and 3.5.3), if any.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authentication request.</returns>
    public ValueTask<AuthenticationRequestMessage> CreateAuthenticationRequestAsync(OpenIddictClientSamlRegistration registration,
        Uri assertionConsumerServiceUrl, string? relayState, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(assertionConsumerServiceUrl);

        if (!assertionConsumerServiceUrl.IsAbsoluteUri)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0909), nameof(assertionConsumerServiceUrl));
        }

        if (relayState is not null && Encoding.UTF8.GetByteCount(relayState) > 80)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0908), nameof(relayState));
        }

        return ExecuteAsync(registration, assertionConsumerServiceUrl, relayState, cancellationToken);

        async ValueTask<AuthenticationRequestMessage> ExecuteAsync(OpenIddictClientSamlRegistration registration,
            Uri acs, string? relayState, CancellationToken cancellationToken)
        {
            var options = _options.CurrentValue;
            var configuration = await GetIdentityProviderConfigurationAsync(registration, cancellationToken);

            var binding = registration.AuthenticationRequestBinding;
            if (!configuration.SingleSignOnServices.TryGetValue(binding, out var destination))
            {
                throw new InvalidOperationException(SR.FormatID0899(registration.RegistrationId, binding));
            }

            var sign = registration.SignAuthenticationRequests ??
                (options.SigningCertificates.Count is not 0 || configuration.WantAuthenticationRequestsSigned);

            var identifier = CreateIdentifier();
            var now = options.TimeProvider.GetUtcNow();

            var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };

            var request = document.CreateElement("samlp", "AuthnRequest", Namespaces.Protocol);
            request.SetAttribute("xmlns:saml", Namespaces.Assertion);
            request.SetAttribute("ID", identifier);
            request.SetAttribute("Version", "2.0");
            request.SetAttribute("IssueInstant", FormatInstant(now));
            request.SetAttribute("Destination", destination.AbsoluteUri);
            request.SetAttribute("AssertionConsumerServiceURL", acs.AbsoluteUri);
            request.SetAttribute("ProtocolBinding", Bindings.HttpPost);

            if (registration.ForceAuthentication)
            {
                request.SetAttribute("ForceAuthn", "true");
            }

            document.AppendChild(request);

            var issuer = AppendElement(request, "saml", "Issuer", Namespaces.Assertion, options.EntityId);

            var policy = AppendElement(request, "samlp", "NameIDPolicy", Namespaces.Protocol);
            if (!string.IsNullOrEmpty(registration.NameIdFormat))
            {
                policy.SetAttribute("Format", registration.NameIdFormat);
            }

            policy.SetAttribute("AllowCreate", "true");

            if (registration.AuthenticationContextClasses.Count is not 0)
            {
                var context = AppendElement(request, "samlp", "RequestedAuthnContext", Namespaces.Protocol);
                context.SetAttribute("Comparison", "exact");

                foreach (var value in registration.AuthenticationContextClasses)
                {
                    AppendElement(context, "saml", "AuthnContextClassRef", Namespaces.Assertion, value);
                }
            }

            X509Certificate2? certificate = sign ? GetSigningCertificate(options) : null;

            AuthenticationRequestMessage message;

            if (binding is Bindings.HttpRedirect)
            {
                var xml = document.OuterXml;

                // SAML bindings, 3.4.4.1: the request is deflated, base64-encoded and URL-encoded. When the request is signed,
                // the signature is computed over the "SAMLRequest", "RelayState" and "SigAlg" parameters, in this order.
                var query = new StringBuilder()
                    .Append(Parameters.SamlRequest).Append('=')
                    .Append(Uri.EscapeDataString(Convert.ToBase64String(Deflate(Encoding.UTF8.GetBytes(xml)))));

                if (relayState is not null)
                {
                    query.Append('&').Append(Parameters.RelayState).Append('=').Append(Uri.EscapeDataString(relayState));
                }

                if (certificate is not null)
                {
                    query.Append('&').Append(Parameters.SignatureAlgorithm).Append('=').Append(Uri.EscapeDataString(options.SignatureAlgorithm));

                    using var key = certificate.GetRSAPrivateKey() ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0881));
                    var signature = CreateRedirectSignature(query.ToString(), key, options.SignatureAlgorithm);

                    query.Append('&').Append(Parameters.Signature).Append('=').Append(Uri.EscapeDataString(signature));
                }

                var address = destination.AbsoluteUri;
                var separator = string.IsNullOrEmpty(destination.Query) ? "?" : destination.Query is "?" ? string.Empty : "&";

                message = new AuthenticationRequestMessage
                {
                    Binding = binding,
                    Destination = destination,
                    ForceAuthentication = registration.ForceAuthentication,
                    IsSigned = certificate is not null,
                    RedirectUrl = new Uri(address + separator + query, UriKind.Absolute),
                    RelayState = relayState,
                    RequestId = identifier,
                    Xml = xml
                };
            }

            else
            {
                if (certificate is not null)
                {
                    using var key = certificate.GetRSAPrivateKey() ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0881));
                    SignElement(request, issuer, certificate, key, options.SignatureAlgorithm, options.DigestAlgorithm);
                }

                var xml = document.OuterXml;

                var parameters = ImmutableDictionary.CreateBuilder<string, string>(StringComparer.Ordinal);
                parameters[Parameters.SamlRequest] = Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));

                if (relayState is not null)
                {
                    parameters[Parameters.RelayState] = relayState;
                }

                message = new AuthenticationRequestMessage
                {
                    Binding = binding,
                    Destination = destination,
                    ForceAuthentication = registration.ForceAuthentication,
                    FormParameters = parameters.ToImmutable(),
                    IsSigned = certificate is not null,
                    RelayState = relayState,
                    RequestId = identifier,
                    Xml = xml
                };
            }

            _logger.LogInformation(6682, SR.GetResourceString(SR.ID6682), identifier, configuration.EntityId, binding);

            return message;
        }
    }

    /// <summary>
    /// Creates the state that must be persisted (and protected) by the host until the response is received.
    /// </summary>
    /// <param name="registration">The registration the request was created for.</param>
    /// <param name="message">The authentication request.</param>
    /// <param name="assertionConsumerServiceUrl">The absolute URL of the assertion consumer service.</param>
    /// <param name="properties">The host-specific properties (e.g the return URL), if any.</param>
    /// <returns>The request state.</returns>
    public RequestState CreateRequestState(OpenIddictClientSamlRegistration registration, AuthenticationRequestMessage message,
        Uri assertionConsumerServiceUrl, IEnumerable<KeyValuePair<string, string?>>? properties = null)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(assertionConsumerServiceUrl);

        if (string.IsNullOrEmpty(registration.RegistrationId))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0885), nameof(registration));
        }

        var options = _options.CurrentValue;
        var now = options.TimeProvider.GetUtcNow();

        return new RequestState
        {
            AssertionConsumerServiceUrl = assertionConsumerServiceUrl,
            CreationDate = now,
            ExpirationDate = now + options.RequestStateLifetime,
            ForceAuthentication = message.ForceAuthentication,
            Properties = properties is null ? ImmutableDictionary<string, string?>.Empty
                : ImmutableDictionary.CreateRange(StringComparer.Ordinal, properties),
            RegistrationId = registration.RegistrationId,
            RelayState = message.RelayState,
            RequestId = message.RequestId
        };
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
            writer.Write(state.RequestId);
            writer.Write(state.RegistrationId);
            WriteNullable(writer, state.RelayState);
            writer.Write(state.AssertionConsumerServiceUrl.AbsoluteUri);
            writer.Write(state.CreationDate.UtcTicks);
            writer.Write(state.ExpirationDate.UtcTicks);
            writer.Write(state.ForceAuthentication);
            writer.Write(state.Properties.Count);

            foreach (var property in state.Properties)
            {
                writer.Write(property.Key);
                WriteNullable(writer, property.Value);
            }
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

            if (reader.ReadByte() is not RequestStateVersion)
            {
                return null;
            }

            var request = reader.ReadString();
            var registration = reader.ReadString();
            var relayState = ReadNullable(reader);
            var url = new Uri(reader.ReadString(), UriKind.Absolute);
            var creation = new DateTimeOffset(reader.ReadInt64(), TimeSpan.Zero);
            var expiration = new DateTimeOffset(reader.ReadInt64(), TimeSpan.Zero);
            var force = reader.ReadBoolean();

            var count = reader.ReadInt32();
            if (count < 0 || count > 1024)
            {
                return null;
            }

            var properties = ImmutableDictionary.CreateBuilder<string, string?>(StringComparer.Ordinal);
            for (var index = 0; index < count; index++)
            {
                properties[reader.ReadString()] = ReadNullable(reader);
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
                ForceAuthentication = force,
                Properties = properties.ToImmutable(),
                RegistrationId = registration,
                RelayState = relayState,
                RequestId = request
            };
        }

        catch (Exception exception) when (exception is ArgumentException or EndOfStreamException or FormatException or IOException or UriFormatException)
        {
            return null;
        }

        static string? ReadNullable(BinaryReader reader) => reader.ReadBoolean() ? reader.ReadString() : null;
    }

    /// <summary>
    /// Creates the metadata document (EntityDescriptor) of the service provider.
    /// </summary>
    /// <param name="assertionConsumerServiceUrl">The absolute URL of the assertion consumer service.</param>
    /// <returns>The serialized XML metadata.</returns>
    public string CreateMetadata(Uri assertionConsumerServiceUrl)
    {
        ArgumentNullException.ThrowIfNull(assertionConsumerServiceUrl);

        var options = _options.CurrentValue;

        var document = new XmlDocument { XmlResolver = null };

        var descriptor = document.CreateElement("md", "EntityDescriptor", Namespaces.Metadata);
        descriptor.SetAttribute("entityID", options.EntityId);
        document.AppendChild(descriptor);

        var sp = AppendElement(descriptor, "md", "SPSSODescriptor", Namespaces.Metadata);
        sp.SetAttribute("AuthnRequestsSigned", options.SigningCertificates.Count is not 0 ? "true" : "false");
        sp.SetAttribute("protocolSupportEnumeration", Namespaces.Protocol);

        foreach (var (certificates, use) in ((List<X509Certificate2>, string)[])
            [(options.SigningCertificates, "signing"), (options.EncryptionCertificates, "encryption")])
        {
            foreach (var certificate in certificates)
            {
                var key = AppendElement(sp, "md", "KeyDescriptor", Namespaces.Metadata);
                key.SetAttribute("use", use);

                var info = AppendElement(key, "ds", "KeyInfo", Namespaces.XmlDsig);
                var data = AppendElement(info, "ds", "X509Data", Namespaces.XmlDsig);
                AppendElement(data, "ds", "X509Certificate", Namespaces.XmlDsig, Convert.ToBase64String(certificate.RawData));
            }
        }

        var service = AppendElement(sp, "md", "AssertionConsumerService", Namespaces.Metadata);
        service.SetAttribute("Binding", Bindings.HttpPost);
        service.SetAttribute("Location", assertionConsumerServiceUrl.AbsoluteUri);
        service.SetAttribute("index", "0");
        service.SetAttribute("isDefault", "true");

        return document.OuterXml;
    }

    /// <summary>
    /// Creates an HTML page automatically posting the authentication request to the identity provider (HTTP-POST binding).
    /// </summary>
    /// <param name="message">The authentication request.</param>
    /// <param name="nonce">The nonce attached to the inline script (that must be allowed by the content security policy).</param>
    /// <returns>The HTML page.</returns>
    public static string CreateFormPostPage(AuthenticationRequestMessage message, string nonce)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentException.ThrowIfNullOrEmpty(nonce);

        return OpenIddict.Extensions.OpenIddictSamlHelpers.CreateFormPostPage(message.Destination, message.FormParameters, nonce);
    }

    /// <summary>
    /// Creates the content security policy that must be attached to the page returned by
    /// <see cref="CreateFormPostPage(AuthenticationRequestMessage, string)"/>.
    /// </summary>
    /// <param name="message">The authentication request.</param>
    /// <param name="nonce">The nonce attached to the inline script.</param>
    /// <returns>The content security policy.</returns>
    public static string CreateFormPostContentSecurityPolicy(AuthenticationRequestMessage message, string nonce)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentException.ThrowIfNullOrEmpty(nonce);

        return OpenIddict.Extensions.OpenIddictSamlHelpers.CreateFormPostContentSecurityPolicy(message.Destination, nonce);
    }

    private static X509Certificate2 GetSigningCertificate(OpenIddictClientSamlOptions options)
    {
        var now = options.TimeProvider.GetUtcNow().UtcDateTime;

        return options.SigningCertificates.Find(certificate => certificate.HasPrivateKey &&
                   certificate.NotBefore.ToUniversalTime() <= now && certificate.NotAfter.ToUniversalTime() >= now) ??
               options.SigningCertificates.Find(static certificate => certificate.HasPrivateKey) ??
               throw new InvalidOperationException(SR.GetResourceString(SR.ID0881));
    }

    private static X509Certificate2? LoadCertificate(byte[] data)
    {
        try
        {
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadCertificate(data);
#else
            return new X509Certificate2(data);
#endif
        }

        catch (CryptographicException)
        {
            return null;
        }
    }

    private static string RemoveWhitespace(string value)
    {
        var builder = new StringBuilder(value.Length);

        foreach (var character in value)
        {
            if (!char.IsWhiteSpace(character))
            {
                builder.Append(character);
            }
        }

        return builder.ToString();
    }
}
