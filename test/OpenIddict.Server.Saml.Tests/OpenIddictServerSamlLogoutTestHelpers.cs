using System.Collections.Immutable;
using System.Globalization;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Xml;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using Parameters = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.Parameters;

namespace OpenIddict.Server.Saml.Tests;

/// <summary>
/// Contains the helpers used to test SAML single logout (in-memory sessions, logout messages built as a service provider would).
/// </summary>
public static class OpenIddictServerSamlLogoutTestHelpers
{
    public const string ServiceProviderLogoutUrl = "https://sp.example.com/slo";
    public const string SecondServiceProviderEntityId = "https://sp2.example.com/metadata";
    public const string SecondServiceProviderLogoutUrl = "https://sp2.example.com/slo";
    public const string SingleLogoutEndpoint = "https://idp.example.com/saml/slo";
    public const string LoginIdClaimType = "login_id";

    public static X509Certificate2 SecondServiceProviderCertificate { get; } =
        OpenIddictServerSamlTestHelpers.CreateCertificate("CN=sp2.example.com");

    public static OpenIddictServerSamlServiceProvider CreateSecondServiceProvider(string binding = Bindings.HttpRedirect) => new()
    {
        AssertionConsumerServiceUrls = { new Uri("https://sp2.example.com/acs", UriKind.Absolute) },
        EntityId = SecondServiceProviderEntityId,
        SigningCertificates = { SecondServiceProviderCertificate },
        SingleLogoutServiceBinding = binding,
        SingleLogoutServiceUrl = new Uri(SecondServiceProviderLogoutUrl, UriKind.Absolute)
    };

    /// <summary>
    /// Registers the mocked core managers (backed by the specified in-memory sessions) and a minimal server configuration.
    /// </summary>
    public static Mock<IOpenIddictSessionManager> AddServerServices(IServiceCollection services, List<FakeSession> sessions,
        Action<OpenIddictServerBuilder>? configuration = null, Mock<IOpenIddictApplicationManager>? applications = null)
    {
        var manager = CreateSessionManager(sessions);

        services.AddLogging();
        services.AddSingleton(manager.Object);
        services.AddSingleton((applications ?? new Mock<IOpenIddictApplicationManager>()).Object);
        services.AddSingleton(Mock.Of<IOpenIddictTokenManager>());
        services.AddSingleton(Mock.Of<IOpenIddictAuthorizationManager>());

        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.SetTokenEndpointUris("connect/token")
                       .AllowClientCredentialsFlow()
                       .SetIssuer(new Uri(OpenIddictServerSamlTestHelpers.IdentityProviderEntityId, UriKind.Absolute))
                       .AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                configuration?.Invoke(options);
            });

        return manager;
    }

    public static Mock<IOpenIddictSessionManager> CreateSessionManager(List<FakeSession> sessions)
    {
        var manager = new Mock<IOpenIddictSessionManager>();

        manager.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictSessionDescriptor>(), It.IsAny<CancellationToken>()))
            .Returns((OpenIddictSessionDescriptor descriptor, CancellationToken _) =>
            {
                var session = new FakeSession
                {
                    ApplicationId = descriptor.ApplicationId,
                    AuthorizationId = descriptor.AuthorizationId,
                    ExpirationDate = descriptor.ExpirationDate,
                    Id = "saml-session-" + (sessions.Count + 1).ToString(CultureInfo.InvariantCulture),
                    LoginId = descriptor.LoginId,
                    Properties = descriptor.Properties.ToImmutableDictionary(StringComparer.Ordinal),
                    Status = descriptor.Status,
                    Subject = descriptor.Subject
                };

                lock (sessions)
                {
                    sessions.Add(session);
                }

                return new ValueTask<object>(session);
            });

        manager.Setup(mock => mock.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns((string identifier, CancellationToken _) => identifier.StartsWith("invalid:", StringComparison.Ordinal)
                // Note: stores using non-string keys (e.g GUIDs) throw an exception for identifiers that cannot be converted.
                ? throw new FormatException()
                : new ValueTask<object?>(sessions.Find(session => string.Equals(session.Id, identifier, StringComparison.Ordinal))));

        manager.Setup(mock => mock.FindByLoginIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns((string identifier, CancellationToken _) => ToAsyncEnumerableAsync(
                sessions.Where(session => string.Equals(session.LoginId, identifier, StringComparison.Ordinal)).ToList()));

        manager.Setup(mock => mock.FindAsync(It.IsAny<(string?, string?, string?, string?, string?)>(), It.IsAny<CancellationToken>()))
            .Returns(((string? Subject, string? LoginId, string? ApplicationId, string? AuthorizationId, string? Status) query, CancellationToken _) =>
                ToAsyncEnumerableAsync(sessions.Where(session =>
                    (query.Subject is null || string.Equals(session.Subject, query.Subject, StringComparison.Ordinal)) &&
                    (query.LoginId is null || string.Equals(session.LoginId, query.LoginId, StringComparison.Ordinal)) &&
                    (query.ApplicationId is null || string.Equals(session.ApplicationId, query.ApplicationId, StringComparison.Ordinal)) &&
                    (query.AuthorizationId is null || string.Equals(session.AuthorizationId, query.AuthorizationId, StringComparison.Ordinal)) &&
                    (query.Status is null || string.Equals(session.Status, query.Status, StringComparison.Ordinal))).ToList()));

        manager.Setup(mock => mock.GetIdAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .Returns((object session, CancellationToken _) => new ValueTask<string?>(((FakeSession) session).Id));

        manager.Setup(mock => mock.GetApplicationIdAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .Returns((object session, CancellationToken _) => new ValueTask<string?>(((FakeSession) session).ApplicationId));

        manager.Setup(mock => mock.GetAuthorizationIdAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .Returns((object session, CancellationToken _) => new ValueTask<string?>(((FakeSession) session).AuthorizationId));

        manager.Setup(mock => mock.GetLoginIdAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .Returns((object session, CancellationToken _) => new ValueTask<string?>(((FakeSession) session).LoginId));

        manager.Setup(mock => mock.GetSubjectAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .Returns((object session, CancellationToken _) => new ValueTask<string?>(((FakeSession) session).Subject));

        manager.Setup(mock => mock.GetPropertiesAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .Returns((object session, CancellationToken _) => new ValueTask<ImmutableDictionary<string, JsonElement>>(((FakeSession) session).Properties));

        manager.Setup(mock => mock.HasStatusAsync(It.IsAny<object>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns((object session, string status, CancellationToken _) => new ValueTask<bool>(string.Equals(((FakeSession) session).Status, status, StringComparison.Ordinal)));

        manager.Setup(mock => mock.HasExpiredAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .Returns((object session, CancellationToken _) => new ValueTask<bool>(false));

        manager.Setup(mock => mock.TryRevokeAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .Returns((object session, CancellationToken _) =>
            {
                ((FakeSession) session).Status = Statuses.Revoked;
                return new ValueTask<bool>(true);
            });

        return manager;
    }

    public static FakeSession CreateSamlSession(string identifier, string serviceProvider, string nameId,
        string login = "login-1", string subject = "alice", string? format = NameIdFormats.Unspecified) => new()
    {
        Id = identifier,
        LoginId = login,
        Properties = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            [SessionProperties.ServiceProvider] = JsonSerializer.SerializeToElement(serviceProvider),
            [SessionProperties.NameId] = JsonSerializer.SerializeToElement(nameId),
            [SessionProperties.NameIdFormat] = JsonSerializer.SerializeToElement(format)
        }.ToImmutableDictionary(StringComparer.Ordinal),
        Status = Statuses.Valid,
        Subject = subject
    };

    public static string CreateLogoutRequest(
        string? id = null,
        string? issuer = OpenIddictServerSamlTestHelpers.ServiceProviderEntityId,
        string? destination = SingleLogoutEndpoint,
        string? nameId = "alice",
        IEnumerable<string>? sessionIndexes = null,
        DateTimeOffset? issueInstant = null,
        string? attributes = null)
    {
        var builder = new StringBuilder()
            .Append("<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"")
            .Append(" ID=\"").Append(id ?? "_logout_" + Guid.NewGuid().ToString("N")).Append('"')
            .Append(" Version=\"2.0\"")
            .Append(" IssueInstant=\"").Append(FormatInstant(issueInstant ?? DateTimeOffset.UtcNow)).Append('"');

        if (destination is not null)
        {
            builder.Append(" Destination=\"").Append(destination).Append('"');
        }

        builder.Append(' ').Append(attributes).Append('>');

        if (issuer is not null)
        {
            builder.Append("<saml:Issuer>").Append(issuer).Append("</saml:Issuer>");
        }

        if (nameId is not null)
        {
            builder.Append("<saml:NameID>").Append(nameId).Append("</saml:NameID>");
        }

        foreach (var index in sessionIndexes ?? [])
        {
            builder.Append("<samlp:SessionIndex>").Append(index).Append("</samlp:SessionIndex>");
        }

        return builder.Append("</samlp:LogoutRequest>").ToString();
    }

    public static string CreateLogoutResponse(string inResponseTo,
        string issuer = SecondServiceProviderEntityId,
        string? destination = SingleLogoutEndpoint,
        string status = StatusCodes.Success,
        string? id = null)
    {
        var builder = new StringBuilder()
            .Append("<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"")
            .Append(" ID=\"").Append(id ?? "_response_" + Guid.NewGuid().ToString("N")).Append('"')
            .Append(" Version=\"2.0\"")
            .Append(" IssueInstant=\"").Append(FormatInstant(DateTimeOffset.UtcNow)).Append('"')
            .Append(" InResponseTo=\"").Append(inResponseTo).Append('"');

        if (destination is not null)
        {
            builder.Append(" Destination=\"").Append(destination).Append('"');
        }

        return builder.Append('>')
            .Append("<saml:Issuer>").Append(issuer).Append("</saml:Issuer>")
            .Append("<samlp:Status><samlp:StatusCode Value=\"").Append(status).Append("\" /></samlp:Status>")
            .Append("</samlp:LogoutResponse>")
            .ToString();
    }

    /// <summary>
    /// Decodes the SAML message contained in a URL created using the HTTP-Redirect binding and validates its signature.
    /// </summary>
    public static (XmlDocument Document, string? RelayState, bool SignatureValid) DecodeRedirectUrl(Uri url, string parameter, X509Certificate2 certificate)
    {
        var values = new Dictionary<string, (string Raw, string Value)>(StringComparer.Ordinal);

        foreach (var segment in url.Query.TrimStart('?').Split('&'))
        {
            var index = segment.IndexOf('=');
            values[segment[..index]] = (segment[(index + 1)..], Uri.UnescapeDataString(segment[(index + 1)..]));
        }

        using var input = new MemoryStream(Convert.FromBase64String(values[parameter].Value));
        using var stream = new DeflateStream(input, CompressionMode.Decompress);
        using var reader = new StreamReader(stream, Encoding.UTF8);

        var document = OpenIddictServerSamlTestHelpers.LoadResponse(reader.ReadToEnd());

        var octets = new StringBuilder().Append(parameter).Append('=').Append(values[parameter].Raw);
        if (values.TryGetValue(Parameters.RelayState, out var relayState))
        {
            octets.Append('&').Append(Parameters.RelayState).Append('=').Append(relayState.Raw);
        }

        octets.Append('&').Append(Parameters.SignatureAlgorithm).Append('=').Append(values[Parameters.SignatureAlgorithm].Raw);

        using var key = certificate.GetRSAPublicKey()!;
        var valid = key.VerifyData(Encoding.UTF8.GetBytes(octets.ToString()),
            Convert.FromBase64String(values[Parameters.Signature].Value), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return (document, values.TryGetValue(Parameters.RelayState, out var state) ? state.Value : null, valid);
    }

    public static string FormatInstant(DateTimeOffset date)
        => date.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    private static async IAsyncEnumerable<object> ToAsyncEnumerableAsync(
        IEnumerable<FakeSession> sessions, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        foreach (var session in sessions)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Yield();
            yield return session;
        }
    }

    public sealed class FakeSession
    {
        public string? ApplicationId { get; set; }

        public string? AuthorizationId { get; set; }

        public DateTimeOffset? ExpirationDate { get; set; }

        public required string Id { get; init; }

        public string? LoginId { get; set; }

        public ImmutableDictionary<string, JsonElement> Properties { get; set; } = ImmutableDictionary<string, JsonElement>.Empty;

        public string? Status { get; set; }

        public string? Subject { get; set; }
    }

    /// <summary>
    /// Represents a SOAP client returning the responses produced by a callback.
    /// </summary>
    public sealed class FakeSoapClient : IOpenIddictServerSamlSoapClient
    {
        public List<(Uri Url, string Envelope)> Requests { get; } = [];

        public Func<Uri, string, string?> Callback { get; set; } = static (_, _) => null;

        public ValueTask<string?> SendAsync(Uri url, string envelope, CancellationToken cancellationToken)
        {
            lock (Requests)
            {
                Requests.Add((url, envelope));
            }

            return new(Callback(url, envelope));
        }
    }
}
