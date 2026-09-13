using System.Collections.Immutable;
using System.Net;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Owin;
using Microsoft.Owin.Testing;
using Owin;
using Xunit;

namespace OpenIddict.Client.Owin.IntegrationTests;

public class OpenIddictClientOwinDynamicRegistrationTests
{
    private static readonly Uri Issuer = new("https://tenant1.fabrikam.com/", UriKind.Absolute);

    [Fact]
    public async Task GetAuthenticationTypes_IncludesDynamicProviderNames()
    {
        // Arrange
        using var server = CreateServer();
        using var client = server.HttpClient;

        // Act
        var types = await client.GetStringAsync("/types");

        // Assert
        Assert.Equal("Tenant1:Tenant 1", types);
    }

    [Fact]
    public async Task GetAuthenticationTypes_ExcludesDynamicProviderNamesWhenForwardingIsDisabled()
    {
        // Arrange
        using var server = CreateServer(options => options.DisableAutomaticAuthenticationTypeForwarding());
        using var client = server.HttpClient;

        // Act
        var types = await client.GetStringAsync("/types");

        // Assert
        Assert.Equal(string.Empty, types);
    }

    [Fact]
    public async Task Challenge_UsingDynamicProviderNameRedirectsToAuthorizationEndpoint_AndCallbackResolvesRegistration()
    {
        // Arrange
        using var server = CreateServer();
        using var client = server.HttpClient;

        // Act
        using var challenge = await client.GetAsync("/challenge");

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);

        var location = challenge.Headers.Location!;
        Assert.Equal("https://tenant1.fabrikam.com/connect/authorize", location.GetLeftPart(UriPartial.Path));

        var parameters = location.Query.TrimStart('?').Split('&')
            .Select(static parameter => parameter.Split('='))
            .ToDictionary(static parts => Uri.UnescapeDataString(parts[0]), static parts => Uri.UnescapeDataString(parts[1]), StringComparer.Ordinal);
        Assert.Equal("Fabrikam", parameters[Parameters.ClientId]);
        Assert.Equal("http://localhost/callback", parameters[Parameters.RedirectUri]);

        // Act
        using var request = new HttpRequestMessage(HttpMethod.Get, "/callback?error=access_denied&state=" +
            Uri.EscapeDataString(parameters[Parameters.State]));

        foreach (var cookie in challenge.Headers.GetValues("Set-Cookie"))
        {
            request.Headers.Add("Cookie", cookie.Split(';')[0]);
        }

        using var callback = await client.SendAsync(request);

        // Assert
        Assert.Equal("tenant1", await callback.Content.ReadAsStringAsync());
    }

    private static TestServer CreateServer(Action<OpenIddictClientOwinBuilder>? configuration = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddOpenIddict()
            .AddClient(options =>
            {
                options.AllowAuthorizationCodeFlow();
                options.DisableTokenStorage();
                options.SetRedirectionEndpointUris("callback");

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                options.AddRegistrationProvider(new TestRegistrationProvider());

                var host = options.UseOwin()
                    .DisableTransportSecurityRequirement()
                    .EnableErrorPassthrough()
                    .EnableRedirectionEndpointPassthrough();

                configuration?.Invoke(host);
            });

        var provider = services.BuildServiceProvider();

        return TestServer.Create(app =>
        {
            app.Use(async (context, next) =>
            {
                await using var scope = provider.CreateAsyncScope();

                context.Set(typeof(IServiceProvider).FullName, scope.ServiceProvider);

                try
                {
                    await next();
                }

                finally
                {
                    context.Environment.Remove(typeof(IServiceProvider).FullName);
                }
            });

            app.UseOpenIddictClient();

            app.Run(async context =>
            {
                if (context.Request.Path == new PathString("/types"))
                {
                    // Note: the main authentication type of the OpenIddict client host is always returned.
                    await context.Response.WriteAsync(string.Join(";", context.Authentication.GetAuthenticationTypes()
                        .Where(static description => description.AuthenticationType is not OpenIddictClientOwinDefaults.AuthenticationType)
                        .Select(static description => description.AuthenticationType + ":" + description.Caption)));
                }

                else if (context.Request.Path == new PathString("/challenge"))
                {
                    context.Authentication.Challenge("Tenant1");
                }

                else if (context.Request.Path == new PathString("/callback"))
                {
                    await context.Authentication.AuthenticateAsync(OpenIddictClientOwinDefaults.AuthenticationType);

                    var transaction = context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName);
                    await context.Response.WriteAsync(transaction?.Registration?.RegistrationId ?? string.Empty);
                }
            });
        });
    }

    private sealed class TestRegistrationProvider : IOpenIddictClientRegistrationProvider
    {
        private static OpenIddictClientRegistration CreateRegistration() => new()
        {
            ClientId = "Fabrikam",
            Configuration = new OpenIddictConfiguration
            {
                AuthorizationEndpoint = new Uri("https://tenant1.fabrikam.com/connect/authorize", UriKind.Absolute),
                CodeChallengeMethodsSupported = { CodeChallengeMethods.Sha256 },
                GrantTypesSupported = { GrantTypes.AuthorizationCode },
                Issuer = Issuer,
                ResponseModesSupported = { ResponseModes.Query },
                ResponseTypesSupported = { ResponseTypes.Code }
            },
            Issuer = Issuer,
            ProviderDisplayName = "Tenant 1",
            ProviderName = "Tenant1",
            RedirectUri = new Uri("callback", UriKind.Relative),
            RegistrationId = "tenant1"
        };

        public ValueTask<OpenIddictClientRegistration?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
            => new(string.Equals(identifier, "tenant1", StringComparison.Ordinal) ? CreateRegistration() : null);

        public ValueTask<ImmutableArray<OpenIddictClientRegistration>> FindByIssuerAsync(Uri issuer, CancellationToken cancellationToken)
            => new(issuer == Issuer ? [CreateRegistration()] : []);

        public ValueTask<ImmutableArray<OpenIddictClientRegistration>> FindByProviderNameAsync(string name, CancellationToken cancellationToken)
            => new(string.Equals(name, "Tenant1", StringComparison.Ordinal) ? [CreateRegistration()] : []);

        public ValueTask<ImmutableArray<OpenIddictClientRegistration>> ListAsync(CancellationToken cancellationToken)
            => new([CreateRegistration()]);
    }
}
