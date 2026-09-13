using System.Collections.Immutable;
using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace OpenIddict.Client.AspNetCore.IntegrationTests;

public class OpenIddictClientAspNetCoreDynamicRegistrationTests
{
    private static readonly Uri Issuer = new("https://tenant1.fabrikam.com/", UriKind.Absolute);

    [Fact]
    public async Task SchemeProvider_ResolvesDynamicProviderNames()
    {
        // Arrange
        using var host = await CreateHostAsync();
        var schemes = host.Services.GetRequiredService<IAuthenticationSchemeProvider>();

        // Act
        var scheme = await schemes.GetSchemeAsync("Tenant1");
        var unknown = await schemes.GetSchemeAsync("Unknown");
        var all = await schemes.GetAllSchemesAsync();

        // Assert
        Assert.IsType<OpenIddictClientAspNetCoreSchemeProvider>(schemes);
        Assert.NotNull(scheme);
        Assert.Equal(typeof(OpenIddictClientAspNetCoreForwarder), scheme.HandlerType);
        Assert.Equal("Tenant 1", scheme.DisplayName);
        Assert.Null(unknown);
        Assert.Contains(all, scheme => string.Equals(scheme.Name, "Tenant1", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SchemeProvider_IgnoresDynamicProviderNamesWhenForwardingIsDisabled()
    {
        // Arrange
        using var host = await CreateHostAsync(options => options.DisableAutomaticAuthenticationSchemeForwarding());
        var schemes = host.Services.GetRequiredService<IAuthenticationSchemeProvider>();

        // Act and assert
        Assert.Null(await schemes.GetSchemeAsync("Tenant1"));
    }

    [Fact]
    public async Task Challenge_UsingDynamicProviderNameRedirectsToAuthorizationEndpoint_AndCallbackResolvesRegistration()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

        // Act
        using var challenge = await client.GetAsync("/challenge");

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);

        var location = challenge.Headers.Location!;
        Assert.Equal("https://tenant1.fabrikam.com/connect/authorize", location.GetLeftPart(UriPartial.Path));

        var parameters = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("Fabrikam", parameters[Parameters.ClientId]);
        Assert.Equal("http://localhost/callback", parameters[Parameters.RedirectUri]);

        // Act
        using var request = new HttpRequestMessage(HttpMethod.Get, "/callback?error=access_denied&state=" +
            Uri.EscapeDataString(parameters[Parameters.State]!));

        foreach (var cookie in challenge.Headers.GetValues("Set-Cookie"))
        {
            request.Headers.Add("Cookie", cookie.Split(';')[0]);
        }

        using var callback = await client.SendAsync(request);

        // Assert
        Assert.Equal("tenant1", await callback.Content.ReadAsStringAsync());
    }

    private static async Task<IHost> CreateHostAsync(Action<OpenIddictClientAspNetCoreBuilder>? configuration = null)
    {
        var builder = new HostBuilder();

        builder.ConfigureServices(services =>
        {
            services.AddOpenIddict()
                .AddClient(options =>
                {
                    options.AllowAuthorizationCodeFlow();
                    options.DisableTokenStorage();
                    options.SetRedirectionEndpointUris("callback");

                    options.AddEphemeralEncryptionKey()
                           .AddEphemeralSigningKey();

                    options.AddRegistrationProvider(new TestRegistrationProvider());

                    var host = options.UseAspNetCore()
                        .DisableTransportSecurityRequirement()
                        .EnableErrorPassthrough()
                        .EnableRedirectionEndpointPassthrough();

                    configuration?.Invoke(host);
                });
        });

        builder.ConfigureWebHost(options =>
        {
            options.UseTestServer();
            options.Configure(app =>
            {
                app.UseAuthentication();

                app.Run(async context =>
                {
                    if (context.Request.Path == "/challenge")
                    {
                        await context.ChallengeAsync("Tenant1");
                        return;
                    }

                    if (context.Request.Path == "/callback")
                    {
                        await context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

                        var transaction = context.Features.Get<OpenIddictClientAspNetCoreFeature>()?.Transaction;
                        await context.Response.WriteAsync(transaction?.Registration?.RegistrationId ?? string.Empty);
                    }
                });
            });
        });

        return await builder.StartAsync();
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
