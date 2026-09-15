/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace OpenIddict.Server.AspNetCore.AdminUI.Tests;

// Note: these tests use the real OpenIddict managers and the Entity Framework Core stores (with GUID keys and an
// in-memory SQLite database) to ensure the admin UI works with stores that can't convert arbitrary identifiers.
public partial class OpenIddictServerAspNetCoreAdminUITests
{
    [Fact]
    public async Task EntityFrameworkCore_ApplicationsCanBeCreatedEditedAndRotatedWithHashedSecrets()
    {
        // Arrange
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        using var host = await CreateEntityFrameworkCoreHostAsync(connection);
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/applications/new");

        // Act
        var created = await PostAsync(client, antiforgery, "/openiddict/admin/applications/new",
        [
            new("client_id", "fabrikam"),
            new("display_name", "Fabrikam"),
            new("client_type", ClientTypes.Confidential),
            new("redirect_uris", "https://fabrikam.com/callback"),
            new("permissions", Permissions.Endpoints.Token),
            new("mode", "generate")
        ]);

        var secret = ExtractSecret(await created.Content.ReadAsStringAsync());

        string identifier;
        await using (var scope = host.Services.CreateAsyncScope())
        {
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var application = await manager.FindByClientIdAsync("fabrikam");

            Assert.NotNull(application);
            identifier = (await manager.GetIdAsync(application))!;

            // Assert: the generated secret was hashed by the manager before being stored.
            var descriptor = new OpenIddictApplicationDescriptor();
            await manager.PopulateAsync(descriptor, application);

            Assert.False(string.Equals(secret, descriptor.ClientSecret, StringComparison.Ordinal));
            Assert.True(await manager.ValidateClientSecretAsync(application, secret));
            Assert.True(Guid.TryParse(identifier, out _));
        }

        var edit = await client.GetStringAsync($"/openiddict/admin/applications/{identifier}");
        Assert.DoesNotContain(secret, edit, StringComparison.Ordinal);

        var updated = await PostAsync(client, antiforgery, $"/openiddict/admin/applications/{identifier}",
        [
            new("client_id", "fabrikam"),
            new("display_name", "Fabrikam (updated)"),
            new("client_type", ClientTypes.Confidential),
            new("permissions", Permissions.Endpoints.Token)
        ]);

        var rotated = await PostAsync(client, antiforgery, $"/openiddict/admin/applications/{identifier}/secret", [new("mode", "generate")]);
        var rotation = ExtractSecret(await rotated.Content.ReadAsStringAsync());

        // Assert
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, updated.StatusCode);
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);

        await using (var scope = host.Services.CreateAsyncScope())
        {
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var application = await manager.FindByIdAsync(identifier);

            Assert.NotNull(application);
            Assert.Equal("Fabrikam (updated)", await manager.GetDisplayNameAsync(application));
            Assert.False(await manager.ValidateClientSecretAsync(application, secret));
            Assert.True(await manager.ValidateClientSecretAsync(application, rotation));
        }

        static string ExtractSecret(string html)
        {
            var match = Regex.Match(html, "<code id=\"new-client-secret\">(?<secret>[^<]+)</code>", RegexOptions.None, TimeSpan.FromSeconds(1));
            Assert.True(match.Success, "The page doesn't contain the generated client secret.");

            return match.Groups["secret"].Value;
        }
    }

    [Fact]
    public async Task EntityFrameworkCore_IdentifiersThatAreNotValidKeysAreTreatedAsUnknownEntities()
    {
        // Arrange
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        using var host = await CreateEntityFrameworkCoreHostAsync(connection);
        using var client = CreateClient(host, role: "admin");

        // Act
        var application = await client.GetAsync("/openiddict/admin/applications/fabrikam");
        var scope = await client.GetAsync("/openiddict/admin/scopes/fabrikam");
        var authorization = await client.GetAsync("/openiddict/admin/authorizations/fabrikam");
        var token = await client.GetAsync("/openiddict/admin/tokens/fabrikam");
        var authorizations = await client.GetAsync("/openiddict/admin/authorizations?client=fabrikam");
        var tokens = await client.GetAsync("/openiddict/admin/tokens?client=fabrikam");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, application.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, scope.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, authorization.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, token.StatusCode);
        Assert.Equal(HttpStatusCode.OK, authorizations.StatusCode);
        Assert.Contains("No authorization was found.", await authorizations.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, tokens.StatusCode);
        Assert.Contains("No token was found.", await tokens.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    private static async Task<IHost> CreateEntityFrameworkCoreHostAsync(SqliteConnection connection, Action<IServiceCollection>? configuration = null)
    {
        var host = await CreateHostAsync(services =>
        {
            services.AddDbContext<AdminUIDbContext>(options =>
            {
                options.UseSqlite(connection);
                options.UseOpenIddict<Guid>();
            });

            services.AddOpenIddict()
                .AddCore(options => options.UseEntityFrameworkCore()
                    .UseDbContext<AdminUIDbContext>()
                    .ReplaceDefaultEntities<Guid>());

            configuration?.Invoke(services);
        });

        await using var scope = host.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<AdminUIDbContext>().Database.EnsureCreatedAsync();

        return host;
    }

    private sealed class AdminUIDbContext(DbContextOptions<AdminUIDbContext> options) : DbContext(options);
}
