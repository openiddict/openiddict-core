/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using OpenIddict.Server.AspNetCore.AdminUI;
using Xunit;

namespace OpenIddict.Server.AspNetCore.AdminUI.Tests;

public partial class OpenIddictServerAspNetCoreAdminUITests
{
    private const string Policy = "openiddict-admin";

    [Fact]
    public void MapOpenIddictAdminUI_ThrowsAnExceptionForNullOrEmptyPolicy()
    {
        // Arrange
        var endpoints = Mock.Of<IEndpointRouteBuilder>();

        // Act and assert
        Assert.Throws<ArgumentNullException>(() => endpoints.MapOpenIddictAdminUI(policy: null!));
        Assert.Throws<ArgumentException>(() => endpoints.MapOpenIddictAdminUI(policy: string.Empty));
    }

    [Fact]
    public async Task MapOpenIddictAdminUI_ThrowsAnExceptionWhenServicesAreNotRegistered()
    {
        // Arrange
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => app.MapOpenIddictAdminUI(Policy));
        Assert.Equal(SR.GetResourceString(SR.ID0681), exception.Message);
    }

    [Theory]
    [InlineData("/openiddict/admin/applications")]
    [InlineData("/openiddict/admin/openiddict-admin.css")]
    [InlineData("/openiddict/admin/tokens/1")]
    public async Task AdminUI_RejectsUnauthenticatedRequests(string path)
    {
        // Arrange
        var manager = new Mock<IOpenIddictApplicationManager>();
        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: null);

        // Act
        var response = await client.GetAsync(path);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        manager.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task AdminUI_RejectsRequestsNotSatisfyingThePolicy()
    {
        // Arrange
        var manager = new Mock<IOpenIddictApplicationManager>();
        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "user");

        // Act
        var page = await client.GetAsync("/openiddict/admin/applications");
        var post = await client.PostAsync("/openiddict/admin/applications/1/delete", new FormUrlEncodedContent([]));

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, page.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, post.StatusCode);
        manager.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task AdminUI_ThrowsAnExceptionWhenCoreServicesAreMissing()
    {
        // Arrange
        using var host = await CreateHostAsync(services => { });
        using var client = CreateClient(host, role: "admin");

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetAsync("/openiddict/admin/applications"));
        Assert.Equal(SR.GetResourceString(SR.ID0680), exception.Message);
    }

    [Fact]
    public async Task AdminUI_RedirectsTheHomePageAndServesTheStylesheet()
    {
        // Arrange
        using var host = await CreateHostAsync(services => { }, prefix: "/management");
        using var client = CreateClient(host, role: "admin");

        // Act
        var home = await client.GetAsync("/management");
        var stylesheet = await client.GetAsync("/management/openiddict-admin.css");
        var fallback = await client.GetAsync("/openiddict/admin");

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, home.StatusCode);
        Assert.Equal("/management/applications", home.Headers.Location?.OriginalString);
        Assert.Equal(HttpStatusCode.OK, stylesheet.StatusCode);
        Assert.Equal("text/css", stylesheet.Content.Headers.ContentType?.MediaType);
        Assert.Contains(".oi-header", await stylesheet.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.NotFound, fallback.StatusCode);
    }

    [Fact]
    public async Task ListApplications_RendersApplicationsWithoutClientSecretsAndSecurityHeaders()
    {
        // Arrange
        var application = new object();

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.ListAsync(3, 2, It.IsAny<CancellationToken>()))
            .Returns(EnumerateAsync(application, new object(), new object()));
        manager.Setup(mock => mock.GetIdAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync("1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.ClientId = "Fabrikam<script>";
                descriptor.ClientSecret = "hashed-secret";
                descriptor.ClientType = ClientTypes.Confidential;
            })
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object),
            configuration: options => options.PageSize = 2);
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.GetAsync("/openiddict/admin/applications?page=2");
        var html = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("no-store", response.Headers.CacheControl?.ToString(), StringComparison.Ordinal);
        Assert.Contains("default-src 'none'", response.Headers.GetValues("Content-Security-Policy").Single(), StringComparison.Ordinal);
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("Fabrikam&lt;script&gt;", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Fabrikam<script>", html, StringComparison.Ordinal);
        Assert.DoesNotContain("hashed-secret", html, StringComparison.Ordinal);
        Assert.Contains("href=\"/openiddict/admin/applications?page=1\"", html, StringComparison.Ordinal);
        Assert.Contains("href=\"/openiddict/admin/applications?page=3\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListApplications_FiltersApplicationsUsingTheSearchTerm()
    {
        // Arrange
        var (fabrikam, contoso) = (new object(), new object());

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.ListAsync(1_001, 0, It.IsAny<CancellationToken>()))
            .Returns(EnumerateAsync(fabrikam, contoso));
        manager.Setup(mock => mock.GetClientIdAsync(fabrikam, It.IsAny<CancellationToken>())).ReturnsAsync("fabrikam");
        manager.Setup(mock => mock.GetClientIdAsync(contoso, It.IsAny<CancellationToken>())).ReturnsAsync("contoso");
        manager.Setup(mock => mock.GetIdAsync(fabrikam, It.IsAny<CancellationToken>())).ReturnsAsync("1");
        manager.Setup(mock => mock.GetIdAsync(contoso, It.IsAny<CancellationToken>())).ReturnsAsync("2");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), contoso, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, object _, CancellationToken _) => descriptor.ClientId = "contoso")
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var html = await client.GetStringAsync("/openiddict/admin/applications?search=CONTO");

        // Assert
        Assert.Contains(">contoso</a>", html, StringComparison.Ordinal);
        Assert.DoesNotContain(">fabrikam</a>", html, StringComparison.Ordinal);
        manager.Verify(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), fabrikam, It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task CreateApplication_RejectsRequestsWithoutAntiforgeryToken()
    {
        // Arrange
        var manager = new Mock<IOpenIddictApplicationManager>();
        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.PostAsync("/openiddict/admin/applications/new", new FormUrlEncodedContent(
        [
            new("client_id", "fabrikam")
        ]));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(HtmlEncoder.Default.Encode(SR.GetResourceString(SR.ID2340)),
            await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        manager.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task CreateApplication_CreatesTheApplicationFromTheForm()
    {
        // Arrange
        var application = new object();
        OpenIddictApplicationDescriptor? created = null;

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, CancellationToken _) => created = descriptor)
            .ReturnsAsync(application);
        manager.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>()))
            .ReturnsAsync("42");

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/applications/new");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/applications/new",
        [
            new("client_id", "fabrikam"),
            new("display_name", "Fabrikam"),
            new("client_type", ClientTypes.Confidential),
            new("application_type", ApplicationTypes.Web),
            new("consent_type", ConsentTypes.Explicit),
            new("mode", "set"),
            new("client_secret", "s3cr3t"),
            new("redirect_uris", "https://fabrikam.com/callback\r\nhttps://fabrikam.com/other"),
            new("post_logout_redirect_uris", "https://fabrikam.com/logout"),
            new("permissions", Permissions.Endpoints.Token),
            new("permissions", Permissions.GrantTypes.AuthorizationCode),
            new("additional_permissions", "scp:api"),
            new("requirements", Requirements.Features.ProofKeyForCodeExchange),
            new("settings", "tkn_lft:act=00:30:00")
        ]);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/openiddict/admin/applications/42?notice=created", response.Headers.Location?.OriginalString);

        Assert.NotNull(created);
        Assert.Equal("fabrikam", created.ClientId);
        Assert.Equal("Fabrikam", created.DisplayName);
        Assert.Equal("s3cr3t", created.ClientSecret);
        Assert.Equal(ClientTypes.Confidential, created.ClientType);
        Assert.Equal(ApplicationTypes.Web, created.ApplicationType);
        Assert.Equal(ConsentTypes.Explicit, created.ConsentType);
        Assert.Equal("https://fabrikam.com/callback https://fabrikam.com/other",
            string.Join(' ', created.RedirectUris.Select(static uri => uri.AbsoluteUri).Order(StringComparer.Ordinal)));
        Assert.Equal("https://fabrikam.com/logout", Assert.Single(created.PostLogoutRedirectUris).AbsoluteUri);
        Assert.Equal(string.Join(" ", Permissions.Endpoints.Token, Permissions.GrantTypes.AuthorizationCode, "scp:api"),
            string.Join(' ', created.Permissions.Order(StringComparer.Ordinal)));
        Assert.Equal(Requirements.Features.ProofKeyForCodeExchange, Assert.Single(created.Requirements));
        Assert.Equal("00:30:00", created.Settings["tkn_lft:act"]);
    }

    [Fact]
    public async Task CreateApplication_DisplaysTheGeneratedSecretOnce()
    {
        // Arrange
        var application = new object();
        string? secret = null;

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, CancellationToken _) => secret = descriptor.ClientSecret)
            .ReturnsAsync(application);
        manager.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>()))
            .ReturnsAsync("42");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), application, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.ClientId = "fabrikam";
                descriptor.ClientSecret = "hashed-secret";
            })
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/applications/new");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/applications/new",
        [
            new("client_id", "fabrikam"),
            new("client_type", ClientTypes.Confidential),
            new("mode", "generate")
        ]);

        var html = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(secret);
        Assert.True(secret.Length >= 43);
        Assert.Contains($"<code id=\"new-client-secret\">{secret}</code>", html, StringComparison.Ordinal);
        Assert.DoesNotContain("hashed-secret", html, StringComparison.Ordinal);
        Assert.DoesNotContain(secret, response.Headers.Location?.OriginalString ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateApplication_RerendersTheFormForInvalidValues()
    {
        // Arrange
        var manager = new Mock<IOpenIddictApplicationManager>();
        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/applications/new");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/applications/new",
        [
            new("client_id", "fabrikam"),
            new("client_type", "unknown"),
            new("redirect_uris", "not-an-uri"),
            new("settings", "=value")
        ]);

        var html = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(HtmlEncoder.Default.Encode(SR.FormatID2341("client_type")), html, StringComparison.Ordinal);
        Assert.Contains(HtmlEncoder.Default.Encode(SR.FormatID2341("redirect_uris")), html, StringComparison.Ordinal);
        Assert.Contains(HtmlEncoder.Default.Encode(SR.FormatID2341("settings")), html, StringComparison.Ordinal);
        Assert.Contains("value=\"fabrikam\"", html, StringComparison.Ordinal);
        manager.Verify(mock => mock.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task CreateApplication_RendersValidationErrorsReturnedByTheManager()
    {
        // Arrange
        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OpenIddictExceptions.ValidationException("invalid",
                [new System.ComponentModel.DataAnnotations.ValidationResult("The client identifier is already used.")]));

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/applications/new");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/applications/new",
        [
            new("client_id", "fabrikam"),
            new("mode", "set"),
            new("client_secret", "s3cr3t")
        ]);

        var html = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("The client identifier is already used.", html, StringComparison.Ordinal);
        Assert.DoesNotContain("s3cr3t", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EditApplication_RendersTheApplicationWithoutSecretsOrPrivateKeys()
    {
        // Arrange
        var application = new object();

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("1", It.IsAny<CancellationToken>())).ReturnsAsync(application);
        manager.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync("1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), application, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.ClientId = "fabrikam";
                descriptor.ClientSecret = "hashed-secret";
                descriptor.RedirectUris.Add(new Uri("https://fabrikam.com/callback"));
                descriptor.Permissions.Add(Permissions.Endpoints.Token);
                descriptor.Permissions.Add("scp:api");
                descriptor.Settings["tkn_lft:act"] = "00:30:00";
                descriptor.JsonWebKeySet = JsonWebKeySet.Create("""
                    { "keys": [ { "kty": "RSA", "kid": "key-1", "n": "bW9kdWx1cw", "e": "AQAB", "d": "cHJpdmF0ZS1leHBvbmVudA" } ] }
                    """);
            })
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var html = await client.GetStringAsync("/openiddict/admin/applications/1");

        // Assert
        Assert.Contains("value=\"fabrikam\"", html, StringComparison.Ordinal);
        Assert.Contains("https://fabrikam.com/callback</textarea>", html, StringComparison.Ordinal);
        Assert.Contains("scp:api</textarea>", html, StringComparison.Ordinal);
        Assert.Contains("tkn_lft:act=00:30:00</textarea>", html, StringComparison.Ordinal);
        Assert.Matches($"value=\"{Regex.Escape(Permissions.Endpoints.Token)}\" checked", html);
        Assert.Contains("key-1", html, StringComparison.Ordinal);
        Assert.Contains("A client secret is configured.", html, StringComparison.Ordinal);
        Assert.DoesNotContain("hashed-secret", html, StringComparison.Ordinal);
        Assert.DoesNotContain("cHJpdmF0ZS1leHBvbmVudA", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EditApplication_ReturnsNotFoundForUnknownApplications()
    {
        // Arrange
        var manager = new Mock<IOpenIddictApplicationManager>();
        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.GetAsync("/openiddict/admin/applications/unknown");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task UpdateApplication_UpdatesTheApplicationAndPreservesTheStoredSecretAndKeys()
    {
        // Arrange
        var application = new object();
        OpenIddictApplicationDescriptor? updated = null;

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("1", It.IsAny<CancellationToken>())).ReturnsAsync(application);
        manager.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync("1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), application, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.ClientId = "fabrikam";
                descriptor.ClientSecret = "hashed-secret";
                descriptor.Permissions.Add(Permissions.Endpoints.Authorization);
                descriptor.RedirectUris.Add(new Uri("https://fabrikam.com/old"));
                descriptor.JsonWebKeySet = JsonWebKeySet.Create("""{ "keys": [ { "kty": "oct", "kid": "key-1", "k": "c2VjcmV0" } ] }""");
            })
            .Returns(ValueTask.CompletedTask);
        manager.Setup(mock => mock.UpdateAsync(application, It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .Callback((object _, OpenIddictApplicationDescriptor descriptor, CancellationToken _) => updated = descriptor)
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/applications/1");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/applications/1",
        [
            new("client_id", "fabrikam"),
            new("display_name", "Fabrikam (updated)"),
            new("client_type", ClientTypes.Public),
            new("redirect_uris", "https://fabrikam.com/new"),
            new("permissions", Permissions.Endpoints.Token),
            new("json_web_key_set", string.Empty)
        ]);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/openiddict/admin/applications/1?notice=updated", response.Headers.Location?.OriginalString);

        Assert.NotNull(updated);
        Assert.Equal("Fabrikam (updated)", updated.DisplayName);
        Assert.Equal("hashed-secret", updated.ClientSecret);
        Assert.Equal(ClientTypes.Public, updated.ClientType);
        Assert.Equal("https://fabrikam.com/new", Assert.Single(updated.RedirectUris).AbsoluteUri);
        Assert.Equal(Permissions.Endpoints.Token, Assert.Single(updated.Permissions));
        Assert.Equal("key-1", Assert.Single(updated.JsonWebKeySet!.Keys).Kid);
    }

    [Fact]
    public async Task UpdateApplication_RendersConcurrencyConflicts()
    {
        // Arrange
        var application = new object();

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("1", It.IsAny<CancellationToken>())).ReturnsAsync(application);
        manager.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync("1");
        manager.Setup(mock => mock.UpdateAsync(application, It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .Returns(() => ValueTask.FromException(new OpenIddictExceptions.ConcurrencyException("conflict")));

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/applications/1");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/applications/1", [new("client_id", "fabrikam")]);

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Contains(HtmlEncoder.Default.Encode(SR.GetResourceString(SR.ID2244)),
            await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("set", "n3w-s3cr3t")]
    [InlineData("remove", null)]
    public async Task ChangeApplicationSecret_UpdatesTheClientSecret(string mode, string? expected)
    {
        // Arrange
        var application = new object();
        OpenIddictApplicationDescriptor? updated = null;

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("1", It.IsAny<CancellationToken>())).ReturnsAsync(application);
        manager.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync("1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), application, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.ClientId = "fabrikam";
                descriptor.ClientSecret = "hashed-secret";
                descriptor.Permissions.Add(Permissions.Endpoints.Token);
            })
            .Returns(ValueTask.CompletedTask);
        manager.Setup(mock => mock.UpdateAsync(application, It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .Callback((object _, OpenIddictApplicationDescriptor descriptor, CancellationToken _) => updated = descriptor)
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/applications/1");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/applications/1/secret",
        [
            new("mode", mode),
            new("client_secret", expected ?? string.Empty)
        ]);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(updated);
        Assert.Equal(expected, updated.ClientSecret);
        Assert.Equal(Permissions.Endpoints.Token, Assert.Single(updated.Permissions));
    }

    [Fact]
    public async Task ChangeApplicationSecret_RejectsSetModeWithoutSecret()
    {
        // Arrange
        var application = new object();

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("1", It.IsAny<CancellationToken>())).ReturnsAsync(application);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/applications/1");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/applications/1/secret", [new("mode", "set")]);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        manager.Verify(mock => mock.UpdateAsync(application, It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task DeleteApplication_DeletesTheApplication()
    {
        // Arrange
        var application = new object();

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("1", It.IsAny<CancellationToken>())).ReturnsAsync(application);
        manager.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync("1");

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/applications/1");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/applications/1/delete", []);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/openiddict/admin/applications?notice=deleted", response.Headers.Location?.OriginalString);
        manager.Verify(mock => mock.DeleteAsync(application, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task Scopes_SupportCreateUpdateAndDelete()
    {
        // Arrange
        var scope = new object();
        OpenIddictScopeDescriptor? created = null, updated = null;

        var manager = new Mock<IOpenIddictScopeManager>();
        manager.Setup(mock => mock.ListAsync(26, 0, It.IsAny<CancellationToken>())).Returns(EnumerateAsync(scope));
        manager.Setup(mock => mock.FindByIdAsync("7", It.IsAny<CancellationToken>())).ReturnsAsync(scope);
        manager.Setup(mock => mock.GetIdAsync(scope, It.IsAny<CancellationToken>())).ReturnsAsync("7");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictScopeDescriptor>(), scope, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictScopeDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.Name = "api";
                descriptor.Resources.Add("resource-server");
            })
            .Returns(ValueTask.CompletedTask);
        manager.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictScopeDescriptor>(), It.IsAny<CancellationToken>()))
            .Callback((OpenIddictScopeDescriptor descriptor, CancellationToken _) => created = descriptor)
            .ReturnsAsync(scope);
        manager.Setup(mock => mock.UpdateAsync(scope, It.IsAny<OpenIddictScopeDescriptor>(), It.IsAny<CancellationToken>()))
            .Callback((object _, OpenIddictScopeDescriptor descriptor, CancellationToken _) => updated = descriptor)
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var list = await client.GetStringAsync("/openiddict/admin/scopes");
        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/scopes/new");

        var create = await PostAsync(client, antiforgery, "/openiddict/admin/scopes/new",
        [
            new("name", "api"),
            new("display_name", "API"),
            new("resources", "resource-1\nresource-2")
        ]);

        var edit = await client.GetStringAsync("/openiddict/admin/scopes/7");
        var update = await PostAsync(client, antiforgery, "/openiddict/admin/scopes/7",
        [
            new("name", "api"),
            new("description", "The API")
        ]);

        var delete = await PostAsync(client, antiforgery, "/openiddict/admin/scopes/7/delete", []);

        // Assert
        Assert.Contains("href=\"/openiddict/admin/scopes/7\">api</a>", list, StringComparison.Ordinal);

        Assert.Equal(HttpStatusCode.Redirect, create.StatusCode);
        Assert.NotNull(created);
        Assert.Equal("api", created.Name);
        Assert.Equal("API", created.DisplayName);
        Assert.Equal("resource-1 resource-2", string.Join(' ', created.Resources.Order(StringComparer.Ordinal)));

        Assert.Contains("resource-server</textarea>", edit, StringComparison.Ordinal);

        Assert.Equal(HttpStatusCode.Redirect, update.StatusCode);
        Assert.NotNull(updated);
        Assert.Equal("The API", updated.Description);
        Assert.Empty(updated.Resources);

        Assert.Equal(HttpStatusCode.Redirect, delete.StatusCode);
        manager.Verify(mock => mock.DeleteAsync(scope, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ListAuthorizations_FiltersBySubjectAndClient()
    {
        // Arrange
        var (application, authorization) = (new object(), new object());

        var applications = new Mock<IOpenIddictApplicationManager>();
        applications.Setup(mock => mock.FindByClientIdAsync("fabrikam", It.IsAny<CancellationToken>())).ReturnsAsync(application);
        applications.Setup(mock => mock.FindByIdAsync("app-1", It.IsAny<CancellationToken>())).ReturnsAsync(application);
        applications.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync("app-1");
        applications.Setup(mock => mock.GetClientIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync("fabrikam");

        var manager = new Mock<IOpenIddictAuthorizationManager>();
        manager.Setup(mock => mock.FindAsync(It.Is<(string?, string?, string?, string?, ImmutableArray<string>?)>(
                query => query.Item1 == "alice" && query.Item2 == "app-1" && query.Item3 == null && query.Item4 == null),
                It.IsAny<CancellationToken>()))
            .Returns(EnumerateAsync(authorization));
        manager.Setup(mock => mock.GetIdAsync(authorization, It.IsAny<CancellationToken>())).ReturnsAsync("authz-1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictAuthorizationDescriptor>(), authorization, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictAuthorizationDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.ApplicationId = "app-1";
                descriptor.Subject = "alice";
                descriptor.Status = Statuses.Valid;
                descriptor.Scopes.Add(Scopes.OpenId);
            })
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services
            .AddSingleton(applications.Object)
            .AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var html = await client.GetStringAsync("/openiddict/admin/authorizations?subject=alice&client=fabrikam");
        var unknown = await client.GetStringAsync("/openiddict/admin/authorizations?client=unknown");

        // Assert
        Assert.Contains("<code>authz-1</code>", html, StringComparison.Ordinal);
        Assert.Contains("<td>fabrikam</td>", html, StringComparison.Ordinal);
        Assert.Contains("action=\"/openiddict/admin/authorizations/authz-1/revoke\"", html, StringComparison.Ordinal);
        Assert.Contains("No authorization was found.", unknown, StringComparison.Ordinal);
        manager.Verify(mock => mock.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task RevokeAuthorization_RevokesTheAuthorizationAndItsTokens()
    {
        // Arrange
        var authorization = new object();

        var applications = new Mock<IOpenIddictApplicationManager>();

        var manager = new Mock<IOpenIddictAuthorizationManager>();
        manager.Setup(mock => mock.FindByIdAsync("authz-1", It.IsAny<CancellationToken>())).ReturnsAsync(authorization);
        manager.Setup(mock => mock.GetIdAsync(authorization, It.IsAny<CancellationToken>())).ReturnsAsync("authz-1");
        manager.Setup(mock => mock.TryRevokeAsync(authorization, It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var tokens = new Mock<IOpenIddictTokenManager>();
        tokens.Setup(mock => mock.FindByAuthorizationIdAsync("authz-1", It.IsAny<CancellationToken>())).Returns(EnumerateAsync());

        using var host = await CreateHostAsync(services => services
            .AddSingleton(applications.Object)
            .AddSingleton(manager.Object)
            .AddSingleton(tokens.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/authorizations/authz-1");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/authorizations/authz-1/revoke", []);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/openiddict/admin/authorizations/authz-1?notice=revoked", response.Headers.Location?.OriginalString);
        manager.Verify(mock => mock.TryRevokeAsync(authorization, It.IsAny<CancellationToken>()), Times.Once());
        tokens.Verify(mock => mock.RevokeByAuthorizationIdAsync("authz-1", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ShowToken_RendersTheTokenWithoutPayload()
    {
        // Arrange
        var token = new object();

        var applications = new Mock<IOpenIddictApplicationManager>();

        var manager = new Mock<IOpenIddictTokenManager>();
        manager.Setup(mock => mock.FindByIdAsync("token-1", It.IsAny<CancellationToken>())).ReturnsAsync(token);
        manager.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>())).ReturnsAsync("token-1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictTokenDescriptor>(), token, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictTokenDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.AuthorizationId = "authz-1";
                descriptor.Payload = "secret-token-payload";
                descriptor.ReferenceId = "secret-reference-identifier";
                descriptor.Status = Statuses.Valid;
                descriptor.Subject = "alice";
                descriptor.Type = TokenTypeIdentifiers.RefreshToken;
            })
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services
            .AddSingleton(applications.Object)
            .AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var html = await client.GetStringAsync("/openiddict/admin/tokens/token-1");

        // Assert
        Assert.Contains("alice", html, StringComparison.Ordinal);
        Assert.Contains("href=\"/openiddict/admin/authorizations/authz-1\"", html, StringComparison.Ordinal);
        Assert.Contains("action=\"/openiddict/admin/tokens/token-1/revoke\"", html, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-token-payload", html, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-reference-identifier", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Tokens_SupportFilteringAndRevocation()
    {
        // Arrange
        var token = new object();

        var applications = new Mock<IOpenIddictApplicationManager>();

        var manager = new Mock<IOpenIddictTokenManager>();
        manager.Setup(mock => mock.FindAsync(It.Is<(string?, string?, string?, string?)>(
                query => query.Item1 == null && query.Item2 == null && query.Item3 == Statuses.Valid && query.Item4 == null),
                It.IsAny<CancellationToken>()))
            .Returns(EnumerateAsync(token));
        manager.Setup(mock => mock.FindByIdAsync("token-1", It.IsAny<CancellationToken>())).ReturnsAsync(token);
        manager.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>())).ReturnsAsync("token-1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictTokenDescriptor>(), token, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictTokenDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.Payload = "secret-token-payload";
                descriptor.Status = Statuses.Valid;
            })
            .Returns(ValueTask.CompletedTask);
        manager.Setup(mock => mock.TryRevokeAsync(token, It.IsAny<CancellationToken>())).ReturnsAsync(true);

        using var host = await CreateHostAsync(services => services
            .AddSingleton(applications.Object)
            .AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var html = await client.GetStringAsync("/openiddict/admin/tokens?status=valid");
        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/tokens?status=valid");
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/tokens/token-1/revoke", []);

        // Assert
        Assert.Contains("<code>token-1</code>", html, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-token-payload", html, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        manager.Verify(mock => mock.TryRevokeAsync(token, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task RevokeToken_RendersConflictWhenTheTokenCannotBeRevoked()
    {
        // Arrange
        var token = new object();

        var applications = new Mock<IOpenIddictApplicationManager>();

        var manager = new Mock<IOpenIddictTokenManager>();
        manager.Setup(mock => mock.FindByIdAsync("token-1", It.IsAny<CancellationToken>())).ReturnsAsync(token);
        manager.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>())).ReturnsAsync("token-1");
        manager.Setup(mock => mock.TryRevokeAsync(token, It.IsAny<CancellationToken>())).ReturnsAsync(false);

        using var host = await CreateHostAsync(services => services
            .AddSingleton(applications.Object)
            .AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/tokens/token-1");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/tokens/token-1/revoke", []);

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task Keys_AreListedWithoutKeyMaterialAndCanBeRevoked()
    {
        // Arrange
        var key = new object();

        var manager = new Mock<IOpenIddictKeyManager>();
        manager.Setup(mock => mock.ListAsync(26, 0, It.IsAny<CancellationToken>())).Returns(EnumerateAsync(key));
        manager.Setup(mock => mock.FindByIdAsync("key-1", It.IsAny<CancellationToken>())).ReturnsAsync(key);
        manager.Setup(mock => mock.GetIdAsync(key, It.IsAny<CancellationToken>())).ReturnsAsync("key-1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictKeyDescriptor>(), key, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictKeyDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.KeyId = "kid-1";
                descriptor.Payload = "protected-key-material";
                descriptor.Status = Statuses.Valid;
            })
            .Returns(ValueTask.CompletedTask);
        manager.Setup(mock => mock.TryRevokeAsync(key, It.IsAny<CancellationToken>())).ReturnsAsync(true);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var html = await client.GetStringAsync("/openiddict/admin/keys");
        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/keys");
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/keys/key-1/revoke", []);

        // Assert
        Assert.Contains("<code>kid-1</code>", html, StringComparison.Ordinal);
        Assert.DoesNotContain("protected-key-material", html, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/openiddict/admin/keys?notice=revoked", response.Headers.Location?.OriginalString);
        manager.Verify(mock => mock.TryRevokeAsync(key, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task AdminUI_RejectsAntiforgeryTokensIssuedToAnotherUser()
    {
        // Arrange
        var application = new object();

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("1", It.IsAny<CancellationToken>())).ReturnsAsync(application);
        manager.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync("1");

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");
        using var other = CreateClient(host, role: "admin", name: "mallory");

        var antiforgery = await GetAntiforgeryAsync(other, "/openiddict/admin/applications/1");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/applications/1/delete", []);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        manager.Verify(mock => mock.DeleteAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task AdminUI_TreatsIdentifiersRejectedByTheStoreAsUnknownEntities()
    {
        // Arrange
        var applications = new Mock<IOpenIddictApplicationManager>();
        applications.Setup(mock => mock.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(() => ValueTask.FromException<object?>(new FormatException("The identifier is not a valid GUID.")));

        var authorizations = new Mock<IOpenIddictAuthorizationManager>();
        authorizations.Setup(mock => mock.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(() => ValueTask.FromException<object?>(new FormatException("The identifier is not a valid integer.")));

        var tokens = new Mock<IOpenIddictTokenManager>();

        using var host = await CreateHostAsync(services => services
            .AddSingleton(applications.Object)
            .AddSingleton(authorizations.Object)
            .AddSingleton(tokens.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var application = await client.GetAsync("/openiddict/admin/applications/fabrikam");
        var authorization = await client.GetAsync("/openiddict/admin/authorizations/fabrikam");
        var authorizationList = await client.GetAsync("/openiddict/admin/authorizations?client=fabrikam");
        var tokenList = await client.GetAsync("/openiddict/admin/tokens?client=fabrikam");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, application.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, authorization.StatusCode);
        Assert.Equal(HttpStatusCode.OK, authorizationList.StatusCode);
        Assert.Contains("No authorization was found.", await authorizationList.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, tokenList.StatusCode);
        Assert.Contains("No token was found.", await tokenList.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        tokens.Verify(mock => mock.FindAsync(It.IsAny<(string?, string?, string?, string?)>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task ListApplications_LimitsTheNumberOfApplicationsInspectedBySearches()
    {
        // Arrange
        var entries = Enumerable.Range(0, 1_001).Select(static _ => new object()).ToArray();
        var match = new object();

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.ListAsync(1_001, 0, It.IsAny<CancellationToken>())).Returns(() => EnumerateAsync(entries));
        manager.Setup(mock => mock.GetClientIdAsync(It.IsAny<object>(), It.IsAny<CancellationToken>())).ReturnsAsync("contoso");
        manager.Setup(mock => mock.GetIdAsync(It.IsAny<object>(), It.IsAny<CancellationToken>())).ReturnsAsync("1");
        manager.Setup(mock => mock.GetIdAsync(match, It.IsAny<CancellationToken>())).ReturnsAsync("42");
        manager.Setup(mock => mock.FindByClientIdAsync("fabrikam", It.IsAny<CancellationToken>())).ReturnsAsync(match);
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), match, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, object _, CancellationToken _) => descriptor.ClientId = "fabrikam")
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var html = await client.GetStringAsync("/openiddict/admin/applications?search=fabrikam");

        // Assert
        Assert.Contains("The search only inspected the first 1000 applications", html, StringComparison.Ordinal);
        Assert.Contains("href=\"/openiddict/admin/applications/42\">fabrikam</a>", html, StringComparison.Ordinal);
        manager.Verify(mock => mock.ListAsync(null, It.IsAny<int?>(), It.IsAny<CancellationToken>()), Times.Never());
        manager.Verify(mock => mock.GetClientIdAsync(It.IsAny<object>(), It.IsAny<CancellationToken>()), Times.Exactly(1_000));
    }

    [Fact]
    public async Task ChangeApplicationSecret_GeneratesAndDisplaysANewSecretOnce()
    {
        // Arrange
        var application = new object();
        OpenIddictApplicationDescriptor? updated = null;

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("1", It.IsAny<CancellationToken>())).ReturnsAsync(application);
        manager.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync("1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), application, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.ClientId = "fabrikam";
                descriptor.ClientSecret = "hashed-secret";
            })
            .Returns(ValueTask.CompletedTask);
        manager.Setup(mock => mock.UpdateAsync(application, It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .Callback((object _, OpenIddictApplicationDescriptor descriptor, CancellationToken _) => updated = new()
            {
                ClientId = descriptor.ClientId,
                ClientSecret = descriptor.ClientSecret
            })
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/applications/1");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/applications/1/secret", [new("mode", "generate")]);
        var html = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(updated?.ClientSecret);
        Assert.False(string.Equals("hashed-secret", updated.ClientSecret, StringComparison.Ordinal));
        Assert.True(updated.ClientSecret.Length >= 43);
        Assert.Contains($"<code id=\"new-client-secret\">{updated.ClientSecret}</code>", html, StringComparison.Ordinal);
        Assert.DoesNotContain("hashed-secret", html, StringComparison.Ordinal);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task UpdateApplication_ReplacesOrRemovesTheJsonWebKeySet()
    {
        // Arrange
        var application = new object();
        List<JsonWebKeySet?> sets = [];

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("1", It.IsAny<CancellationToken>())).ReturnsAsync(application);
        manager.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync("1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), application, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.ClientId = "fabrikam";
                descriptor.JsonWebKeySet = JsonWebKeySet.Create("""{ "keys": [ { "kty": "RSA", "kid": "old-key", "n": "bW9kdWx1cw", "e": "AQAB" } ] }""");
            })
            .Returns(ValueTask.CompletedTask);
        manager.Setup(mock => mock.UpdateAsync(application, It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .Callback((object _, OpenIddictApplicationDescriptor descriptor, CancellationToken _) => sets.Add(descriptor.JsonWebKeySet))
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/applications/1");

        // Act
        var replace = await PostAsync(client, antiforgery, "/openiddict/admin/applications/1",
        [
            new("client_id", "fabrikam"),
            new("json_web_key_set", """{ "keys": [ { "kty": "RSA", "kid": "new-key", "n": "bW9kdWx1cw", "e": "AQAB" } ] }""")
        ]);
        var remove = await PostAsync(client, antiforgery, "/openiddict/admin/applications/1",
        [
            new("client_id", "fabrikam"),
            new("remove_json_web_key_set", "true")
        ]);
        var conflict = await PostAsync(client, antiforgery, "/openiddict/admin/applications/1",
        [
            new("client_id", "fabrikam"),
            new("json_web_key_set", """{ "keys": [ { "kty": "RSA", "kid": "new-key", "n": "bW9kdWx1cw", "e": "AQAB" } ] }"""),
            new("remove_json_web_key_set", "true")
        ]);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, replace.StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, remove.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, conflict.StatusCode);
        Assert.Contains(HtmlEncoder.Default.Encode(SR.FormatID2343("json_web_key_set", "remove_json_web_key_set")),
            await conflict.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        Assert.Equal(2, sets.Count);
        Assert.Equal("new-key", Assert.Single(sets[0]!.Keys).Kid);
        Assert.Null(sets[1]);
    }

    [Fact]
    public async Task RevokeKey_InvalidatesTheKeyRing()
    {
        // Arrange
        var key = new object();

        var manager = new Mock<IOpenIddictKeyManager>();
        manager.Setup(mock => mock.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>())).Returns(() => EnumerateAsync(key));
        manager.Setup(mock => mock.FindByIdAsync("key-1", It.IsAny<CancellationToken>())).ReturnsAsync(key);
        manager.Setup(mock => mock.GetIdAsync(key, It.IsAny<CancellationToken>())).ReturnsAsync("key-1");
        manager.Setup(mock => mock.TryRevokeAsync(key, It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var ring = new OpenIddictServerKeyRing(
            Microsoft.Extensions.Logging.Abstractions.NullLogger<OpenIddictServerKeyRing>.Instance,
            Mock.Of<IOptionsMonitor<OpenIddictServerOptions>>());

        // Note: the cached snapshot is private: a placeholder instance is attached to the key ring
        // to be able to determine whether the key ring was invalidated by the revocation.
        var field = typeof(OpenIddictServerKeyRing).GetField("_snapshot",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        field.SetValue(ring, System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(field.FieldType));

        using var host = await CreateHostAsync(services => services
            .AddSingleton(manager.Object)
            .AddSingleton(ring));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/keys");

        // Act
        Assert.NotNull(field.GetValue(ring));
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/keys/key-1/revoke", []);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Null(field.GetValue(ring));
    }

    [Fact]
    public async Task ShowAuthorization_IndicatesWhenMoreTokensAreAttached()
    {
        // Arrange
        var authorization = new object();

        var applications = new Mock<IOpenIddictApplicationManager>();

        var manager = new Mock<IOpenIddictAuthorizationManager>();
        manager.Setup(mock => mock.FindByIdAsync("authz-1", It.IsAny<CancellationToken>())).ReturnsAsync(authorization);
        manager.Setup(mock => mock.GetIdAsync(authorization, It.IsAny<CancellationToken>())).ReturnsAsync("authz-1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictAuthorizationDescriptor>(), authorization, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictAuthorizationDescriptor descriptor, object _, CancellationToken _) => descriptor.Subject = "alice")
            .Returns(ValueTask.CompletedTask);

        var tokens = new Mock<IOpenIddictTokenManager>();
        tokens.Setup(mock => mock.FindByAuthorizationIdAsync("authz-1", It.IsAny<CancellationToken>()))
            .Returns(() => EnumerateAsync(new object(), new object(), new object()));
        tokens.Setup(mock => mock.GetIdAsync(It.IsAny<object>(), It.IsAny<CancellationToken>())).ReturnsAsync("token");

        using var host = await CreateHostAsync(services => services
            .AddSingleton(applications.Object)
            .AddSingleton(manager.Object)
            .AddSingleton(tokens.Object), configuration: options => options.PageSize = 2);
        using var client = CreateClient(host, role: "admin");

        // Act
        var html = await client.GetStringAsync("/openiddict/admin/authorizations/authz-1");

        // Assert
        Assert.Contains("only the first 2 tokens are displayed", html, StringComparison.Ordinal);
        Assert.Contains("href=\"/openiddict/admin/tokens?authorization=authz-1\"", html, StringComparison.Ordinal);
        Assert.Equal(2, Regex.Matches(html, "<code>token</code>", RegexOptions.None, TimeSpan.FromSeconds(1)).Count);
    }

    [Fact]
    public async Task UpdateApplication_PreservesUnchangedRedirectUrisAndCustomTypesVerbatim()
    {
        // Arrange
        var application = new object();
        OpenIddictApplicationDescriptor? updated = null;

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("1", It.IsAny<CancellationToken>())).ReturnsAsync(application);
        manager.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync("1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), application, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.ClientId = "fabrikam";
                descriptor.ApplicationType = "custom_application_type";
                descriptor.ConsentType = "custom_consent_type";
                descriptor.RedirectUris.Add(new Uri("http://localhost:3000"));
                descriptor.RedirectUris.Add(new Uri("https://Client.Example/cb?a=%7e"));
                descriptor.PostLogoutRedirectUris.Add(new Uri("https://Client.Example"));
            })
            .Returns(ValueTask.CompletedTask);
        manager.Setup(mock => mock.UpdateAsync(application, It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .Callback((object _, OpenIddictApplicationDescriptor descriptor, CancellationToken _) => updated = descriptor)
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        var html = await client.GetStringAsync("/openiddict/admin/applications/1");
        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/applications/1");

        // Act: post the rendered values back unchanged, as a browser would.
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/applications/1",
        [
            new("client_id", "fabrikam"),
            new("display_name", "Fabrikam (renamed)"),
            new("application_type", GetSelectedOption(html, "application_type")),
            new("client_type", GetSelectedOption(html, "client_type")),
            new("consent_type", GetSelectedOption(html, "consent_type")),
            new("redirect_uris", GetTextArea(html, "redirect_uris")),
            new("post_logout_redirect_uris", GetTextArea(html, "post_logout_redirect_uris"))
        ]);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(updated);
        Assert.Equal("Fabrikam (renamed)", updated.DisplayName);
        Assert.Equal("custom_application_type", updated.ApplicationType);
        Assert.Equal("custom_consent_type", updated.ConsentType);
        Assert.Null(updated.ClientType);
        Assert.Equal(["http://localhost:3000", "https://Client.Example/cb?a=%7e"],
            updated.RedirectUris.Select(static uri => uri.OriginalString).Order(StringComparer.Ordinal),
            StringComparer.Ordinal);
        Assert.Equal("https://Client.Example", Assert.Single(updated.PostLogoutRedirectUris).OriginalString);

        static string GetTextArea(string html, string id)
        {
            var match = Regex.Match(html, $"<textarea id=\"{id}\"[^>]*>(?<value>[^<]*)</textarea>",
                RegexOptions.None, TimeSpan.FromSeconds(1));
            Assert.True(match.Success);
            return WebUtility.HtmlDecode(match.Groups["value"].Value);
        }

        static string GetSelectedOption(string html, string id)
        {
            var select = Regex.Match(html, $"<select id=\"{id}\"[^>]*>(?<options>.*?)</select>",
                RegexOptions.Singleline, TimeSpan.FromSeconds(1));
            Assert.True(select.Success);
            var option = Regex.Match(select.Groups["options"].Value, "<option value(?:=\"(?<value>[^\"]*)\")?[^>]*\\bselected",
                RegexOptions.None, TimeSpan.FromSeconds(1));
            Assert.True(option.Success, select.Value);
            return WebUtility.HtmlDecode(option.Groups["value"].Value);
        }
    }

    [Fact]
    public async Task UpdateApplication_RejectsUnknownTypesThatAreNotStored()
    {
        // Arrange
        var application = new object();

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("1", It.IsAny<CancellationToken>())).ReturnsAsync(application);
        manager.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync("1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), application, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.ClientId = "fabrikam";
                descriptor.ApplicationType = "custom_application_type";
            })
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/applications/1");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/applications/1",
        [
            new("client_id", "fabrikam"),
            new("application_type", "another_application_type")
        ]);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        manager.Verify(mock => mock.UpdateAsync(It.IsAny<object>(),
            It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task ListTokens_FiltersByAuthorization()
    {
        // Arrange
        var (first, second, third) = (new object(), new object(), new object());

        var applications = new Mock<IOpenIddictApplicationManager>();

        var manager = new Mock<IOpenIddictTokenManager>();
        manager.Setup(mock => mock.FindByAuthorizationIdAsync("authz-1", It.IsAny<CancellationToken>()))
            .Returns(() => EnumerateAsync(first, second, third));
        manager.Setup(mock => mock.GetIdAsync(first, It.IsAny<CancellationToken>())).ReturnsAsync("token-1");
        manager.Setup(mock => mock.GetIdAsync(second, It.IsAny<CancellationToken>())).ReturnsAsync("token-2");
        manager.Setup(mock => mock.GetIdAsync(third, It.IsAny<CancellationToken>())).ReturnsAsync("token-3");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .Callback((OpenIddictTokenDescriptor descriptor, object token, CancellationToken _) =>
            {
                descriptor.Subject = "alice";
                descriptor.Status = ReferenceEquals(token, second) ? Statuses.Revoked : Statuses.Valid;
            })
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services
            .AddSingleton(applications.Object)
            .AddSingleton(manager.Object), configuration: options => options.PageSize = 1);
        using var client = CreateClient(host, role: "admin");

        // Act
        var page1 = await client.GetStringAsync("/openiddict/admin/tokens?authorization=authz-1&status=valid");
        var page2 = await client.GetStringAsync("/openiddict/admin/tokens?authorization=authz-1&status=valid&page=2");

        // Assert
        Assert.Contains("<code>token-1</code>", page1, StringComparison.Ordinal);
        Assert.DoesNotContain("<code>token-2</code>", page1, StringComparison.Ordinal);
        Assert.Contains("value=\"authz-1\"", page1, StringComparison.Ordinal);
        Assert.Contains("authorization=authz-1&amp;page=2", page1, StringComparison.Ordinal);
        Assert.Contains("<code>token-3</code>", page2, StringComparison.Ordinal);
        Assert.DoesNotContain("<code>token-1</code>", page2, StringComparison.Ordinal);
        manager.Verify(mock => mock.FindAsync(It.IsAny<(string?, string?, string?, string?)>(), It.IsAny<CancellationToken>()), Times.Never());
        manager.Verify(mock => mock.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task MapOpenIddictAdminUI_DetectsConflictingEndpoints()
    {
        // Arrange
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddOpenIddictAdminUI();

        await using var app = builder.Build();
        app.MapOpenIddictAdminApi(Policy);
        app.MapOpenIddictAdminUI(Policy);

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(
            () => ((IEndpointRouteBuilder) app).DataSources.SelectMany(static source => source.Endpoints).ToList());
        Assert.StartsWith("The OpenIddict admin UI endpoint 'GET /openiddict/admin/applications' conflicts with the existing endpoint",
            exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task MapOpenIddictAdminUI_AllowsDistinctPrefixes(bool before)
    {
        // Arrange
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddOpenIddictAdminUI();

        await using var app = builder.Build();

        if (before)
        {
            app.MapOpenIddictAdminUI(Policy, "/admin");
            app.MapOpenIddictAdminUI(Policy, "/other");
            app.MapOpenIddictAdminApi(Policy);
            app.MapGet("/admin/applications/{id:int}", () => "constrained");
        }

        else
        {
            app.MapOpenIddictAdminApi(Policy);
            app.MapOpenIddictAdminUI(Policy, "/admin");
        }

        // Act
        var endpoints = ((IEndpointRouteBuilder) app).DataSources.SelectMany(static source => source.Endpoints).ToList();

        // Assert
        Assert.Contains(endpoints, static endpoint => endpoint is RouteEndpoint { RoutePattern.RawText: "/admin/applications" });
    }

    [Fact]
    public void AddOpenIddictAdminUI_ValidatesThePageSize()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddOpenIddictAdminUI(options => options.PageSize = 0);

        using var provider = services.BuildServiceProvider();

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OpenIddictServerAspNetCoreAdminUIOptions>>().Value);
        Assert.Contains(SR.GetResourceString(SR.ID0682), exception.Message, StringComparison.Ordinal);
    }

    private static HttpClient CreateClient(IHost host, string? role, string name = "admin")
    {
        var client = host.GetTestServer().CreateClient();

        if (!string.IsNullOrEmpty(role))
        {
            client.DefaultRequestHeaders.Add(TestAuthenticationHandler.RoleHeaderName, role);
            client.DefaultRequestHeaders.Add(TestAuthenticationHandler.NameHeaderName, name);
        }

        return client;
    }

    private static async Task<(string Cookie, string Token)> GetAntiforgeryAsync(HttpClient client, string path)
    {
        var response = await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var html = await response.Content.ReadAsStringAsync();
        var match = AntiforgeryTokenRegex().Match(html);
        Assert.True(match.Success, "The page doesn't contain an antiforgery token.");

        var cookie = Assert.Single(response.Headers.GetValues("Set-Cookie"),
            static value => value.StartsWith(".AspNetCore.Antiforgery.", StringComparison.Ordinal));

        return (cookie[..cookie.IndexOf(';')], WebUtility.HtmlDecode(match.Groups["token"].Value));
    }

    private static Task<HttpResponseMessage> PostAsync(HttpClient client, (string Cookie, string Token) antiforgery,
        string path, KeyValuePair<string, string>[] fields)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new FormUrlEncodedContent([.. fields, new("__RequestVerificationToken", antiforgery.Token)])
        };

        request.Headers.Add("Cookie", antiforgery.Cookie);

        return client.SendAsync(request);
    }

    private static async Task<IHost> CreateHostAsync(Action<IServiceCollection> services,
        string prefix = OpenIddictServerAspNetCoreAdminUIConstants.DefaultRoutePrefix,
        Action<OpenIddictServerAspNetCoreAdminUIOptions>? configuration = null)
    {
        var host = new HostBuilder()
            .ConfigureWebHost(builder =>
            {
                builder.UseTestServer();

                builder.ConfigureServices(collection =>
                {
                    collection.AddLogging(options => options.SetMinimumLevel(LogLevel.Warning));
                    collection.AddRouting();

                    collection.AddAuthentication(TestAuthenticationHandler.SchemeName)
                        .AddScheme<AuthenticationSchemeOptions, TestAuthenticationHandler>(TestAuthenticationHandler.SchemeName, options => { });

                    collection.AddAuthorizationBuilder()
                        .AddPolicy(Policy, policy => policy.RequireRole("admin"));

                    collection.AddOpenIddictAdminUI(configuration);

                    services(collection);
                });

                builder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints => endpoints.MapOpenIddictAdminUI(Policy, prefix));
                });
            })
            .Build();

        await host.StartAsync();

        return host;
    }

    private static async IAsyncEnumerable<object> EnumerateAsync(params object[] items)
    {
        foreach (var item in items)
        {
            yield return item;
        }

        await Task.CompletedTask;
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\" value=\"(?<token>[^\"]+)\"", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex AntiforgeryTokenRegex();

    private sealed class TestAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger, UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string NameHeaderName = "X-Test-Name";
        public const string RoleHeaderName = "X-Test-Role";
        public const string SchemeName = "Test";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue(RoleHeaderName, out var role) || string.IsNullOrEmpty(role))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var identity = new ClaimsIdentity(SchemeName);
            identity.AddClaim(new Claim(ClaimTypes.Name, Request.Headers[NameHeaderName].ToString()));
            identity.AddClaim(new Claim(ClaimTypes.Role, role.ToString()));

            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
        }
    }
}
