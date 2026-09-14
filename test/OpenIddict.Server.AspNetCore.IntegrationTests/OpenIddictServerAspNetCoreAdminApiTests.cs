/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;

namespace OpenIddict.Server.AspNetCore.IntegrationTests;

public class OpenIddictServerAspNetCoreAdminApiTests
{
    private const string Policy = "openiddict-admin";

    [Fact]
    public void MapOpenIddictAdminApi_ThrowsAnExceptionForNullOrEmptyPolicy()
    {
        // Arrange
        var endpoints = Mock.Of<IEndpointRouteBuilder>();

        // Act and assert
        Assert.Throws<ArgumentNullException>(() => endpoints.MapOpenIddictAdminApi(policy: null!));
        Assert.Throws<ArgumentException>(() => endpoints.MapOpenIddictAdminApi(policy: string.Empty));
    }

    [Fact]
    public async Task AdminApi_RejectsUnauthenticatedRequests()
    {
        // Arrange
        var manager = new Mock<IOpenIddictApplicationManager>();
        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: null);

        // Act
        var response = await client.GetAsync("/openiddict/admin/applications");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        manager.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task AdminApi_RejectsRequestsNotSatisfyingThePolicy()
    {
        // Arrange
        var manager = new Mock<IOpenIddictApplicationManager>();
        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "user");

        // Act
        var response = await client.DeleteAsync("/openiddict/admin/applications/1");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        manager.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task AdminApi_UsesTheConfiguredPrefix()
    {
        // Arrange
        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()))
            .Returns(EnumerateAsync());

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object), prefix: "/management");
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.GetAsync("/management/applications");
        var fallback = await client.GetAsync("/openiddict/admin/applications");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("[]", await response.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.NotFound, fallback.StatusCode);
    }

    [Fact]
    public async Task ListApplications_ReturnsApplicationsWithoutClientSecrets()
    {
        // Arrange
        var application = new object();

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.ListAsync(5, 10, It.IsAny<CancellationToken>()))
            .Returns(EnumerateAsync(application));
        manager.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>()))
            .ReturnsAsync("1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), application, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.ClientId = "Fabrikam";
                descriptor.ClientSecret = "hashed-secret";
                descriptor.ClientType = ClientTypes.Confidential;
                descriptor.Permissions.Add(Permissions.Endpoints.Token);
                descriptor.RedirectUris.Add(new Uri("https://fabrikam.com/callback"));
                descriptor.Settings["setting"] = "value";
            })
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.GetAsync("/openiddict/admin/applications?count=5&offset=10");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("no-store", response.Headers.CacheControl?.ToString(), StringComparison.Ordinal);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var item = Assert.Single(document.RootElement.EnumerateArray());

        Assert.Equal("1", item.GetProperty("id").GetString());
        Assert.Equal("Fabrikam", item.GetProperty("client_id").GetString());
        Assert.Equal(ClientTypes.Confidential, item.GetProperty("client_type").GetString());
        Assert.Equal(Permissions.Endpoints.Token, Assert.Single(item.GetProperty("permissions").EnumerateArray()).GetString());
        Assert.Equal("https://fabrikam.com/callback", Assert.Single(item.GetProperty("redirect_uris").EnumerateArray()).GetString());
        Assert.Equal("value", item.GetProperty("settings").GetProperty("setting").GetString());
        Assert.False(item.TryGetProperty("client_secret", out _));
        Assert.DoesNotContain("hashed-secret", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("count=0")]
    [InlineData("count=1001")]
    [InlineData("count=abc")]
    [InlineData("offset=-1")]
    public async Task ListApplications_RejectsInvalidPaginationParameters(string query)
    {
        // Arrange
        var manager = new Mock<IOpenIddictApplicationManager>();
        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.GetAsync("/openiddict/admin/applications?" + query);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(Errors.InvalidRequest, document.RootElement.GetProperty("error").GetString());
        manager.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task AdminApi_ThrowsAnExceptionWhenCoreServicesAreMissing()
    {
        // Arrange
        using var host = await CreateHostAsync(services => { });
        using var client = CreateClient(host, role: "admin");

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetAsync("/openiddict/admin/applications"));
        Assert.Equal(SR.GetResourceString(SR.ID0564), exception.Message);
    }

    [Fact]
    public async Task GetApplication_ReturnsJsonWebKeySetWithoutPrivateKeyParameters()
    {
        // Arrange
        var application = new object();

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(application);
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), application, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, object _, CancellationToken _) =>
                descriptor.JsonWebKeySet = JsonWebKeySet.Create("""
                    {
                      "keys": [
                        { "kty": "RSA", "kid": "key-1", "use": "sig", "n": "bW9kdWx1cw", "e": "AQAB",
                          "d": "cHJpdmF0ZS1leHBvbmVudA", "p": "cHJpbWUtMQ", "q": "cHJpbWUtMg",
                          "dp": "ZXhwb25lbnQtMQ", "dq": "ZXhwb25lbnQtMg", "qi": "Y29lZmZpY2llbnQ" },
                        { "kty": "oct", "kid": "key-2", "k": "c3ltbWV0cmljLXNlY3JldA" }
                      ]
                    }
                    """))
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.GetAsync("/openiddict/admin/applications/1");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(content);
        var keys = document.RootElement.GetProperty("json_web_key_set").GetProperty("keys").EnumerateArray().ToArray();
        Assert.Equal(2, keys.Length);

        Assert.Equal("key-1", keys[0].GetProperty("kid").GetString());
        Assert.Equal("bW9kdWx1cw", keys[0].GetProperty("n").GetString());
        Assert.Equal("AQAB", keys[0].GetProperty("e").GetString());
        Assert.Equal("key-2", keys[1].GetProperty("kid").GetString());

        foreach (var parameter in (string[]) ["d", "p", "q", "dp", "dq", "qi", "k"])
        {
            Assert.All(keys, key => Assert.False(key.TryGetProperty(parameter, out _)));
        }

        Assert.DoesNotContain("cHJpdmF0ZS1leHBvbmVudA", content, StringComparison.Ordinal);
        Assert.DoesNotContain("c3ltbWV0cmljLXNlY3JldA", content, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetApplication_ReturnsNotFoundForUnknownApplications()
    {
        // Arrange
        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("unknown", It.IsAny<CancellationToken>()))
            .ReturnsAsync(value: null);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.GetAsync("/openiddict/admin/applications/unknown");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task CreateApplication_CreatesApplicationFromDescriptor()
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
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), application, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, object _, CancellationToken _) => descriptor.ClientId = created!.ClientId)
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.PostAsync("/openiddict/admin/applications", JsonContent("""
            {
              "client_id": "Fabrikam",
              "client_secret": "7Fjfp0ZBr1KtDRbnfVdmIw",
              "client_type": "confidential",
              "display_name": "Fabrikam",
              "display_names": { "fr-FR": "Fabrikam (FR)" },
              "permissions": [ "ept:token", "gt:client_credentials" ],
              "redirect_uris": [ "https://fabrikam.com/callback" ],
              "requirements": [ "ft:pkce" ],
              "settings": { "tkn_lft:act": "00:10:00" },
              "properties": { "custom": { "value": 42 } }
            }
            """));

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("/openiddict/admin/applications/42", response.Headers.Location?.OriginalString);

        Assert.NotNull(created);
        Assert.Equal("Fabrikam", created.ClientId);
        Assert.Equal("7Fjfp0ZBr1KtDRbnfVdmIw", created.ClientSecret);
        Assert.Equal(ClientTypes.Confidential, created.ClientType);
        Assert.Equal("Fabrikam (FR)", created.DisplayNames[System.Globalization.CultureInfo.GetCultureInfo("fr-FR")]);
        Assert.True(created.Permissions.SetEquals(["ept:token", "gt:client_credentials"]));
        Assert.Equal(new Uri("https://fabrikam.com/callback"), Assert.Single(created.RedirectUris));
        Assert.Equal("ft:pkce", Assert.Single(created.Requirements));
        Assert.Equal("00:10:00", created.Settings["tkn_lft:act"]);
        Assert.Equal(42, created.Properties["custom"].GetProperty("value").GetInt32());

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("42", document.RootElement.GetProperty("id").GetString());
        Assert.Equal("Fabrikam", document.RootElement.GetProperty("client_id").GetString());
    }

    [Fact]
    public async Task CreateApplication_RejectsNonJsonRequests()
    {
        // Arrange
        var manager = new Mock<IOpenIddictApplicationManager>();
        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.PostAsync("/openiddict/admin/applications",
            new FormUrlEncodedContent([new KeyValuePair<string, string>("client_id", "Fabrikam")]));

        // Assert
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        manager.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData("""{ "unknown": "value" }""", "unknown")]
    [InlineData("""{ "client_id": 42 }""", "client_id")]
    [InlineData("""{ "redirect_uris": [ "/relative" ] }""", "redirect_uris")]
    [InlineData("""{ "display_names": { "@@@": "value" } }""", "display_names")]
    [InlineData("""{ "permissions": "ept:token" }""", "permissions")]
    public async Task CreateApplication_RejectsInvalidProperties(string payload, string property)
    {
        // Arrange
        var manager = new Mock<IOpenIddictApplicationManager>();
        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.PostAsync("/openiddict/admin/applications", JsonContent(payload));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(SR.FormatID2242(property), document.RootElement.GetProperty("error_description").GetString());
        manager.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task CreateApplication_ReturnsValidationErrors()
    {
        // Arrange
        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OpenIddictExceptions.ValidationException("Invalid application.",
                [new System.ComponentModel.DataAnnotations.ValidationResult("The client identifier cannot be null or empty.")]));

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.PostAsync("/openiddict/admin/applications", JsonContent("{}"));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("The client identifier cannot be null or empty.",
            Assert.Single(document.RootElement.GetProperty("errors").EnumerateArray()).GetString());
    }

    [Fact]
    public async Task UpdateApplication_MergesTheSpecifiedProperties()
    {
        // Arrange
        var application = new object();
        OpenIddictApplicationDescriptor? updated = null;

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(application);
        manager.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>()))
            .ReturnsAsync("1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), application, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictApplicationDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.ClientId = "Fabrikam";
                descriptor.DisplayName = "Old name";
                descriptor.Permissions.Add(Permissions.Endpoints.Token);
            })
            .Returns(ValueTask.CompletedTask);
        manager.Setup(mock => mock.UpdateAsync(application, It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()))
            .Callback((object _, OpenIddictApplicationDescriptor descriptor, CancellationToken _) => updated = descriptor)
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.PatchAsync("/openiddict/admin/applications/1", JsonContent("""{ "display_name": "New name" }"""));

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(updated);
        Assert.Equal("Fabrikam", updated.ClientId);
        Assert.Equal("New name", updated.DisplayName);
        Assert.Equal(Permissions.Endpoints.Token, Assert.Single(updated.Permissions));
    }

    [Fact]
    public async Task DeleteApplication_DeletesTheApplication()
    {
        // Arrange
        var application = new object();

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(application);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.DeleteAsync("/openiddict/admin/applications/1");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        manager.Verify(mock => mock.DeleteAsync(application, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task DeleteApplication_ReturnsConflictForConcurrencyExceptions()
    {
        // Arrange
        var application = new object();

        var manager = new Mock<IOpenIddictApplicationManager>();
        manager.Setup(mock => mock.FindByIdAsync("1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(application);
        manager.Setup(mock => mock.DeleteAsync(application, It.IsAny<CancellationToken>()))
            .Returns(ValueTask.FromException(new OpenIddictExceptions.ConcurrencyException("Concurrency failure.")));

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.DeleteAsync("/openiddict/admin/applications/1");

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task CreateScope_CreatesScopeFromDescriptor()
    {
        // Arrange
        var scope = new object();
        OpenIddictScopeDescriptor? created = null;

        var manager = new Mock<IOpenIddictScopeManager>();
        manager.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictScopeDescriptor>(), It.IsAny<CancellationToken>()))
            .Callback((OpenIddictScopeDescriptor descriptor, CancellationToken _) => created = descriptor)
            .ReturnsAsync(scope);
        manager.Setup(mock => mock.GetIdAsync(scope, It.IsAny<CancellationToken>()))
            .ReturnsAsync("s1");

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.PostAsync("/openiddict/admin/scopes",
            JsonContent("""{ "name": "api", "display_name": "API", "resources": [ "resource_server" ] }"""));

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.NotNull(created);
        Assert.Equal("api", created.Name);
        Assert.Equal("API", created.DisplayName);
        Assert.Equal("resource_server", Assert.Single(created.Resources));
    }

    [Fact]
    public async Task ListTokens_UsesFiltersWhenSpecified()
    {
        // Arrange
        var tokens = new[] { new object(), new object(), new object() };

        var manager = new Mock<IOpenIddictTokenManager>();
        manager.Setup(mock => mock.FindAsync(It.Is<(string? Subject, string? ApplicationId, string? Status, string? Type)>(query =>
            string.Equals(query.Subject, "Bob", StringComparison.Ordinal) && string.Equals(query.ApplicationId, "app", StringComparison.Ordinal) &&
            string.Equals(query.Status, Statuses.Valid, StringComparison.Ordinal) && query.Type == null), It.IsAny<CancellationToken>()))
            .Returns(EnumerateAsync(tokens));
        manager.Setup(mock => mock.GetIdAsync(tokens[1], It.IsAny<CancellationToken>()))
            .ReturnsAsync("t2");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictTokenDescriptor>(), tokens[1], It.IsAny<CancellationToken>()))
            .Callback((OpenIddictTokenDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.Payload = "sensitive-payload";
                descriptor.ReferenceId = "sensitive-reference";
                descriptor.Subject = "Bob";
            })
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.GetAsync("/openiddict/admin/tokens?subject=Bob&application_id=app&status=valid&count=1&offset=1");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(content);
        var item = Assert.Single(document.RootElement.EnumerateArray());
        Assert.Equal("t2", item.GetProperty("id").GetString());
        Assert.Equal("Bob", item.GetProperty("subject").GetString());
        Assert.DoesNotContain("sensitive", content, StringComparison.Ordinal);

        manager.Verify(mock => mock.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task RevokeToken_RevokesTheToken()
    {
        // Arrange
        var token = new object();

        var manager = new Mock<IOpenIddictTokenManager>();
        manager.Setup(mock => mock.FindByIdAsync("t1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        manager.Setup(mock => mock.TryRevokeAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.PostAsync("/openiddict/admin/tokens/t1/revoke", JsonContent(string.Empty));
        var form = await client.PostAsync("/openiddict/admin/tokens/t1/revoke", new StringContent(string.Empty));

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, form.StatusCode);
        manager.Verify(mock => mock.TryRevokeAsync(token, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task RevokeAuthorization_RevokesTheAssociatedTokens()
    {
        // Arrange
        var authorization = new object();

        var manager = new Mock<IOpenIddictAuthorizationManager>();
        manager.Setup(mock => mock.FindByIdAsync("a1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(authorization);
        manager.Setup(mock => mock.GetIdAsync(authorization, It.IsAny<CancellationToken>()))
            .ReturnsAsync("a1");
        manager.Setup(mock => mock.TryRevokeAsync(authorization, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var tokens = new Mock<IOpenIddictTokenManager>();
        tokens.Setup(mock => mock.RevokeByAuthorizationIdAsync("a1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(2);

        using var host = await CreateHostAsync(services => services
            .AddSingleton(manager.Object)
            .AddSingleton(tokens.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.PostAsync("/openiddict/admin/authorizations/a1/revoke", JsonContent("{}"));

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        manager.Verify(mock => mock.TryRevokeAsync(authorization, It.IsAny<CancellationToken>()), Times.Once());
        tokens.Verify(mock => mock.RevokeByAuthorizationIdAsync("a1", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task RevokeAuthorization_ReturnsConflictWhenRevocationFails()
    {
        // Arrange
        var authorization = new object();

        var manager = new Mock<IOpenIddictAuthorizationManager>();
        manager.Setup(mock => mock.FindByIdAsync("a1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(authorization);
        manager.Setup(mock => mock.TryRevokeAsync(authorization, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.PostAsync("/openiddict/admin/authorizations/a1/revoke", JsonContent("{}"));

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task ListKeys_DoesNotReturnKeyMaterial()
    {
        // Arrange
        var key = new object();

        var manager = new Mock<IOpenIddictKeyManager>();
        manager.Setup(mock => mock.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()))
            .Returns(EnumerateAsync(key));
        manager.Setup(mock => mock.GetIdAsync(key, It.IsAny<CancellationToken>()))
            .ReturnsAsync("k1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictKeyDescriptor>(), key, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictKeyDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.Algorithm = SecurityAlgorithms.RsaSha256;
                descriptor.KeyId = "kid";
                descriptor.Payload = "protected-key-material";
                descriptor.Status = Statuses.Valid;
            })
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.GetAsync("/openiddict/admin/keys");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(content);
        var item = Assert.Single(document.RootElement.EnumerateArray());
        Assert.Equal("kid", item.GetProperty("key_id").GetString());
        Assert.Equal(Statuses.Valid, item.GetProperty("status").GetString());
        Assert.DoesNotContain("protected-key-material", content, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RevokeKey_RevokesTheKey()
    {
        // Arrange
        var key = new object();

        var manager = new Mock<IOpenIddictKeyManager>();
        manager.Setup(mock => mock.FindByIdAsync("k1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(key);
        manager.Setup(mock => mock.TryRevokeAsync(key, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.PostAsync("/openiddict/admin/keys/k1/revoke", JsonContent("{}"));

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        manager.Verify(mock => mock.TryRevokeAsync(key, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ListSessions_FiltersSessionsBySubjectAndLoginIdentifier()
    {
        // Arrange
        var session = new object();

        var manager = new Mock<IOpenIddictSessionManager>();
        manager.Setup(mock => mock.FindAsync(It.Is<(string?, string?, string?, string?, string?)>(query => query.Item1 == "Bob" && query.Item2 == "login"), It.IsAny<CancellationToken>()))
            .Returns(EnumerateAsync(session));
        manager.Setup(mock => mock.GetIdAsync(session, It.IsAny<CancellationToken>()))
            .ReturnsAsync("s1");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictSessionDescriptor>(), session, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictSessionDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.ApplicationId = "a1";
                descriptor.ExpirationDate = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
                descriptor.LoginId = "login";
                descriptor.Principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("secret", "value")]));
                descriptor.Status = Statuses.Valid;
                descriptor.Subject = "Bob";
            })
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.GetAsync("/openiddict/admin/sessions?subject=Bob&login_id=login");
        var content = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var document = JsonDocument.Parse(content);
        var item = Assert.Single(document.RootElement.EnumerateArray());

        Assert.Equal("s1", item.GetProperty("id").GetString());
        Assert.Equal("a1", item.GetProperty("application_id").GetString());
        Assert.Equal("login", item.GetProperty("login_id").GetString());
        Assert.Equal("Bob", item.GetProperty("subject").GetString());
        Assert.Equal(Statuses.Valid, item.GetProperty("status").GetString());
        Assert.NotEqual(JsonValueKind.Null, item.GetProperty("expiration_date").ValueKind);
        Assert.DoesNotContain("secret", content, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetSession_ReturnsNotFoundForUnknownSession()
    {
        // Arrange
        var manager = new Mock<IOpenIddictSessionManager>();

        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.GetAsync("/openiddict/admin/sessions/unknown");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task TerminateSession_TerminatesTheSession()
    {
        // Arrange
        var service = new Mock<OpenIddictServerService>(Mock.Of<IServiceProvider>());
        service.Setup(mock => mock.TerminateSessionAsync("s1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new OpenIddictServerSessionTerminationResult
            {
                SessionIds = ["s1", "s2"],
                NotifiedParticipants =
                [
                    new OpenIddictServerLogoutParticipant { ApplicationId = "a1", ClientId = "Fabrikam", SessionId = "s1" }
                ]
            });

        using var host = await CreateHostAsync(services => services.AddSingleton(service.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.PostAsync("/openiddict/admin/sessions/s1/terminate", JsonContent(string.Empty));
        var unknown = await client.PostAsync("/openiddict/admin/sessions/unknown/terminate", JsonContent(string.Empty));

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("s1 s2", string.Join(' ', document.RootElement.GetProperty("session_ids").EnumerateArray().Select(static value => value.GetString())));
        Assert.Equal("Fabrikam", Assert.Single(document.RootElement.GetProperty("notified_clients").EnumerateArray()).GetString());

        service.Verify(mock => mock.TerminateSessionAsync("s1", It.IsAny<CancellationToken>()), Times.Once());
    }

    private static StringContent JsonContent(string payload)
        => new(payload, Encoding.UTF8, "application/json");

    private static HttpClient CreateClient(IHost host, string? role)
    {
        var client = host.GetTestServer().CreateClient();

        if (!string.IsNullOrEmpty(role))
        {
            client.DefaultRequestHeaders.Add(TestAuthenticationHandler.HeaderName, role);
        }

        return client;
    }

    private static async Task<IHost> CreateHostAsync(Action<IServiceCollection> configuration,
        string prefix = OpenIddictServerAspNetCoreDefaults.AdminApiRoutePrefix)
    {
        var host = new HostBuilder()
            .ConfigureWebHost(builder =>
            {
                builder.UseTestServer();

                builder.ConfigureServices(services =>
                {
                    services.AddLogging(options => options.SetMinimumLevel(LogLevel.Warning));
                    services.AddRouting();

                    services.AddAuthentication(TestAuthenticationHandler.SchemeName)
                        .AddScheme<AuthenticationSchemeOptions, TestAuthenticationHandler>(TestAuthenticationHandler.SchemeName, options => { });

                    services.AddAuthorizationBuilder()
                        .AddPolicy(Policy, policy => policy.RequireRole("admin"));

                    configuration(services);
                });

                builder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints => endpoints.MapOpenIddictAdminApi(Policy, prefix));
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

    private sealed class TestAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger, UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string HeaderName = "X-Test-Role";
        public const string SchemeName = "Test";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue(HeaderName, out var role) || string.IsNullOrEmpty(role))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var identity = new ClaimsIdentity(SchemeName);
            identity.AddClaim(new Claim(ClaimTypes.Name, "admin"));
            identity.AddClaim(new Claim(ClaimTypes.Role, role.ToString()));

            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
        }
    }
}
