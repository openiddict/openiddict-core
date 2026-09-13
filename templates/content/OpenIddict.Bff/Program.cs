using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using OpenIddict.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    });

builder.Services.AddAuthorization();

builder.Services.AddOpenIddict()
    .AddClient(options =>
    {
        options.AllowAuthorizationCodeFlow()
               .AllowRefreshTokenFlow();

        // Note: the BFF doesn't use a database: the state tokens are self-contained.
        options.DisableTokenStorage();

        // Note: the development certificates must be replaced by persistent certificates in production.
        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        options.UseSystemNetHttp()
               .SetProductInformation(typeof(Program).Assembly);

        var settings = builder.Configuration.GetSection("OpenIddict");

        var registration = new OpenIddictClientRegistration
        {
            Issuer = new Uri(settings["Authority"] ?? throw new InvalidOperationException("The authority is missing."), UriKind.Absolute),
            ClientId = settings["ClientId"],
            ClientSecret = string.IsNullOrEmpty(settings["ClientSecret"]) ? null : settings["ClientSecret"],

            // Note: these URIs must match the paths used by the BFF endpoints and must be registered in the server.
            RedirectUri = new Uri("bff/callback/login", UriKind.Relative),
            PostLogoutRedirectUri = new Uri("bff/callback/logout", UriKind.Relative)
        };

        registration.Scopes.UnionWith(settings.GetSection("Scopes").Get<string[]>() ?? [Scopes.OpenId]);

        options.AddRegistration(registration);

        // Register the BFF services: session endpoints, automatic token refresh and antiforgery checks.
        options.UseBff(bff => bff.UseInMemorySessionStore());
    });

// Proxy the API calls declared in the "ReverseProxy" section (the user access token is attached by the BFF transforms).
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddOpenIddictBffTransforms();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseOpenIddictBff();
app.UseAuthorization();

// Map the login (/bff/login), logout (/bff/logout), user (/bff/user),
// callback and back-channel logout (/bff/backchannel-logout) endpoints.
app.MapOpenIddictBffEndpoints();

// Local API endpoint: requires an authenticated user and the "X-CSRF: 1" header.
app.MapGet("/api/me", (ClaimsPrincipal user) => Results.Ok(new
{
    Name = user.Identity?.Name,
    Claims = user.Claims.Select(claim => new { claim.Type, claim.Value })
}))
.RequireAuthorization()
.AsOpenIddictBffApiEndpoint();

app.MapReverseProxy();

app.Run();
