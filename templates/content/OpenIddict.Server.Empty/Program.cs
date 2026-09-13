using System.Security.Claims;
using System.Text.Encodings.Web;
using Company.Server;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<DbContext>(options =>
{
    // Configure Entity Framework Core to use SQLite (replace with the provider of your choice).
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));

    // Register the entity sets needed by OpenIddict.
    options.UseOpenIddict();
});

// Note: the cookie handler stores the identity of the logged in user between the
// login page and the authorization endpoint. Replace it by your own user store.
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options => options.LoginPath = "/account/login");

builder.Services.AddAuthorization();
builder.Services.AddAntiforgery();

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<DbContext>();
    })
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("connect/authorize")
               .SetEndSessionEndpointUris("connect/endsession")
               .SetTokenEndpointUris("connect/token")
               .SetUserInfoEndpointUris("connect/userinfo");

        options.AllowAuthorizationCodeFlow()
               .AllowClientCredentialsFlow()
               .AllowRefreshTokenFlow();

        options.RegisterScopes(Scopes.Email, Scopes.Profile);

        // Note: the development certificates must be replaced by persistent certificates
        // in production (or by automatic key management, see EnableAutomaticKeyManagement()).
        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough();
    });

// Create the database and, in development, register a sample client application.
builder.Services.AddHostedService<Worker>();

var app = builder.Build();

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapMethods("/connect/authorize", [HttpMethods.Get, HttpMethods.Post], async context =>
{
    var request = context.GetOpenIddictServerRequest() ??
        throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

    // Redirect the user agent to the login page if the user is not logged in.
    var result = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    if (result is not { Succeeded: true })
    {
        await context.ChallengeAsync(CookieAuthenticationDefaults.AuthenticationScheme, new AuthenticationProperties
        {
            RedirectUri = context.Request.PathBase + context.Request.Path + QueryString.Create(
                context.Request.HasFormContentType ? context.Request.Form : context.Request.Query)
        });

        return;
    }

    // TODO: display a consent form if necessary and create a permanent authorization
    // (see IOpenIddictAuthorizationManager) to avoid asking for consent every time.
    var identity = new ClaimsIdentity(
        authenticationType: TokenValidationParameters.DefaultAuthenticationType,
        nameType: Claims.Name,
        roleType: Claims.Role);

    identity.SetClaim(Claims.Subject, result.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value)
            .SetClaim(Claims.Name, result.Principal.Identity?.Name);

    identity.SetScopes(request.GetScopes());
    identity.SetDestinations(GetDestinations);

    await context.SignInAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
});

app.MapPost("/connect/token", async context =>
{
    var request = context.GetOpenIddictServerRequest() ??
        throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

    ClaimsIdentity identity;

    if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
    {
        // Retrieve the claims principal stored in the authorization code/refresh token.
        var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // TODO: ensure the user still exists and is still allowed to sign in and refresh the user claims.
        identity = new ClaimsIdentity(result.Principal!.Claims,
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);
    }

    else if (request.IsClientCredentialsGrantType())
    {
        // Note: the client credentials are automatically validated by OpenIddict.
        identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, request.ClientId);
        identity.SetScopes(request.GetScopes());
    }

    else
    {
        throw new InvalidOperationException("The specified grant type is not supported.");
    }

    identity.SetDestinations(GetDestinations);

    await context.SignInAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
});

app.MapMethods("/connect/endsession", [HttpMethods.Get, HttpMethods.Post], async context =>
{
    // Delete the local authentication cookie and ask OpenIddict to redirect the user
    // agent to the post_logout_redirect_uri specified by the client application.
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await context.SignOutAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
        new AuthenticationProperties { RedirectUri = "/" });
});

app.MapMethods("/connect/userinfo", [HttpMethods.Get, HttpMethods.Post], async context =>
{
    var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    if (result is not { Succeeded: true })
    {
        await context.ChallengeAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        return;
    }

    var claims = new Dictionary<string, object?>(StringComparer.Ordinal)
    {
        // Note: the "sub" claim is a mandatory claim and must be included in the JSON response.
        [Claims.Subject] = result.Principal.GetClaim(Claims.Subject)
    };

    if (result.Principal.HasScope(Scopes.Profile))
    {
        claims[Claims.Name] = result.Principal.GetClaim(Claims.Name);
    }

    await context.Response.WriteAsJsonAsync(claims);
});

app.MapGet("/account/login", async (HttpContext context, IAntiforgery antiforgery) =>
{
    if (!app.Environment.IsDevelopment())
    {
        // TODO: implement user authentication (e.g using ASP.NET Core Identity or an external provider).
        context.Response.StatusCode = StatusCodes.Status501NotImplemented;
        return;
    }

    var tokens = antiforgery.GetAndStoreTokens(context);
    var encoder = HtmlEncoder.Default;

    context.Response.ContentType = "text/html; charset=utf-8";
    await context.Response.WriteAsync($"""
        <!DOCTYPE html>
        <html>
        <body>
            <h1>Development login</h1>
            <p>Any user name is accepted: replace this page by a real authentication mechanism.</p>
            <form method="post">
                <input type="hidden" name="{encoder.Encode(tokens.FormFieldName)}" value="{encoder.Encode(tokens.RequestToken ?? string.Empty)}" />
                <input type="hidden" name="ReturnUrl" value="{encoder.Encode(context.Request.Query["ReturnUrl"].ToString())}" />
                <input name="UserName" placeholder="User name" required />
                <button type="submit">Log in</button>
            </form>
        </body>
        </html>
        """);
});

app.MapPost("/account/login", async (HttpContext context, IAntiforgery antiforgery) =>
{
    if (!app.Environment.IsDevelopment())
    {
        context.Response.StatusCode = StatusCodes.Status501NotImplemented;
        return;
    }

    await antiforgery.ValidateRequestAsync(context);

    var form = await context.Request.ReadFormAsync();
    var name = form["UserName"].ToString();
    if (string.IsNullOrWhiteSpace(name))
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        return;
    }

    var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
    identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, name));
    identity.AddClaim(new Claim(ClaimTypes.Name, name));

    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

    // Only allow local return URLs to prevent open redirect attacks.
    var url = form["ReturnUrl"].ToString();
    context.Response.Redirect(!string.IsNullOrEmpty(url) && url.StartsWith('/') && !url.StartsWith("//") && !url.StartsWith("/\\") ? url : "/");
});

app.MapGet("/", () => "OpenIddict server: see /.well-known/openid-configuration.");

app.Run();

static IEnumerable<string> GetDestinations(Claim claim) => claim.Type switch
{
    // Note: by default, claims are NOT automatically included in the access and identity tokens.
    Claims.Name when claim.Subject!.HasScope(Scopes.Profile) => [Destinations.AccessToken, Destinations.IdentityToken],

    _ => [Destinations.AccessToken]
};
