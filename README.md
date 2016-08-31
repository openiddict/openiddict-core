# OpenIddict
### The OpenID Connect server you'll be addicted to.

[![Build status](https://ci.appveyor.com/api/projects/status/46ofo2eusje0hcw2?svg=true)](https://ci.appveyor.com/project/openiddict/openiddict-core)
[![Build status](https://travis-ci.org/openiddict/openiddict-core.svg)](https://travis-ci.org/openiddict/openiddict-core)


### What's OpenIddict?

OpenIddict aims at providing a **simple and easy-to-use solution** to implement an **OpenID Connect server in any ASP.NET Core application**.


### Why an OpenID Connect server?

Adding an OpenID Connect server to your application **allows you to support token authentication**.
It also allows you to manage all your users using local password or an external identity provider
(e.g. Facebook or Google) for all your applications in one central place,
with the power to control who can access your API and the information that is exposed to each client.


### How does it work?

OpenIddict is based on **[ASP.NET Core Identity](https://github.com/aspnet/Identity)** (for user management) and relies on
**[AspNet.Security.OpenIdConnect.Server (codenamed ASOS)](https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server)** to control the OpenID Connect authentication flow.

OpenIddict fully supports the **code/implicit/hybrid flows** and the **client credentials/resource owner password grants**. For more information about these terms, please visit the **[OpenID website](http://openid.net/specs/openid-connect-core-1_0.html)** and read the **[OAuth2 specification](https://tools.ietf.org/html/rfc6749)**.

Note: OpenIddict uses **[Entity Framework Core](https://github.com/aspnet/EntityFramework)** by default, but you can also provide your own store.

--------------

## Getting started

To use OpenIddict, you need to:

  - **Install the latest [.NET Core tooling](https://www.microsoft.com/net/download) and update your packages to reference the RC2 final packages**.

  - **Have an existing project or create a new one**: when creating a new project using Visual Studio's default ASP.NET Core template, using **individual user accounts authentication** is strongly recommended. When updating an existing project, you must provide your own `AccountController` to handle the registration process and the authentication flow.

  - **Add the appropriate MyGet repositories to your NuGet sources**. This can be done by adding a new `NuGet.Config` file at the root of your solution:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="NuGet" value="https://api.nuget.org/v3/index.json" />
    <add key="aspnet-contrib" value="https://www.myget.org/F/aspnet-contrib/api/v3/index.json" />
  </packageSources>
</configuration>
```

  - **Update your `project.json`** to reference `AspNet.Security.OAuth.Validation` and `OpenIddict`:

```json
"dependencies": {
  "AspNet.Security.OAuth.Validation": "1.0.0-alpha2-final",
  "OpenIddict": "1.0.0-*"
}
```

  - **Configure the OpenIddict services** in `Startup.ConfigureServices`:

```csharp
public void ConfigureServices(IServiceCollection services) {
    services.AddMvc();

    services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlServer(Configuration["Data:DefaultConnection:ConnectionString"]));       

    // Register the Identity services.
	services.AddIdentity<ApplicationUser, IdentityRole>()
	    .AddEntityFrameworkStores<ApplicationDbContext>()
	    .AddDefaultTokenProviders();

	// Register the OpenIddict services, including the default Entity Framework stores.
	services.AddOpenIddict<ApplicationUser, ApplicationDbContext>()
        // Enable the token endpoint (required to use the password flow).
        .EnableTokenEndpoint("/connect/token")

        // Allow client applications to use the grant_type=password flow.
        .AllowPasswordFlow()

	    // During development, you can disable the HTTPS requirement.
	    .DisableHttpsRequirement()

        // Register a new ephemeral key, that is discarded when the application
        // shuts down. Tokens signed using this key are automatically invalidated.
        // This method should only be used during development.
        .AddEphemeralSigningKey();
}
```

> **Note:** for more information about the different options and configurations available, check out 
[Configuration and options](https://github.com/openiddict/core/wiki/Configuration-and-options)
in the project wiki.

  - **Add OpenIddict and the OAuth2 token validation middleware in your ASP.NET Core pipeline** by calling `app.UseOAuthValidation()` and `app.UseOpenIddict()` after `app.UseIdentity()` and before `app.UseMvc()`:

```csharp
public void Configure(IApplicationBuilder app) {
    app.UseIdentity();

    app.UseOAuthValidation();

    app.UseOpenIddict();

    app.UseMvc();
}
```

> **Note:** `UseOpenIddict()` must be registered ***after*** `app.UseIdentity()` and the external social providers.

  - **Update your `ApplicationUser` entity model to inherit from `OpenIddictUser`**:

```csharp
public class ApplicationUser : OpenIddictUser { }
```

  - **Update your Entity Framework context to inherit from `OpenIddictDbContext`**:

```csharp
public class ApplicationDbContext : OpenIddictDbContext<ApplicationUser> {
    public ApplicationDbContext(DbContextOptions options)
        : base(options) {
    }
}
```

> **Note:** although recommended, inheriting from `OpenIddictDbContext` is not mandatory. Alternatively, you can also create your own context and manually add the entity sets needed by OpenIddict:

```csharp
public class ApplicationDbContext : IdentityDbContext<ApplicationUser> {
    public ApplicationDbContext(DbContextOptions options)
        : base(options) {
    }

    public DbSet<OpenIddictApplication> Applications { get; set; }

    public DbSet<OpenIddictAuthorization> Authorizations { get; set; }

    public DbSet<OpenIddictScope> Scopes { get; set; }

    public DbSet<OpenIddictToken> Tokens { get; set; }
}
```

> **Note:** if you change the default entity primary key (e.g. to `int` or `Guid` instead of `string`), make sure to register your Entity Framework context using the overload accepting a `TKey` generic argument:

```csharp
services.AddOpenIddict<ApplicationUser, IdentityRole<int>, ApplicationDbContext, int>()
```

  - **Create your own authorization controller**:

To **support the password or the client credentials flow, you must provide your own token endpoint action**:

```csharp
[HttpPost("~/connect/token")]
[Produces("application/json")]
public async Task<IActionResult> Exchange() {
    var request = HttpContext.GetOpenIdConnectRequest();

    if (request.IsPasswordGrantType()) {
        var user = await _userManager.FindByNameAsync(request.Username);
        if (user == null) {
            return BadRequest(new OpenIdConnectResponse {
                Error = OpenIdConnectConstants.Errors.InvalidGrant,
                ErrorDescription = "The username/password couple is invalid."
            });
        }

        // Ensure the password is valid.
        if (!await _userManager.CheckPasswordAsync(user, request.Password)) {
            if (_userManager.SupportsUserLockout) {
                await _userManager.AccessFailedAsync(user);
            }

            return BadRequest(new OpenIdConnectResponse {
                Error = OpenIdConnectConstants.Errors.InvalidGrant,
                ErrorDescription = "The username/password couple is invalid."
            });
        }

        if (_userManager.SupportsUserLockout) {
            await _userManager.ResetAccessFailedCountAsync(user);
        }

        var identity = await _userManager.CreateIdentityAsync(user, request.GetScopes());

        // Create a new authentication ticket holding the user identity.
        var ticket = new AuthenticationTicket(
            new ClaimsPrincipal(identity),
            new AuthenticationProperties(),
            OpenIdConnectServerDefaults.AuthenticationScheme);

        ticket.SetResources(request.GetResources());
        ticket.SetScopes(request.GetScopes());

        return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
    }

    return BadRequest(new OpenIdConnectResponse {
        Error = OpenIdConnectConstants.Errors.UnsupportedGrantType,
        ErrorDescription = "The specified grant type is not supported."
    });
}
```

To **enable authorization code/implicit flows support, you'll similarly have to create your own authorization endpoint action** and your own views/view models. The Mvc.Server sample comes with an [`AuthorizationController` that you can easily reuse in your application](https://github.com/openiddict/openiddict-core/blob/dev/samples/Mvc.Server/Controllers/AuthorizationController.cs).

![](https://cloud.githubusercontent.com/assets/6998306/10988233/d9026712-843a-11e5-8ff0-e7addffd727b.png)

  - **Enable the corresponding flows in the OpenIddict options**:

```csharp
public void ConfigureServices(IServiceCollection services) {
	// Register the OpenIddict services, including the default Entity Framework stores.
	services.AddOpenIddict<ApplicationUser, ApplicationDbContext>()
        // Enable the authorization and token endpoints (required to use the code flow).
        .EnableAuthorizationEndpoint("/connect/authorize")
        .EnableTokenEndpoint("/connect/token")

        // Allow client applications to use the code flow.
        .AllowAuthorizationCodeFlow()

	    // During development, you can disable the HTTPS requirement.
	    .DisableHttpsRequirement()

        // Register a new ephemeral key, that is discarded when the application
        // shuts down. Tokens signed using this key are automatically invalidated.
        // This method should only be used during development.
        .AddEphemeralSigningKey();
}
```

  - **Register your client application**:

```csharp
using (var context = new ApplicationDbContext(
    app.ApplicationServices.GetRequiredService<DbContextOptions<ApplicationDbContext>>())) {
    context.Database.EnsureCreated();

    if (!context.Applications.Any()) {
        context.Applications.Add(new OpenIddictApplication {
            // Assign a unique identifier to your client app:
            Id = "48BF1BC3-CE01-4787-BBF2-0426EAD21342",

            // Assign a display named used in the consent form page:
            DisplayName = "MVC Core client application",

            // Register the appropriate redirect_uri and post_logout_redirect_uri:
            RedirectUri = "http://localhost:53507/signin-oidc",
            LogoutRedirectUri = "http://localhost:53507/",

            // Generate a new derived key from the client secret:
            Secret = Crypto.HashPassword("secret_secret_secret"),

            // Note: use "public" for JS/mobile/desktop applications
            // and "confidential" for server-side applications.
            Type = OpenIddictConstants.ClientTypes.Confidential
        });

        context.SaveChanges();
    }
}
```

## Resources

**Looking for additional resources to help you get started?** Don't miss these interesting blog posts:

- **[Setting up ASP.NET v5 (vNext) to use JWT tokens (using OpenIddict)](http://capesean.co.za/blog/asp-net-5-jwt-tokens/)** by [Sean Walsh](https://github.com/capesean/)
- **[Using OpenIddict to easily add token authentication to your .NET web apps](http://overengineer.net/Using-OpenIddict-to-easily-add-token-authentication-to-your-.NET-web-apps)** by [Josh Comley](https://github.com/joshcomley)
- **[Authorizing your .NET Core MVC6 API requests with OpenIddict and Identity](http://kerryritter.com/authorizing-your-net-core-mvc6-api-requests-with-openiddict-and-identity/)** by [Kerry Ritter](https://github.com/kerryritter)
- **[Creating your own OpenID Connect server with ASOS](http://kevinchalet.com/2016/07/13/creating-your-own-openid-connect-server-with-asos-introduction/)** by [Kévin Chalet](https://github.com/PinpointTownes)

## Support

**Need help or wanna share your thoughts? Don't hesitate to join our dedicated chat rooms:**

- **JabbR: [https://jabbr.net/#/rooms/aspnet-contrib](https://jabbr.net/#/rooms/aspnet-contrib)**
- **Gitter: [https://gitter.im/openiddict/openiddict-core](https://gitter.im/openiddict/openiddict-core)**

## Contributors

**OpenIddict** is actively maintained by **[Kévin Chalet](https://github.com/PinpointTownes)**. Contributions are welcome and can be submitted using pull requests.

**Special thanks to [Christopher McCrum](https://github.com/chrisjmccrum) and [Data Citadel](http://www.datacitadel.com/) for their incredible support**.

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
