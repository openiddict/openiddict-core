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

    services.AddEntityFramework()
        .AddSqlServer()
        .AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(Configuration["Data:DefaultConnection:ConnectionString"]));

    // Register the Identity services.
	services.AddIdentity<ApplicationUser, IdentityRole>()
	    .AddEntityFrameworkStores<ApplicationDbContext>()
	    .AddDefaultTokenProviders();
	
	// Register the OpenIddict services, including the default Entity Framework stores.
	services.AddOpenIddict<ApplicationUser, ApplicationDbContext>()
	    // During development, you can disable the HTTPS requirement.
	    .DisableHttpsRequirement();
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

## Enabling interactive flows support

Out-the-box, **OpenIddict only enables non-interactive flows** (resource owner password credentials, client credentials, refresh token).

To enable authorization code/implicit flows support, OpenIddict offers **an optional ASP.NET Core MVC module** that includes an authorization controller and a few native views that you can easily replace by your own ones to fully customize your login experience.

![](https://cloud.githubusercontent.com/assets/6998306/10988233/d9026712-843a-11e5-8ff0-e7addffd727b.png)

  - **Reference the necessary modules**:

```json
"dependencies": {
  "OpenIddict": "1.0.0-*",
  "OpenIddict.Assets": "1.0.0-*",
  "OpenIddict.Mvc": "1.0.0-*",
  "OpenIddict.Security": "1.0.0-*"
}
```

  - **Register the modules in `ConfigureServices`**:

```csharp
// Register the OpenIddict services, including the default Entity Framework stores.
services.AddOpenIddict<ApplicationUser, ApplicationDbContext>()
    // Register the HTML/CSS assets and MVC modules to handle the interactive flows.
    // Note: these modules are not necessary when using your own authorization controller
    // or when using non-interactive flows-only like the resource owner password credentials grant.
    .AddAssets()
    .AddMvc()

    // Register the NWebsec module. Note: you can replace the default Content Security Policy (CSP)
    // by calling UseNWebsec with a custom delegate instead of using the parameterless extension.
    // This can be useful to allow your HTML views to reference remote scripts/images/styles.
    .AddNWebsec(options => options.DefaultSources(directive => directive.Self())
        .ImageSources(directive => directive.Self()
            .CustomSources("*"))
        .ScriptSources(directive => directive.Self()
            .UnsafeInline()
            .CustomSources("https://my.custom.url/"))
        .StyleSources(directive => directive.Self()
            .UnsafeInline()))

    // During development, you can disable the HTTPS requirement.
    .DisableHttpsRequirement();
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

## Support

**Need help or wanna share your thoughts? Don't hesitate to join our dedicated chat rooms:**

- **JabbR: [https://jabbr.net/#/rooms/aspnet-contrib](https://jabbr.net/#/rooms/aspnet-contrib)**
- **Gitter: [https://gitter.im/openiddict/openiddict-core](https://gitter.im/openiddict/openiddict-core)**

## Contributors

**OpenIddict** is actively maintained by **[Kévin Chalet](https://github.com/PinpointTownes)**. Contributions are welcome and can be submitted using pull requests.

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
