# OpenIddict
### The OpenID Connect server you'll be addicted to.

[![Build status](https://ci.appveyor.com/api/projects/status/46ofo2eusje0hcw2?svg=true)](https://ci.appveyor.com/project/openiddict/openiddict-core)
[![Build status](https://travis-ci.org/openiddict/openiddict-core.svg)](https://travis-ci.org/openiddict/openiddict-core)


### What's OpenIddict?

OpenIddict aims at providing a **simple and easy-to-use solution** to implement an **OpenID Connect server in any ASP.NET Core application**.

OpenIddict is based on
**[AspNet.Security.OpenIdConnect.Server (codenamed ASOS)](https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server)** to control the OpenID Connect authentication flow and can be used with any membership stack, **including [ASP.NET Core Identity](https://github.com/aspnet/Identity)**.

OpenIddict fully supports the **[code/implicit/hybrid flows](http://openid.net/specs/openid-connect-core-1_0.html)** and the **[client credentials/resource owner password grants](https://tools.ietf.org/html/rfc6749)**. You can also create your own custom grant types.

Note: OpenIddict uses **[Entity Framework Core](https://github.com/aspnet/EntityFramework)** by default, but you can also provide your own store.

### Why an OpenID Connect server?

Adding an OpenID Connect server to your application **allows you to support token authentication**.
It also allows you to manage all your users using local password or an external identity provider
(e.g. Facebook or Google) for all your applications in one central place,
with the power to control who can access your API and the information that is exposed to each client.

## Samples

**[Specialized samples can be found in the samples repository](https://github.com/openiddict/openiddict-samples):**

  - [Authorization code flow sample](https://github.com/openiddict/openiddict-samples/tree/master/samples/CodeFlow)
  - [Implicit flow sample](https://github.com/openiddict/openiddict-samples/tree/master/samples/ImplicitFlow)
  - [Password flow sample](https://github.com/openiddict/openiddict-samples/tree/master/samples/PasswordFlow)
  - [Client credentials flow sample](https://github.com/openiddict/openiddict-samples/tree/master/samples/ClientCredentialsFlow)
  - [Refresh flow sample](https://github.com/openiddict/openiddict-samples/tree/master/samples/RefreshFlow)

--------------

## Getting started

To use OpenIddict, you need to:

  - **Install the latest [.NET Core tooling](https://www.microsoft.com/net/download) and update your packages to reference the ASP.NET Core RTM packages**.

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
  "OpenIddict": "1.0.0-*",
  "OpenIddict.EntityFrameworkCore": "1.0.0-*",
  "OpenIddict.Mvc": "1.0.0-*"
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
	    .AddEntityFrameworkCoreStores<ApplicationDbContext>()
	    .AddDefaultTokenProviders();

	// Register the OpenIddict services.
	services.AddOpenIddict()
        // Register the Entity Framework stores.
        .AddEntityFrameworkCoreStores<ApplicationDbContext>()

        // Register the ASP.NET Core MVC binder used by OpenIddict.
        // Note: if you don't call this method, you won't be able to
        // bind OpenIdConnectRequest or OpenIdConnectResponse parameters.
        .AddMvcBinders()

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

  - **Update your Entity Framework context registration to register the OpenIddict entities**:

```csharp
public class ApplicationDbContext : IdentityDbContext<ApplicationUser> {
    public ApplicationDbContext(DbContextOptions options)
        : base(options) { }

    protected override void OnModelCreating(ModelBuilder builder) {
        // Register the entity sets needed by OpenIddict.
        // Note: use the generic overload if you need
        // to replace the default OpenIddict entities.
        builder.UseOpenIddict();

        base.OnModelCreating(builder);

        // Customize the ASP.NET Identity model and override the defaults if needed.
        // For example, you can rename the ASP.NET Identity table names and more.
        // Add your customizations after calling base.OnModelCreating(builder);
    }
}
```

> **Note:** if you change the default entity primary key (e.g. to `int` or `Guid` instead of `string`), make sure to use the `AddEntityFrameworkCoreStores` overload accepting a `TKey` generic argument and use the generic `builder.UseOpenIddict<TKey>()` overload:

```csharp
services.AddOpenIddict()
    .AddEntityFrameworkCoreStores<ApplicationDbContext, Guid>()
```

```csharp
protected override void OnModelCreating(ModelBuilder builder) {
    // Register the entity sets needed by OpenIddict.
    builder.UseOpenIddict<Guid>();

    base.OnModelCreating(builder);

    // Customize the ASP.NET Identity model and override the defaults if needed.
    // For example, you can rename the ASP.NET Identity table names and more.
    // Add your customizations after calling base.OnModelCreating(builder);
}
```

  - **Create your own authorization controller**:

To **support the password or the client credentials flow, you must provide your own token endpoint action**.
To enable authorization code/implicit flows support, you'll similarly have to create your own authorization endpoint action and your own views/view models.

The **Mvc.Server sample comes with an [`AuthorizationController` that supports both the password flow and the authorization code flow and that you can easily reuse in your application](https://github.com/openiddict/openiddict-core/blob/dev/samples/Mvc.Server/Controllers/AuthorizationController.cs)**.

  - **Enable the corresponding flows in the OpenIddict options**:

```csharp
public void ConfigureServices(IServiceCollection services) {
	// Register the OpenIddict services.
	services.AddOpenIddict()
        // Register the Entity Framework stores.
        .AddEntityFrameworkCoreStores<ApplicationDbContext>()

        // Register the ASP.NET Core MVC binder used by OpenIddict.
        // Note: if you don't call this method, you won't be able to
        // bind OpenIdConnectRequest or OpenIdConnectResponse parameters.
        .AddMvcBinders()

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

    var applications = context.Set<OpenIddictApplication>();

    if (!applications.Any()) {
        applications.Add(new OpenIddictApplication {
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

**Looking for additional resources to help you get started?** Don't miss these interesting blog posts/books:

- **[Setting up ASP.NET v5 (vNext) to use JWT tokens (using OpenIddict)](http://capesean.co.za/blog/asp-net-5-jwt-tokens/)** by [Sean Walsh](https://github.com/capesean/)
- **[Using OpenIddict to easily add token authentication to your .NET web apps](http://overengineer.net/Using-OpenIddict-to-easily-add-token-authentication-to-your-.NET-web-apps)** by [Josh Comley](https://github.com/joshcomley)
- **[Authorizing your .NET Core MVC6 API requests with OpenIddict and Identity](http://kerryritter.com/authorizing-your-net-core-mvc6-api-requests-with-openiddict-and-identity/)** by [Kerry Ritter](https://github.com/kerryritter)
- **[Creating your own OpenID Connect server with ASOS](http://kevinchalet.com/2016/07/13/creating-your-own-openid-connect-server-with-asos-introduction/)** by [Kévin Chalet](https://github.com/PinpointTownes)
- **[Bearer Token Authentication in ASP.NET Core](https://blogs.msdn.microsoft.com/webdev/2016/10/27/bearer-token-authentication-in-asp-net-core/)** by [Mike Rousos](https://github.com/mjrousos) (for the Microsoft .NET Web Development and Tools blog)
- **[ASP.NET Core and Angular 2](https://www.amazon.com/ASP-NET-Core-Angular-Valerio-Sanctis-ebook/dp/B01DZQHCVU/)** by [Valerio De Sanctis](https://github.com/Darkseal)

## Support

**Need help or wanna share your thoughts?** Don't hesitate to join us on Gitter or ask your question on StackOverflow:

- **Gitter: [https://gitter.im/openiddict/openiddict-core](https://gitter.im/openiddict/openiddict-core)**
- **StackOverflow: [https://stackoverflow.com/questions/tagged/openiddict](https://stackoverflow.com/questions/tagged/openiddict)**

## Contributors

**OpenIddict** is actively maintained by **[Kévin Chalet](https://github.com/PinpointTownes)**. Contributions are welcome and can be submitted using pull requests.

**Special thanks to [Christopher McCrum](https://github.com/chrisjmccrum) and [Data Citadel](http://www.datacitadel.com/) for their incredible support**.

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
