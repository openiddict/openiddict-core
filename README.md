# OpenIddict, as an OpenID Connect Addict

### What's Open Iddict ?

OpenIddict library aims to provide a simple and easy out of the box solution to implement your OpenID Connect 
server for ASP.NET 5.
OpenIddict leverages the use of Identity (for user management) and Entityframework (as store provider).

### What's Open ID Connect ?

Open ID is a protocol that allows multiple clients to delegate the Authentication to one or multiple Authority servers.
Facebook, Google, Twitter, are all well-known as OpenId Authority Servers.

### Why should I want/need my own Open ID Connect Server?

There are many scenarios on when this may be useful, 

 1. Having multiple applications with one central place for authentication.
 2. Having non-trusted clients (like JavaScript, Desktop or Mobile applications).
 3. Needs or wants to use single sign-on for multiple services.

In general terms, you want to have a centralized authentication server/login and then any allowed clients
(yours or not) can use the authentication server to handle identity and claims.

--------------

## Getting Started

To use OpenIddict Server you need to include OpenIddict as a dependency in your project.json:
```
    "dependencies": {
        "OpenIddict": "1.0.0-*"
    },
```

In ConfigureServices there's a handy extension method for IdentityBuilder that you need to set up.
Here is a complete ConfigureServices including Identity, Mvc and EntityFramework:

```csharp
public void ConfigureServices(IServiceCollection services) {
    services.AddMvc();

    services.AddEntityFramework()
        .AddSqlServer()
        .AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(Configuration["Data:DefaultConnection:ConnectionString"]));

    services.AddIdentity<ApplicationUser, IdentityRole>()
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders()
        .AddOpenIddict();

    /// .... other services you may have
}

in your Configure method, you will need to use it:

```csharp
public void Configure(IApplicationBuilder app) {
    app.UseIdentity();
    
    // any external provider like, app.UseGoogleAuthentication, app.UseFacebookAuthentication, etc..
    
    app.UseOpenIddict(options => {
        // options
    });
}
```

> `UseOpenIddict()` must be **AFTER** `app.UseIdentity()` and any external providers.

### Configuration & Options.

<p>OpenIddict have multiple options you can set to customize for your requirements/needs.<p>

<table>
<thead>
    <tr><th>Options</th><th>type</th><th>Description</th><th>Default</th></tr>
</thead>
<tbody>
<tr>
<td>AuthenticationScheme</td>
<td>string</td>
<td>
    The base address used to uniquely identify the authorization server.<br>
    The URI must be absolute and may contain a path, but no query string or fragment part.<br>
    Unless AllowInsecureHttp has been set to true, an HTTPS address must be provided.
</td>
<td><code>oidc-server</code></td>
</tr>
<tr>
  <td>Issuer</td>
  <td>Uri</td>
  <td>The base address (absolute) used to uniquely identify the authorization server.<br>
      <sub><i>Unless <code>AllowInsecureHttp</code> has been set to <code>true</code>, an HTTPS address must be provided.</i></sub>
  </td>
  <td></td>
</tr>
<tr>
  <td>
    AuthorizationEndpointPath
    <br>
    LogoutEndpointPath
  </td>
  <td>PathString</td>
  <td>The path of the endpoint. Can be set to <code>PathString.Empty</code> to disable the endpoint</td>
  <td>
      <code>/connect/authorize</code>
      <br>
      <code>/connect/logout</code>
  </td>
      
</tr>
<tr>
  <td>
    AuthorizationCodeLifetime
    <br>
    AccessTokenLifetime
    <br>
    IdentityTokenLifetime
    <br>
    RefreshTokenLifetime
  </td>
  <td>TimeSpan</td>
  <td>The period of time the token or code remains valid after being issued.</td>
  <td>
    5 minutes
    <br>
    1 hour
    <br>
    20 minutes
    <br>
    6 hours
  </td>
</tr>
<tr>
  <td>UseSlidingExpiration</td>
  <td>bool</td>
  <td>
    Determines whether refresh tokens issued during a <code>grant_type=refresh_token</code> request should be generated with a new expiration date or should re-use the same expiration date as the original refresh token.
    <br>
    <sub>Set this property to <code>true</code> to assign a new expiration date each time a refresh token is issued, <code>false</code> to use the expiration date of the original refresh token.</sub>
  </td>
  <td><code>true</code></td>
</tr>
<tr>
  <td>ApplicationCanDisplayErrors</td>
  <td>bool</td>
  <td>Set to <code>true</code> if the web application is able to render error messages on the authorization endpoint.</td>
  <td><code>false</code></td>
</tr>
<tr>
  <td>AllowInsecureHttp</td>
  <td>bool</td>
  <td>
    True to allow incoming requests to arrive on HTTP and to allow redirect_uri parameters to have HTTP URI addresses.
    <br>
    <sub>Setting this option to false in production is strongly encouraged to mitigate man-in-the-middle attacks.</sub>
  </td>
  <td><code>false</code></td>
</tr>
<tr>
  <td>UseCustomViews</td>
  <td>bool</td>
  <td>
  OpenIddict comes with built in views out of the box. If you want to use your custom views, you can set this option to true and provide the following required views:
  <br>
  <ul>
    <li>Authorize.cshtml</li>
    <li>Logout.cshtml</li>
    <li>Signin.cshtml</li>
    <li>Error.cshtml</li>
  </ul>
  </td>
  <td><code>false</code></td>
</tr>
</tbody>
</table>

You can find working samples in the [samples](https://github.com/openiddict/core/tree/dev/samples) directory.

## Support

**Need help or wanna share your thoughts? Don't hesitate to join our dedicated chat rooms:**

- **JabbR: [https://jabbr.net/#/rooms/aspnet-contrib](https://jabbr.net/#/rooms/aspnet-contrib)**

## Contributors

**OpenIddict** is actively maintained by **[Kévin Chalet](https://github.com/PinpointTownes)**. Contributions are welcome and can be submitted using pull requests.

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
