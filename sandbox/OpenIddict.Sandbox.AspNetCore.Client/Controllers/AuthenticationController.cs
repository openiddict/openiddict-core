using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Client.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Sandbox.AspNetCore.Client.Controllers;

public class AuthenticationController : Controller
{
    [HttpGet("~/login")]
    public ActionResult LogIn(string provider, string returnUrl)
    {
        var issuer = provider switch
        {
            "local" or "local-github" => "https://localhost:44395/",
            "github"                  => "https://github.com/",
            "google"                  => "https://accounts.google.com/",
            "reddit"                  => "https://www.reddit.com/",
            "twitter"                 => "https://twitter.com/",

            _ => null
        };

        if (string.IsNullOrEmpty(issuer))
        {
            return BadRequest();
        }

        var properties = new AuthenticationProperties(new Dictionary<string, string>
        {
            // Note: when only one client is registered in the client options,
            // setting the issuer property is not required and can be omitted.
            [OpenIddictClientAspNetCoreConstants.Properties.Issuer] = issuer
        })
        {
            // Only allow local return URLs to prevent open redirect attacks.
            RedirectUri = Url.IsLocalUrl(returnUrl) ? returnUrl : "/"
        };

        // The local authorization server sample allows the client to select the external
        // identity provider that will be used to eventually authenticate the user. For that,
        // a custom "identity_provider" parameter is sent to the authorization server so that
        // the user is directly redirected to GitHub (in this case, no login page is shown).
        if (provider is "local-github")
        {
            properties.Parameters[Parameters.IdentityProvider] = "github";
        }

        // Ask the OpenIddict client middleware to redirect the user agent to the identity provider.
        return Challenge(properties, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
    }

    // Note: this controller uses the same callback action for all providers
    // but for users who prefer using a different action per provider,
    // the following action can be split into separate actions.
    [HttpGet("~/signin-{provider}"), HttpPost("~/signin-{provider}")]
    public async Task<ActionResult> Callback()
    {
        // Retrieve the authorization data validated by OpenIddict as part of the callback handling.
        var result = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

        // Multiple strategies exist to handle OAuth 2.0/OpenID Connect callbacks, each with their pros and cons:
        //
        //   * Directly using the tokens to perform the necessary action(s) on behalf of the user, which is suitable
        //     for applications that don't need a long-term access to the user's resources or don't want to store
        //     access/refresh tokens in a database or in an authentication cookie (which has security implications).
        //     It is also suitable for applications that don't need to authenticate users but only need to perform
        //     action(s) on their behalf by making API calls using the access token returned by the remote server.
        //
        //   * Storing the external claims/tokens in a database (and optionally keeping the essential claims in an
        //     authentication cookie so that cookie size limits are not hit). For the applications that use ASP.NET
        //     Core Identity, the UserManager.SetAuthenticationTokenAsync() API can be used to store external tokens.
        //
        //     Note: in this case, it's recommended to use column encryption to protect the tokens in the database.
        //
        //   * Storing the external claims/tokens in an authentication cookie, which doesn't require having
        //     a user database but may be affected by the cookie size limits enforced by most browser vendors
        //     (e.g Safari for macOS and Safari for iOS/iPadOS enforce a per-domain 4KB limit for all cookies).
        //
        //     Note: this is the approach used here, but the external claims are first filtered to only persist
        //     a few claims like the user identifier. The same approach is used to store the access/refresh tokens.

        // Important: if the remote server doesn't support OpenID Connect and doesn't expose a userinfo endpoint,
        // result.Principal.Identity will represent an unauthenticated identity and won't contain any claim.
        //
        // Such identities cannot be used as-is to build an authentication cookie in ASP.NET Core (as the
        // antiforgery stack requires at least a name claim to bind CSRF cookies to the user's identity) but
        // the access/refresh tokens can be retrieved using result.Properties.GetTokens() to make API calls.
        if (result.Principal.Identity is not ClaimsIdentity { IsAuthenticated: true })
        {
            throw new InvalidOperationException("The external authorization data cannot be used for authentication.");
        }

        // Build an identity based on the external claims and that will be used to create the authentication cookie.
        //
        // By default, all claims extracted during the authorization dance are available. The claims collection stored
        // in the cookie can be filtered out or mapped to different names depending the claim name or its issuer.
        var claims = new List<Claim>(result.Principal.Claims
            .Select(claim => claim switch
            {
                // Applications can map non-standard claims issued by specific issuers to a standard equivalent.
                { Type: "id", Issuer: "https://github.com/" or "https://twitter.com/" }
                    => new Claim(Claims.Subject, claim.Value, claim.ValueType, claim.Issuer),

                _ => claim
            })
            .Where(claim => claim switch
            {
                // Preserve the "name" and "sub" claims.
                { Type: Claims.Name or Claims.Subject } => true,

                // Applications that use multiple client registrations can filter claims based on the issuer.
                { Type: "bio", Issuer: "https://github.com/" } => true,

                // Don't preserve the other claims.
                _ => false
            }));

        var identity = new ClaimsIdentity(claims,
            authenticationType: CookieAuthenticationDefaults.AuthenticationScheme,
            nameType: Claims.Name,
            roleType: Claims.Role);

        // Build the authentication properties based on the properties that were added when the challenge was triggered.
        var properties = new AuthenticationProperties(result.Properties.Items);

        // If needed, the tokens returned by the authorization server can be stored in the authentication cookie.
        // To make cookies less heavy, tokens that are not used are filtered out before creating the cookie.
        properties.StoreTokens(result.Properties.GetTokens().Where(token => token switch
        {
            // Preserve the access and refresh tokens returned in the token response, if available.
            {
                Name: OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken or
                      OpenIddictClientAspNetCoreConstants.Tokens.RefreshToken
            } => true,

            // Ignore the other tokens.
            _ => false
        }));

        // Note: "return SignIn(...)" cannot be directly used in this case, as the cookies handler doesn't allow
        // redirecting from an endpoint that doesn't match the path set in CookieAuthenticationOptions.LoginPath.
        // For more information about this restriction, visit https://github.com/dotnet/aspnetcore/issues/36934.
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity), properties);

        return Redirect(properties.RedirectUri);
    }

    [HttpGet("~/logout"), HttpPost("~/logout")]
    public ActionResult LogOut()
    {
        // Ask the cookies middleware to delete the local cookie created when the user agent
        // is redirected from the identity provider after a successful authorization flow.
        var properties = new AuthenticationProperties
        {
            RedirectUri = "/"
        };

        return SignOut(properties, CookieAuthenticationDefaults.AuthenticationScheme);
    }
}
