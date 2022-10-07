using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using OpenIddict.Client.Owin;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Sandbox.AspNet.Client.Controllers
{
    public class AuthenticationController : Controller
    {
        [HttpGet, Route("~/login")]
        public ActionResult LogIn(string provider, string returnUrl)
        {
            var context = HttpContext.GetOwinContext();

            // Note: OpenIddict always validates the specified provider name when handling the challenge operation,
            // but the provider can also be validated earlier to return an error page or a special HTTP error code.
            if (!string.Equals(provider, "Local",           StringComparison.Ordinal) &&
                !string.Equals(provider, "Local+GitHub",    StringComparison.Ordinal) &&
                !string.Equals(provider, Providers.GitHub,  StringComparison.Ordinal) &&
                !string.Equals(provider, Providers.Google,  StringComparison.Ordinal) &&
                !string.Equals(provider, Providers.Twitter, StringComparison.Ordinal))
            {
                return new HttpStatusCodeResult(400);
            }

            // The local authorization server sample allows the client to select the external
            // identity provider that will be used to eventually authenticate the user. For that,
            // a custom "identity_provider" parameter is sent to the authorization server so that
            // the user is directly redirected to GitHub (in this case, no login page is shown).
            if (string.Equals(provider, "Local+GitHub", StringComparison.Ordinal))
            {
                var properties = new AuthenticationProperties(new Dictionary<string, string>
                {
                    // Note: when only one client is registered in the client options,
                    // specifying the issuer URI or the provider name is not required.
                    [OpenIddictClientOwinConstants.Properties.ProviderName] = "Local",

                    // Note: the OWIN host requires appending the #string suffix to indicate
                    // that the "identity_provider" property is a public string parameter.
                    [Parameters.IdentityProvider + OpenIddictClientOwinConstants.PropertyTypes.String] = "GitHub"
                })
                {
                    // Only allow local return URLs to prevent open redirect attacks.
                    RedirectUri = Url.IsLocalUrl(returnUrl) ? returnUrl : "/"
                };

                // Ask the OpenIddict client middleware to redirect the user agent to the identity provider.
                context.Authentication.Challenge(properties, OpenIddictClientOwinDefaults.AuthenticationType);
                return new EmptyResult();
            }

            else
            {
                var properties = new AuthenticationProperties(new Dictionary<string, string>
                {
                    // Note: when only one client is registered in the client options,
                    // specifying the issuer URI or the provider name is not required.
                    [OpenIddictClientOwinConstants.Properties.ProviderName] = provider
                })
                {
                    // Only allow local return URLs to prevent open redirect attacks.
                    RedirectUri = Url.IsLocalUrl(returnUrl) ? returnUrl : "/"
                };

                // Ask the OpenIddict client middleware to redirect the user agent to the identity provider.
                context.Authentication.Challenge(properties, OpenIddictClientOwinDefaults.AuthenticationType);
                return new EmptyResult();
            }
        }

        [HttpPost, Route("~/logout"), ValidateAntiForgeryToken]
        public async Task<ActionResult> LogOut(string returnUrl)
        {
            var context = HttpContext.GetOwinContext();

            // Retrieve the identity stored in the local authentication cookie. If it's not available,
            // this indicate that the user is already logged out locally (or has not logged in yet).
            var result = await context.Authentication.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationType);
            if (result is not { Identity: ClaimsIdentity identity })
            {
                // Only allow local return URLs to prevent open redirect attacks.
                return Redirect(Url.IsLocalUrl(returnUrl) ? returnUrl : "/");
            }

            // Remove the local authentication cookie before triggering a redirection to the remote server.
            context.Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);

            // Resolve the issuer of the user identifier claim stored in the local authentication cookie.
            // If the issuer is known to support remote sign-out, ask OpenIddict to initiate a logout request.
            var issuer = identity.Claims.Select(claim => claim.Issuer).First();
            if (issuer is "https://localhost:44349/")
            {
                var properties = new AuthenticationProperties(new Dictionary<string, string>
                {
                    // Note: when only one client is registered in the client options,
                    // setting the issuer property is not required and can be omitted.
                    [OpenIddictClientOwinConstants.Properties.Issuer] = issuer,

                    // While not required, the specification encourages sending an id_token_hint
                    // parameter containing an identity token returned by the server for this user.
                    [OpenIddictClientOwinConstants.Properties.IdentityTokenHint] =
                        result.Properties.Dictionary[OpenIddictClientOwinConstants.Tokens.BackchannelIdentityToken]
                })
                {
                    // Only allow local return URLs to prevent open redirect attacks.
                    RedirectUri = Url.IsLocalUrl(returnUrl) ? returnUrl : "/"
                };

                // Ask the OpenIddict client middleware to redirect the user agent to the identity provider.
                context.Authentication.SignOut(properties, OpenIddictClientOwinDefaults.AuthenticationType);
                return new EmptyResult();
            }

            // Only allow local return URLs to prevent open redirect attacks.
            return Redirect(Url.IsLocalUrl(returnUrl) ? returnUrl : "/");
        }

        // Note: this controller uses the same callback action for all providers
        // but for users who prefer using a different action per provider,
        // the following action can be split into separate actions.
        [AcceptVerbs("GET", "POST"), Route("~/callback/login/{provider}")]
        public async Task<ActionResult> LogInCallback()
        {
            var context = HttpContext.GetOwinContext();

            // Retrieve the authorization data validated by OpenIddict as part of the callback handling.
            var result = await context.Authentication.AuthenticateAsync(OpenIddictClientOwinDefaults.AuthenticationType);

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
            // Such identities cannot be used as-is to build an authentication cookie in ASP.NET (as the
            // antiforgery stack requires at least a name claim to bind CSRF cookies to the user's identity) but
            // the access/refresh tokens can be retrieved using result.Properties.GetTokens() to make API calls.
            if (result.Identity is not ClaimsIdentity { IsAuthenticated: true })
            {
                throw new InvalidOperationException("The external authorization data cannot be used for authentication.");
            }

            // Build an identity based on the external claims and that will be used to create the authentication cookie.
            //
            // By default, all claims extracted during the authorization dance are available. The claims collection stored
            // in the cookie can be filtered out or mapped to different names depending the claim name or its issuer.
            var claims = new List<Claim>(result.Identity.Claims
                .Select(claim => claim switch
                {
                    // Map the standard "sub" and custom "id" claims to ClaimTypes.NameIdentifier, which is
                    // the default claim type used by .NET and is required by the antiforgery components.
                    { Type: Claims.Subject } or
                    { Type: "id", Issuer: "https://github.com/" or "https://twitter.com/" }
                        => new Claim(ClaimTypes.NameIdentifier, claim.Value, claim.ValueType, claim.Issuer),

                    // Map the standard "name" claim to ClaimTypes.Name.
                    { Type: Claims.Name }
                        => new Claim(ClaimTypes.Name, claim.Value, claim.ValueType, claim.Issuer),

                    // The antiforgery components require an "identityprovider" claim, which
                    // is mapped from the authorization server claim returned by OpenIddict.
                    { Type: Claims.AuthorizationServer }
                        => new Claim("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider",
                            claim.Value, claim.ValueType, claim.Issuer),

                    _ => claim
                })
                .Where(claim => claim switch
                {
                    // Preserve the basic claims that are necessary for the application to work correctly.
                    {
                        Type: ClaimTypes.NameIdentifier or
                              ClaimTypes.Name           or
                              "http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider"
                    } => true,

                    // Applications that use multiple client registrations can filter claims based on the issuer.
                    { Type: "bio", Issuer: "https://github.com/" } => true,

                    // Don't preserve the other claims.
                    _ => false
                }));

            var identity = new ClaimsIdentity(claims,
                authenticationType: CookieAuthenticationDefaults.AuthenticationType,
                nameType: ClaimTypes.Name,
                roleType: ClaimTypes.Role);

            // Build the authentication properties based on the properties that were added when the challenge was triggered.
            var properties = new AuthenticationProperties(result.Properties.Dictionary
                .Where(item => item switch
                {
                    // Preserve the redirect URL.
                    { Key: ".redirect" } => true,

                    // If needed, the tokens returned by the authorization server can be stored in the authentication cookie.
                    {
                        Key: OpenIddictClientOwinConstants.Tokens.BackchannelAccessToken   or
                             OpenIddictClientOwinConstants.Tokens.BackchannelIdentityToken or
                             OpenIddictClientOwinConstants.Tokens.RefreshToken
                    } => true,

                    // Don't add the other properties to the external cookie.
                    _ => false
                })
                .ToDictionary(pair => pair.Key, pair => pair.Value));

            context.Authentication.SignIn(properties, identity);
            return Redirect(properties.RedirectUri);
        }

        // Note: this controller uses the same callback action for all providers
        // but for users who prefer using a different action per provider,
        // the following action can be split into separate actions.
        [AcceptVerbs("GET", "POST"), Route("~/callback/logout/{provider}")]
        public async Task<ActionResult> LogOutCallback()
        {
            var context = HttpContext.GetOwinContext();

            // Retrieve the data stored by OpenIddict in the state token created when the logout was triggered.
            var result = await context.Authentication.AuthenticateAsync(OpenIddictClientOwinDefaults.AuthenticationType);

            // In this sample, the local authentication cookie is always removed before the user agent is redirected
            // to the authorization server. Applications that prefer delaying the removal of the local cookie can
            // remove the corresponding code from the logout action and remove the authentication cookie in this action.

            return Redirect(result.Properties.RedirectUri);
        }
    }
}
