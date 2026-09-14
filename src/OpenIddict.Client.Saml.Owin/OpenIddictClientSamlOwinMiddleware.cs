/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Client.Saml.OpenIddictClientSamlConstants;
using static OpenIddict.Client.Saml.OpenIddictClientSamlModels;
using Claims = OpenIddict.Abstractions.OpenIddictConstants.Claims;
using Parameters = OpenIddict.Client.Saml.OpenIddictClientSamlConstants.Parameters;
using Properties = OpenIddict.Client.Saml.OpenIddictClientSamlConstants.Properties;

namespace OpenIddict.Client.Saml.Owin;

/// <summary>
/// Handles the SAML 2.0 service provider challenges, assertion consumer service and metadata endpoints in an OWIN/Katana pipeline.
/// </summary>
/// <remarks>
/// Challenges are applied when the rest of the pipeline returns a 401 response whose authentication challenge
/// contains <see cref="OpenIddictClientSamlOwinOptions.AuthenticationType"/> or the provider name of a registration
/// that doesn't correspond to the authentication type of another authentication middleware registered before this
/// middleware (to ensure such types are always detected, register the SAML middleware after the other authentication middleware).
/// </remarks>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientSamlOwinMiddleware : OwinMiddleware
{
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSamlOwinMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline, if applicable.</param>
    public OpenIddictClientSamlOwinMiddleware(OwinMiddleware? next)
        : base(next)
    {
    }

    /// <inheritdoc/>
    public override async Task Invoke(IOwinContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var provider = context.Get<IServiceProvider>(typeof(IServiceProvider).FullName) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0900));

        var options = provider.GetService<IOptionsMonitor<OpenIddictClientSamlOwinOptions>>()?.CurrentValue ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0900));

        if (context.Request.Path == options.MetadataPath)
        {
            await MetadataAsync(context, provider, options);
            return;
        }

        if (context.Request.Path == options.AssertionConsumerServicePath && !await AssertionConsumerServiceAsync(context, provider, options))
        {
            return;
        }

        // Note: challenges are applied once the rest of the pipeline has completed (as with the OpenIddict client OWIN host,
        // challenges are not applied from Response.OnSendingHeaders(), where writing the auto-post page or awaiting the
        // registration and metadata resolution could deadlock). If the response headers were already sent by another
        // component (e.g a 401 response whose body was already written), the challenge cannot be applied and is ignored.
        var headers = new HeadersState();
        context.Response.OnSendingHeaders(static state => ((HeadersState) state).Sent = true, headers);

        if (Next is not null)
        {
            await Next.Invoke(context);
        }

        if (context.Response.StatusCode is 401 && context.Authentication.AuthenticationResponseChallenge is { } challenge &&
            await ResolveChallengeAsync(context, provider, options, challenge.AuthenticationTypes) is var (matched, registration) &&
            matched)
        {
            if (headers.Sent)
            {
                provider.GetService<ILogger<OpenIddictClientSamlOwinMiddleware>>()?.LogWarning(6686, SR.GetResourceString(SR.ID6686));
                return;
            }

            await ChallengeAsync(context, provider, options, registration, challenge.Properties ?? new AuthenticationProperties());
        }
    }

    private static async Task MetadataAsync(IOwinContext context, IServiceProvider provider, OpenIddictClientSamlOwinOptions options)
    {
        if (!string.Equals(context.Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = 405;
            return;
        }

        if (!ValidateTransportSecurity(context, options))
        {
            await WriteErrorAsync(context, SR.GetResourceString(SR.ID2458));
            return;
        }

        context.Response.ContentType = MediaTypes.Metadata;
        await WriteAsync(context, GetService(provider).CreateMetadata(GetUrl(context, options.AssertionConsumerServicePath)));
    }

    /// <summary>
    /// Handles the assertion consumer service requests.
    /// </summary>
    /// <returns><see langword="true"/> if the request must be passed to the rest of the pipeline.</returns>
    private static async Task<bool> AssertionConsumerServiceAsync(IOwinContext context, IServiceProvider provider, OpenIddictClientSamlOwinOptions options)
    {
        if (!ValidateTransportSecurity(context, options))
        {
            await WriteErrorAsync(context, SR.GetResourceString(SR.ID2458));
            return false;
        }

        // SAML bindings, 3.5.4: the response is sent as a form-encoded "SAMLResponse" parameter (HTTP-POST binding).
        if (!string.Equals(context.Request.Method, "POST", StringComparison.OrdinalIgnoreCase) ||
            context.Request.ContentType is not { Length: > 0 } type ||
            !type.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            await WriteErrorAsync(context, SR.GetResourceString(SR.ID2440));
            return false;
        }

        var form = await context.Request.ReadFormAsync();
        if (form.GetValues(Parameters.SamlResponse) is not { Count: 1 } || form.GetValues(Parameters.RelayState) is { Count: > 1 })
        {
            await WriteErrorAsync(context, SR.GetResourceString(SR.ID2440));
            return false;
        }

        var relayState = form.Get(Parameters.RelayState);

        // Restore the request state from the correlation cookie associated with the relay state, if applicable.
        RequestState? state = null;

        if (IsCorrelationIdentifier(relayState))
        {
            var name = options.CorrelationCookieName + relayState;
            if (context.Request.Cookies[name] is { Length: > 0 } value)
            {
                state = provider.GetRequiredService<OpenIddictClientSamlOwinStateProtector>().Unprotect(value);

                // Note: the correlation cookie is always removed to ensure it cannot be used again.
                context.Response.Cookies.Delete(name, CreateCookieOptions(context, options));
            }
        }

        var result = await GetService(provider).ValidateResponseAsync(form.Get(Parameters.SamlResponse), relayState, state,
            GetUrl(context, options.AssertionConsumerServicePath), context.Request.CallCancelled);

        context.Set(typeof(ResponseValidationResult).FullName, result);

        if (options.EnableAssertionConsumerServicePassthrough)
        {
            return true;
        }

        if (!result.Succeeded)
        {
            await WriteErrorAsync(context, result.ErrorDescription!);
            return false;
        }

        var properties = CreateProperties(result);

        // Note: Katana authentication middleware only apply sign-in grants whose identity uses their authentication type.
        context.Authentication.SignIn(properties, new ClaimsIdentity(result.Principal!.Claims,
            options.SignInAuthenticationType, Claims.Name, Claims.Role));

        context.Response.Headers.Set("Cache-Control", "no-cache, no-store");
        context.Response.Redirect(properties.RedirectUri ?? context.Request.PathBase.Add(new PathString("/")).ToUriComponent());

        return false;
    }

    private static async Task<(bool Matched, OpenIddictClientSamlRegistration? Registration)> ResolveChallengeAsync(
        IOwinContext context, IServiceProvider provider, OpenIddictClientSamlOwinOptions options, string[]? types)
    {
        if (types is null or [])
        {
            return (false, null);
        }

        foreach (var type in types)
        {
            if (string.Equals(type, options.AuthenticationType, StringComparison.Ordinal))
            {
                return (true, null);
            }
        }

        if (options.DisableAutomaticAuthenticationTypeForwarding)
        {
            return (false, null);
        }

        var service = GetService(provider);
        HashSet<string>? owned = null;

        foreach (var type in types)
        {
            if (string.IsNullOrEmpty(type))
            {
                continue;
            }

            // Note: authentication types handled by the other authentication middleware active in the pipeline
            // (e.g cookies) always take precedence over the provider names of the SAML registrations.
            owned ??= new HashSet<string>(context.Authentication.GetAuthenticationTypes()
                .Select(static description => description.AuthenticationType)
                .Where(static type => !string.IsNullOrEmpty(type)), StringComparer.Ordinal);

            if (owned.Contains(type))
            {
                continue;
            }

            // Note: the lookups (including negative lookups) are cached by the SAML service.
            if (await service.GetRegistrationsByProviderNameAsync(type, context.Request.CallCancelled) is [var registration])
            {
                return (true, registration);
            }
        }

        return (false, null);
    }

    private static async Task ChallengeAsync(IOwinContext context, IServiceProvider provider, OpenIddictClientSamlOwinOptions options,
        OpenIddictClientSamlRegistration? registration, AuthenticationProperties properties)
    {
        var service = GetService(provider);
        var cancellationToken = context.Request.CallCancelled;

        if (registration is not null)
        {
            if (properties.Dictionary.ContainsKey(Properties.RegistrationId) || properties.Dictionary.ContainsKey(Properties.ProviderName))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0905));
            }
        }

        else if (properties.Dictionary.TryGetValue(Properties.RegistrationId, out var identifier) && !string.IsNullOrEmpty(identifier))
        {
            registration = await service.GetRegistrationByIdAsync(identifier, cancellationToken);
        }

        else if (properties.Dictionary.TryGetValue(Properties.ProviderName, out var name) && !string.IsNullOrEmpty(name))
        {
            registration = await service.GetRegistrationByProviderNameAsync(name, cancellationToken);
        }

        else
        {
            registration = await service.GetRegistrationsAsync(cancellationToken) switch
            {
                [var candidate] => candidate,
                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0901))
            };
        }

        // Note: the current URL is used as the default return URL.
        if (string.IsNullOrEmpty(properties.RedirectUri))
        {
            properties.RedirectUri = context.Request.PathBase.Add(context.Request.Path).ToUriComponent() + context.Request.QueryString.ToUriComponent();
        }

        properties.Dictionary[Properties.RegistrationId] = registration.RegistrationId;
        properties.Dictionary[Properties.ProviderName] = registration.ProviderName;

        // Note: the relay state is a random correlation identifier (SAML bindings, 3.4.3 and 3.5.3 restrict it
        // to 80 bytes) used to locate the cookie storing the protected request state (and the return URL).
        var relayState = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(24));
        var acs = GetUrl(context, options.AssertionConsumerServicePath);

        var request = await service.CreateAuthenticationRequestAsync(registration, acs, relayState, cancellationToken);
        var state = service.CreateRequestState(registration, request, acs,
            properties.Dictionary.Select(static property => new KeyValuePair<string, string?>(property.Key, property.Value)));

        var cookie = CreateCookieOptions(context, options);
        cookie.Expires = state.ExpirationDate.UtcDateTime;

        context.Response.Cookies.Append(options.CorrelationCookieName + relayState,
            provider.GetRequiredService<OpenIddictClientSamlOwinStateProtector>().Protect(state), cookie);

        context.Response.Headers.Set("Cache-Control", "no-cache, no-store");
        context.Response.Headers.Set("Pragma", "no-cache");

        if (request.RedirectUrl is Uri url)
        {
            context.Response.Redirect(url.AbsoluteUri);
            return;
        }

        var nonce = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16));

        context.Response.StatusCode = 200;
        context.Response.Headers.Set("Content-Security-Policy", OpenIddictClientSamlService.CreateFormPostContentSecurityPolicy(request, nonce));
        context.Response.ContentType = "text/html; charset=utf-8";

        await WriteAsync(context, OpenIddictClientSamlService.CreateFormPostPage(request, nonce));
    }

    private static CookieOptions CreateCookieOptions(IOwinContext context, OpenIddictClientSamlOwinOptions options) => new()
    {
        HttpOnly = true,
        Path = context.Request.PathBase.Add(options.AssertionConsumerServicePath).ToUriComponent(),
        SameSite = SameSiteMode.None,
        Secure = true
    };

    private static AuthenticationProperties CreateProperties(ResponseValidationResult result)
    {
        if (result.State is RequestState state)
        {
            var dictionary = new Dictionary<string, string>(StringComparer.Ordinal);

            foreach (var property in state.Properties)
            {
                if (property.Value is not null)
                {
                    dictionary[property.Key] = property.Value;
                }
            }

            return new AuthenticationProperties(dictionary);
        }

        // Note: for unsolicited responses, the relay state is only used as the return URL if it's a local URL.
        var properties = new AuthenticationProperties
        {
            RedirectUri = IsLocalUrl(result.RelayState) ? result.RelayState : "/"
        };

        if (result.Registration?.RegistrationId is { Length: > 0 } identifier)
        {
            properties.Dictionary[Properties.RegistrationId] = identifier;
        }

        if (result.Registration?.ProviderName is { Length: > 0 } name)
        {
            properties.Dictionary[Properties.ProviderName] = name;
        }

        return properties;
    }

    private static bool IsCorrelationIdentifier(string? value)
        => value is { Length: > 0 and <= 64 } && value.All(static character => character is
            (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_');

    private static bool IsLocalUrl(string? value)
        => value is { Length: > 0 } && value[0] is '/' &&
           (value.Length is 1 || (value[1] is not ('/' or '\\') && !value.Any(char.IsControl)));

    private static OpenIddictClientSamlService GetService(IServiceProvider provider)
        => provider.GetService<OpenIddictClientSamlService>() ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0900));

    private static bool ValidateTransportSecurity(IOwinContext context, OpenIddictClientSamlOwinOptions options)
        => options.DisableTransportSecurityRequirement || context.Request.IsSecure;

    private static Uri GetUrl(IOwinContext context, PathString path)
        => new(context.Request.Scheme + Uri.SchemeDelimiter + context.Request.Host.Value +
            context.Request.PathBase.Add(path).ToUriComponent(), UriKind.Absolute);

    private static Task WriteErrorAsync(IOwinContext context, string description)
    {
        context.Response.StatusCode = 400;
        context.Response.Headers.Set("Cache-Control", "no-cache, no-store");
        context.Response.ContentType = "text/plain; charset=utf-8";
        context.Response.Headers.Set("X-Content-Type-Options", "nosniff");

        return WriteAsync(context, description);
    }

    private sealed class HeadersState
    {
        public bool Sent { get; set; }
    }

    private static Task WriteAsync(IOwinContext context, string content)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        context.Response.ContentLength = bytes.Length;

        return context.Response.WriteAsync(bytes, context.Request.CallCancelled);
    }
}
