/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.Extensions.Options;
using Microsoft.Owin.Security.Infrastructure;

namespace OpenIddict.Client.Owin;

// See https://github.com/owin/owin/issues/7 for more information.
using AuthenticateDelegate = Func<
    /* Authentication types: */ string[]?,
    /* Callback:             */ Action<
        /* Identity:                   */ IIdentity?,
        /* Authentication properties:  */ IDictionary<string, string?>?,
        /* Authentication description: */ IDictionary<string, object?>?,
        /* State:                      */ object?>,
    /* State:                */ object?,
    Task>;

/// <summary>
/// Provides the entry point necessary to register the OpenIddict client handler in an OWIN pipeline.
/// Note: this middleware is intended to be used with dependency injection containers
/// that support middleware resolution, like Autofac. Since it depends on scoped services,
/// it is NOT recommended to instantiate it as a singleton like a regular OWIN middleware.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientOwinMiddleware : AuthenticationMiddleware<OpenIddictClientOwinOptions>
{
    private readonly IOpenIddictClientDispatcher _dispatcher;
    private readonly IOpenIddictClientFactory _factory;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientOwinMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline, if applicable.</param>
    /// <param name="options">The OpenIddict client OWIN options.</param>
    /// <param name="dispatcher">The OpenIddict client dispatcher.</param>
    /// <param name="factory">The OpenIddict client factory.</param>
    public OpenIddictClientOwinMiddleware(
        OwinMiddleware? next,
        IOptionsMonitor<OpenIddictClientOwinOptions> options,
        IOpenIddictClientDispatcher dispatcher,
        IOpenIddictClientFactory factory)
        : base(next, options.CurrentValue)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
    }

    /// <inheritdoc/>
    public override async Task Invoke(IOwinContext context)
    {
        // Retrieve the existing authentication delegate.
        var function = context.Get<AuthenticateDelegate?>("security.Authenticate");

        try
        {
            // Replace the security.Authenticate delegate responsible for listing authentication types and returning
            // identities to handle the forwarded authentication types managed by the OpenIddict OWIN client host.
            context.Set<AuthenticateDelegate>("security.Authenticate", async (types, callback, state) =>
            {
                // Note: a null array is typically used by OWIN to resolve all the configured authentication types.
                // In this case, iterate all the forwarded authentication types and call the callback action for each type.
                if (types is null)
                {
                    foreach (var description in Options.ForwardedAuthenticationTypes)
                    {
                        callback(null, null, description.Properties, state);
                    }
                }

                else if (types.Length is > 0)
                {
                    foreach (var type in types)
                    {
                        // If the specified authentication types don't match a forwarded authentication type
                        // managed by the OpenIddict OWIN client host, don't invoke the callback and let the
                        // corresponding authentication middleware handle it if it matches a registered type.
                        if (string.IsNullOrEmpty(type) ||
                            string.Equals(type, OpenIddictClientOwinDefaults.AuthenticationType, StringComparison.Ordinal) ||
                            !TryGetForwardedAuthenticationType(type, out AuthenticationDescription? description))
                        {
                            continue;
                        }

                        // Resolve the authentication result returned by the OpenIddict OWIN client host:
                        // if the returned identity was created by the specified provider, return the result
                        // and stop iterating (only a single identity is returned by the OWIN host).
                        //
                        // Note: exceptions MUST NOT be caught to ensure they are properly surfaced to the caller
                        // (e.g if AuthenticateAsync("[provider name]") is called from an unsupported endpoint).
                        if (await context.Authentication.AuthenticateAsync(OpenIddictClientOwinDefaults.AuthenticationType)
                            is { Identity: ClaimsIdentity identity } result &&
                            identity.FindFirst(Claims.Private.ProviderName)?.Value is string provider &&
                            string.Equals(provider, description.AuthenticationType, StringComparison.Ordinal))
                        {
                            callback(
                                new ClaimsIdentity(
                                    identity, identity.Claims, description.AuthenticationType,
                                    identity.NameClaimType, identity.RoleClaimType),
                                result.Properties.Dictionary, description.Properties, state);

                            break;
                        }
                    }
                }

                // Always invoke the original authentication delegate to allow the other
                // authentication middleware to return the authentication types they
                // support and the identities they were able to extract, if applicable.
                if (function is not null)
                {
                    await function(types, callback, state);
                }
            });

            await base.Invoke(context);
        }

        finally
        {
            // Restore the original authentication delegate.
            context.Set("security.Authenticate", function);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        bool TryGetForwardedAuthenticationType(string type, [NotNullWhen(true)] out AuthenticationDescription? result)
        {
            foreach (var description in Options.ForwardedAuthenticationTypes)
            {
                if (string.Equals(description.AuthenticationType, type, StringComparison.Ordinal))
                {
                    result = description;
                    return true;
                }
            }

            result = null;
            return false;
        }
    }

    /// <summary>
    /// Creates and returns a new <see cref="OpenIddictClientOwinHandler"/> instance.
    /// </summary>
    /// <returns>A new instance of the <see cref="OpenIddictClientOwinHandler"/> class.</returns>
    protected override AuthenticationHandler<OpenIddictClientOwinOptions> CreateHandler()
        => new OpenIddictClientOwinHandler(_dispatcher, _factory);
}
