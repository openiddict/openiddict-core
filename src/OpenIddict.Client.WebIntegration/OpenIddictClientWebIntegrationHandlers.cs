/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Net.Http.Headers;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlerFilters;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;
using Properties = OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants.Properties;

namespace OpenIddict.Client.WebIntegration;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
        /*
         * Authentication processing:
         */
        ResolveDynamicUserinfoEndpoint.Descriptor,

        /*
         * Challenge processing:
         */
        AttachDefaultScopes.Descriptor,
        FormatNonStandardScopeParameter.Descriptor)
        .AddRange(Exchange.DefaultHandlers)
        .AddRange(Userinfo.DefaultHandlers);

    /// <summary>
    /// Contains the logic responsible for resolving the address of
    /// dynamic userinfo endpoints for providers that require it.
    /// </summary>
    public class ResolveDynamicUserinfoEndpoint : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ResolveDynamicUserinfoEndpoint>()
                .SetOrder(ResolveUserinfoEndpoint.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // The following providers are known to use dynamic userinfo endpoints:
            context.UserinfoEndpoint = context.Registration.GetProviderName() switch
            {
                // Salesforce exposes a userinfo endpoint whose address is user-specific
                // and returned as part of the token response when using the code flow.
                Providers.Salesforce => (string?) context.TokenResponse?["id"] is string address &&
                    Uri.TryCreate(address, UriKind.Absolute, out Uri? uri) ? uri : null,

                _ => context.UserinfoEndpoint
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching default scopes for providers that require it.
    /// </summary>
    public class AttachDefaultScopes : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<AttachDefaultScopes>()
                .SetOrder(AttachScopes.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: Reddit requires sending at least one scope element. If no scope parameter
            // is set, a misleading "invalid client identifier" error is returned to the caller.
            // To prevent that, the "identity" scope is always added by default.
            if (context.Registration.GetProviderName() is Providers.Reddit)
            {
                context.Scopes.Add("identity");
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for overriding the standard "scope"
    /// parameter for providers that are known to use a non-standard format.
    /// </summary>
    public class FormatNonStandardScopeParameter : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<FormatNonStandardScopeParameter>()
                .SetOrder(AttachChallengeParameters.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.Request.Scope = context.Registration.GetProviderName() switch
            {
                // The following providers are known to use comma-separated scopes instead of
                // the standard format (that requires using a space as the scope separator):
                Providers.Reddit
                    when context.GrantType is GrantTypes.AuthorizationCode or GrantTypes.Implicit
                    => string.Join(",", context.Scopes),

                _ => context.Request.Scope
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for overriding the user agent for providers
    /// that are known to require or encourage using custom values (e.g Reddit).
    /// </summary>
    public class UseProductNameAsUserAgent<TContext> : IOpenIddictClientHandler<TContext>
        where TContext : BaseExternalContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpMetadataAddress>()
                .UseSingletonHandler<UseProductNameAsUserAgent<TContext>>()
                .SetOrder(int.MaxValue - 200_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another client stack.
            var request = context.Transaction.GetHttpRequestMessage() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

            // A few providers (like Reddit) are known to aggressively check user agents and encourage
            // developers to use unique user agents. While OpenIddict itself always adds a user agent,
            // the default value doesn't differ accross applications. To reduce the risks of seeing
            // requests blocked by these providers, the user agent is replaced by a custom value
            // containing the product name and version set by the user or by the client identifier.
            if (context.Registration.GetProviderName() is Providers.Reddit)
            {
                var (name, version) = (
                    GetProductName(context.Registration.Properties) ?? context.Registration.ClientId!,
                    GetProductVersion(context.Registration.Properties));

                request.Headers.UserAgent.Add(new ProductInfoHeaderValue(name, version));
            }

            static string? GetProductName(IReadOnlyDictionary<string, object?> properties)
                => properties.TryGetValue(Properties.ProductName, out object? value) && value is string name ? name : null;

            static string? GetProductVersion(IReadOnlyDictionary<string, object?> properties)
                => properties.TryGetValue(Properties.ProductVersion, out object? value) && value is string version ? version : null;

            return default;
        }
    }
}
