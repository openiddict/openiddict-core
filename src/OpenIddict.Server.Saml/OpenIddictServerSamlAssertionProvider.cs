/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using Microsoft.Extensions.Options;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using static OpenIddict.Server.Saml.OpenIddictServerSamlModels;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Creates assertions from the claims of the authenticated principal.
/// </summary>
/// <remarks>
/// The NameID is resolved from the email claim when the emailAddress format is used, is a random
/// value when the transient format is used and is resolved from <see cref="OpenIddictServerSamlOptions.NameIdClaimTypes"/>
/// otherwise. Attributes are resolved using <see cref="OpenIddictServerSamlServiceProvider.AttributeMappings"/>.
/// </remarks>
public sealed class OpenIddictServerSamlAssertionProvider : IOpenIddictServerSamlAssertionProvider
{
    private readonly IOptionsMonitor<OpenIddictServerSamlOptions> _options;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSamlAssertionProvider"/> class.
    /// </summary>
    /// <param name="options">The SAML options.</param>
    public OpenIddictServerSamlAssertionProvider(IOptionsMonitor<OpenIddictServerSamlOptions> options)
        => _options = options ?? throw new ArgumentNullException(nameof(options));

    /// <inheritdoc/>
    public ValueTask<AssertionDescriptor?> CreateAssertionAsync(AssertionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var format = context.ServiceProvider.NameIdFormat;

        var value = format switch
        {
            NameIdFormats.EmailAddress => FindFirstValue(context.Principal, [Claims.Email, ClaimTypes.Email]),
            NameIdFormats.Transient    => OpenIddict.Extensions.OpenIddictSamlHelpers.CreateIdentifier(),
            _                          => FindFirstValue(context.Principal, _options.CurrentValue.NameIdClaimTypes)
        };

        if (string.IsNullOrEmpty(value))
        {
            return new(result: null);
        }

        List<AssertionAttribute> attributes = [];

        foreach (var mapping in context.ServiceProvider.AttributeMappings)
        {
            var values = context.Principal.FindAll(mapping.Key)
                .Select(static claim => claim.Value)
                .Where(static value => !string.IsNullOrEmpty(value))
                .Distinct(StringComparer.Ordinal)
                .ToList();

            if (values.Count is 0)
            {
                continue;
            }

            attributes.Add(new AssertionAttribute { Name = mapping.Value, Values = values });
        }

        return new(new AssertionDescriptor
        {
            Attributes = attributes,
            AuthenticationInstant = context.AuthenticationInstant,
            NameId = value,
            NameIdFormat = format,
            SessionIndex = context.Principal.FindFirst(Claims.SessionId)?.Value
        });

        static string? FindFirstValue(ClaimsPrincipal principal, IEnumerable<string> types)
        {
            foreach (var type in types)
            {
                var claim = principal.FindFirst(type);
                if (!string.IsNullOrEmpty(claim?.Value))
                {
                    return claim.Value;
                }
            }

            return null;
        }
    }
}
