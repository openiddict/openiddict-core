/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Server
{
    public class OpenIddictServerTokenHandler : JsonWebTokenHandler
    {
        public ValueTask<string> CreateTokenFromDescriptorAsync(SecurityTokenDescriptor descriptor)
        {
            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            if (descriptor.Subject == null)
            {
                throw new ArgumentException("The subject associated with a descriptor cannot be null.", nameof(descriptor));
            }

            if (descriptor.Claims == null)
            {
                throw new InvalidOperationException("The claims collection cannot be null or empty.");
            }

            if (!descriptor.Claims.TryGetValue(Claims.Private.TokenUsage, out var type) || string.IsNullOrEmpty((string) type))
            {
                throw new InvalidOperationException("The token usage cannot be null or empty.");
            }

            var destinations = new Dictionary<string, string[]>(StringComparer.Ordinal);
            foreach (var group in descriptor.Subject.Claims.GroupBy(claim => claim.Type))
            {
                var collection = group.ToList();

                // Note: destinations are attached to claims as special CLR properties. Such properties can't be serialized
                // as part of classic JWT tokens. To work around this limitation, claim destinations are added to a special
                // claim named oi_cl_dstn that contains a map of all the claims and their attached destinations, if any.

                var set = new HashSet<string>(collection[0].GetDestinations(), StringComparer.OrdinalIgnoreCase);
                if (set.Count != 0)
                {
                    // Ensure the other claims of the same type use the same exact destinations.
                    for (var index = 0; index < collection.Count; index++)
                    {
                        if (!set.SetEquals(collection[index].GetDestinations()))
                        {
                            throw new InvalidOperationException($"Conflicting destinations for the claim '{group.Key}' were specified.");
                        }
                    }

                    destinations[group.Key] = set.ToArray();
                }
            }

            // Unless at least one claim was added to the claim destinations map,
            // don't add the special claim to avoid adding a useless empty claim.
            if (destinations.Count != 0)
            {
                descriptor.Claims[Claims.Private.ClaimDestinations] = destinations;
            }

            return new ValueTask<string>(base.CreateToken(descriptor));
        }

        public ValueTask<TokenValidationResult> ValidateTokenStringAsync(string token, TokenValidationParameters parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            if (!parameters.PropertyBag.TryGetValue(Claims.Private.TokenUsage, out var type) || string.IsNullOrEmpty((string) type))
            {
                throw new InvalidOperationException("The token usage cannot be null or empty.");
            }

            if (!CanReadToken(token))
            {
                return new ValueTask<TokenValidationResult>(new TokenValidationResult
                {
                    Exception = new SecurityTokenException("The token was not compatible with the JWT format."),
                    IsValid = false
                });
            }

            try
            {
                var result = base.ValidateToken(token, parameters);
                if (result == null || !result.IsValid)
                {
                    return new ValueTask<TokenValidationResult>(new TokenValidationResult
                    {
                        Exception = result?.Exception,
                        IsValid = false
                    });
                }

                var assertion = ((JsonWebToken) result.SecurityToken)?.InnerToken ?? (JsonWebToken) result.SecurityToken;

                if (!assertion.TryGetPayloadValue(Claims.Private.TokenUsage, out string usage) ||
                    !string.Equals(usage, (string) type, StringComparison.OrdinalIgnoreCase))
                {
                    return new ValueTask<TokenValidationResult>(new TokenValidationResult
                    {
                        Exception = new SecurityTokenException("The token usage associated to the token does not match the expected type."),
                        IsValid = false
                    });
                }

                // Restore the claim destinations from the special oi_cl_dstn claim (represented as a dictionary/JSON object).
                if (assertion.TryGetPayloadValue(Claims.Private.ClaimDestinations, out IDictionary<string, string[]> definitions))
                {
                    foreach (var definition in definitions)
                    {
                        foreach (var claim in result.ClaimsIdentity.Claims.Where(claim => claim.Type == definition.Key))
                        {
                            claim.SetDestinations(definition.Value);
                        }
                    }
                }

                return new ValueTask<TokenValidationResult>(result);
            }

            catch (Exception exception)
            {
                return new ValueTask<TokenValidationResult>(new TokenValidationResult
                {
                    Exception = exception,
                    IsValid = false
                });
            }
        }
    }
}
