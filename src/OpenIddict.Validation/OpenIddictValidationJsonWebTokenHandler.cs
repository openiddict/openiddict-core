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

namespace OpenIddict.Validation
{
    public class OpenIddictValidationJsonWebTokenHandler : JsonWebTokenHandler
    {
        public ValueTask<TokenValidationResult> ValidateTokenStringAsync(string token, TokenValidationParameters parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            if (parameters.PropertyBag == null)
            {
                throw new InvalidOperationException("The property bag cannot be null.");
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
