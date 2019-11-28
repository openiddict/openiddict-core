/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using JetBrains.Annotations;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Abstractions
{
    /// <summary>
    /// Provides extension methods to make <see cref="OpenIddictRequest"/>
    /// and <see cref="OpenIddictResponse"/> easier to work with.
    /// </summary>
    public static class OpenIddictExtensions
    {
        /// <summary>
        /// Extracts the authentication context class values from an <see cref="OpenIddictRequest"/>.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        public static ImmutableHashSet<string> GetAcrValues([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.AcrValues))
            {
                return ImmutableHashSet.Create<string>(StringComparer.Ordinal);
            }

            return ImmutableHashSet.CreateRange(StringComparer.Ordinal, GetValues(request.AcrValues, Separators.Space));
        }

        /// <summary>
        /// Extracts the response types from an <see cref="OpenIddictRequest"/>.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        public static ImmutableHashSet<string> GetResponseTypes([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.ResponseType))
            {
                return ImmutableHashSet.Create<string>(StringComparer.Ordinal);
            }

            return ImmutableHashSet.CreateRange(StringComparer.Ordinal, GetValues(request.ResponseType, Separators.Space));
        }

        /// <summary>
        /// Extracts the scopes from an <see cref="OpenIddictRequest"/>.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        public static ImmutableHashSet<string> GetScopes([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.Scope))
            {
                return ImmutableHashSet.Create<string>(StringComparer.Ordinal);
            }

            return ImmutableHashSet.CreateRange(StringComparer.Ordinal, GetValues(request.Scope, Separators.Space));
        }

        /// <summary>
        /// Determines whether the requested authentication context class values contain the specified item.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <param name="value">The component to look for in the parameter.</param>
        public static bool HasAcrValue([NotNull] this OpenIddictRequest request, [NotNull] string value)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException("The value cannot be null or empty.", nameof(value));
            }

            if (string.IsNullOrEmpty(request.AcrValues))
            {
                return false;
            }

            return HasValue(request.AcrValues, value, Separators.Space);
        }

        /// <summary>
        /// Determines whether the requested prompt contains the specified value.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <param name="prompt">The component to look for in the parameter.</param>
        public static bool HasPrompt([NotNull] this OpenIddictRequest request, [NotNull] string prompt)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(prompt))
            {
                throw new ArgumentException("The prompt cannot be null or empty.", nameof(prompt));
            }

            if (string.IsNullOrEmpty(request.Prompt))
            {
                return false;
            }

            return HasValue(request.Prompt, prompt, Separators.Space);
        }

        /// <summary>
        /// Determines whether the requested response type contains the specified value.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <param name="type">The component to look for in the parameter.</param>
        public static bool HasResponseType([NotNull] this OpenIddictRequest request, [NotNull] string type)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The response type cannot be null or empty.", nameof(type));
            }

            if (string.IsNullOrEmpty(request.ResponseType))
            {
                return false;
            }

            return HasValue(request.ResponseType, type, Separators.Space);
        }

        /// <summary>
        /// Determines whether the requested scope contains the specified value.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <param name="scope">The component to look for in the parameter.</param>
        public static bool HasScope([NotNull] this OpenIddictRequest request, [NotNull] string scope)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(scope))
            {
                throw new ArgumentException("The scope cannot be null or empty.", nameof(scope));
            }

            if (string.IsNullOrEmpty(request.Scope))
            {
                return false;
            }

            return HasValue(request.Scope, scope, Separators.Space);
        }

        /// <summary>
        /// Determines whether the "response_type" parameter corresponds to the "none" response type.
        /// See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a response_type=none request, <c>false</c> otherwise.</returns>
        public static bool IsNoneFlow([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.ResponseType))
            {
                return false;
            }

            var segment = Trim(new StringSegment(request.ResponseType), Separators.Space);
            if (segment.Length == 0)
            {
                return false;
            }

            return segment.Equals(ResponseTypes.None, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the "response_type" parameter corresponds to the authorization code flow.
        /// See http://tools.ietf.org/html/rfc6749#section-4.1.1 for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a code flow request, <c>false</c> otherwise.</returns>
        public static bool IsAuthorizationCodeFlow([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.ResponseType))
            {
                return false;
            }

            var segment = Trim(new StringSegment(request.ResponseType), Separators.Space);
            if (segment.Length == 0)
            {
                return false;
            }

            return segment.Equals(ResponseTypes.Code, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the "response_type" parameter corresponds to the implicit flow.
        /// See http://tools.ietf.org/html/rfc6749#section-4.2.1 and
        /// http://openid.net/specs/openid-connect-core-1_0.html for more information
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is an implicit flow request, <c>false</c> otherwise.</returns>
        public static bool IsImplicitFlow([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.ResponseType))
            {
                return false;
            }

            var flags = /* none: */ 0x00;

            foreach (var element in new StringTokenizer(request.ResponseType, Separators.Space))
            {
                var segment = Trim(element, Separators.Space);
                if (segment.Length == 0)
                {
                    continue;
                }

                if (segment.Equals(ResponseTypes.IdToken, StringComparison.Ordinal))
                {
                    flags |= /* id_token: */ 0x01;

                    continue;
                }

                // Note: though the OIDC core specs does not include the OAuth 2.0-inherited response_type=token,
                // it is considered as a valid response_type for the implicit flow for backward compatibility.
                else if (segment.Equals(ResponseTypes.Token, StringComparison.Ordinal))
                {
                    flags |= /* token */ 0x02;

                    continue;
                }

                // Always return false if the response_type item
                // is not a valid component for the implicit flow.
                return false;
            }

            // Return true if the response_type parameter contains "id_token" or "token".
            return (flags & /* id_token: */ 0x01) == 0x01 || (flags & /* token: */ 0x02) == 0x02;
        }

        /// <summary>
        /// Determines whether the "response_type" parameter corresponds to the hybrid flow.
        /// See http://tools.ietf.org/html/rfc6749#section-4.2.1 and
        /// http://openid.net/specs/openid-connect-core-1_0.html for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is an hybrid flow request, <c>false</c> otherwise.</returns>
        public static bool IsHybridFlow([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.ResponseType))
            {
                return false;
            }

            var flags = /* none */ 0x00;

            foreach (var element in new StringTokenizer(request.ResponseType, Separators.Space))
            {
                var segment = Trim(element, Separators.Space);
                if (segment.Length == 0)
                {
                    continue;
                }

                if (segment.Equals(ResponseTypes.Code, StringComparison.Ordinal))
                {
                    flags |= /* code: */ 0x01;

                    continue;
                }

                else if (segment.Equals(ResponseTypes.IdToken, StringComparison.Ordinal))
                {
                    flags |= /* id_token: */ 0x02;

                    continue;
                }

                else if (segment.Equals(ResponseTypes.Token, StringComparison.Ordinal))
                {
                    flags |= /* token: */ 0x04;

                    continue;
                }

                // Always return false if the response_type item
                // is not a valid component for the hybrid flow.
                return false;
            }

            // Return false if the response_type parameter doesn't contain "code".
            if ((flags & /* code: */ 0x01) != 0x01)
            {
                return false;
            }

            // Return true if the response_type parameter contains "id_token" or "token".
            return (flags & /* id_token: */ 0x02) == 0x02 || (flags & /* token: */ 0x04) == 0x04;
        }

        /// <summary>
        /// Determines whether the "response_mode" parameter corresponds to the fragment response mode.
        /// See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <returns>
        /// <c>true</c> if the request specified the fragment response mode or if
        /// it's the default value for the requested flow, <c>false</c> otherwise.
        /// </returns>
        public static bool IsFragmentResponseMode([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.Equals(request.ResponseMode, ResponseModes.Fragment, StringComparison.Ordinal))
            {
                return true;
            }

            // Don't guess the response_mode value
            // if an explicit value has been provided.
            if (!string.IsNullOrEmpty(request.ResponseMode))
            {
                return false;
            }

            // Both the implicit and the hybrid flows
            // use response_mode=fragment by default.
            return request.IsImplicitFlow() || request.IsHybridFlow();
        }

        /// <summary>
        /// Determines whether the "response_mode" parameter corresponds to the query response mode.
        /// See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <returns>
        /// <c>true</c> if the request specified the query response mode or if
        /// it's the default value for the requested flow, <c>false</c> otherwise.
        /// </returns>
        public static bool IsQueryResponseMode([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.Equals(request.ResponseMode, ResponseModes.Query, StringComparison.Ordinal))
            {
                return true;
            }

            // Don't guess the response_mode value
            // if an explicit value has been provided.
            if (!string.IsNullOrEmpty(request.ResponseMode))
            {
                return false;
            }

            // Code flow and "response_type=none" use response_mode=query by default.
            return request.IsAuthorizationCodeFlow() || request.IsNoneFlow();
        }

        /// <summary>
        /// Determines whether the "response_mode" parameter corresponds to the form post response mode.
        /// See http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <returns>
        /// <c>true</c> if the request specified the form post response mode or if
        /// it's the default value for the requested flow, <c>false</c> otherwise.
        /// </returns>
        public static bool IsFormPostResponseMode([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            return string.Equals(request.ResponseMode, ResponseModes.FormPost, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the "grant_type" parameter corresponds to the authorization code grant.
        /// See http://tools.ietf.org/html/rfc6749#section-4.1.3 for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a code grant request, <c>false</c> otherwise.</returns>
        public static bool IsAuthorizationCodeGrantType([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            return string.Equals(request.GrantType, GrantTypes.AuthorizationCode, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the "grant_type" parameter corresponds to the client credentials grant.
        /// See http://tools.ietf.org/html/rfc6749#section-4.4.2 for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a client credentials grant request, <c>false</c> otherwise.</returns>
        public static bool IsClientCredentialsGrantType([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            return string.Equals(request.GrantType, GrantTypes.ClientCredentials, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the "grant_type" parameter corresponds to the device code grant.
        /// See https://tools.ietf.org/html/rfc8628 for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a device code grant request, <c>false</c> otherwise.</returns>
        public static bool IsDeviceCodeGrantType([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            return string.Equals(request.GrantType, GrantTypes.DeviceCode, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the "grant_type" parameter corresponds to the password grant.
        /// See http://tools.ietf.org/html/rfc6749#section-4.3.2 for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a password grant request, <c>false</c> otherwise.</returns>
        public static bool IsPasswordGrantType([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            return string.Equals(request.GrantType, GrantTypes.Password, StringComparison.Ordinal);
        }

        /// <summary>
        /// Determines whether the "grant_type" parameter corresponds to the refresh token grant.
        /// See http://tools.ietf.org/html/rfc6749#section-6 for more information.
        /// </summary>
        /// <param name="request">The <see cref="OpenIddictRequest"/> instance.</param>
        /// <returns><c>true</c> if the request is a refresh token grant request, <c>false</c> otherwise.</returns>
        public static bool IsRefreshTokenGrantType([NotNull] this OpenIddictRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            return string.Equals(request.GrantType, GrantTypes.RefreshToken, StringComparison.Ordinal);
        }

        /// <summary>
        /// Gets the destinations associated with a claim.
        /// </summary>
        /// <param name="claim">The <see cref="Claim"/> instance.</param>
        /// <returns>The destinations associated with the claim.</returns>
        public static ImmutableHashSet<string> GetDestinations([NotNull] this Claim claim)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            claim.Properties.TryGetValue(Properties.Destinations, out string destinations);

            if (string.IsNullOrEmpty(destinations))
            {
                return ImmutableHashSet.Create<string>(StringComparer.OrdinalIgnoreCase);
            }

            return ImmutableHashSet.CreateRange(StringComparer.OrdinalIgnoreCase, JArray.Parse(destinations).Values<string>());
        }

        /// <summary>
        /// Determines whether the given claim contains the required destination.
        /// </summary>
        /// <param name="claim">The <see cref="Claim"/> instance.</param>
        /// <param name="destination">The required destination.</param>
        public static bool HasDestination([NotNull] this Claim claim, [NotNull] string destination)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            if (string.IsNullOrEmpty(destination))
            {
                throw new ArgumentException("The destination cannot be null or empty.", nameof(destination));
            }

            return GetDestinations(claim).Contains(destination, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Adds specific destinations to a claim.
        /// </summary>
        /// <param name="claim">The <see cref="Claim"/> instance.</param>
        /// <param name="destinations">The destinations.</param>
        public static Claim SetDestinations([NotNull] this Claim claim, IEnumerable<string> destinations)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            if (destinations == null || !destinations.Any())
            {
                claim.Properties.Remove(Properties.Destinations);

                return claim;
            }

            if (destinations.Any(destination => string.IsNullOrEmpty(destination)))
            {
                throw new ArgumentException("Destinations cannot be null or empty.", nameof(destinations));
            }

            claim.Properties[Properties.Destinations] =
                new JArray(destinations.Distinct(StringComparer.OrdinalIgnoreCase)).ToString(Formatting.None);

            return claim;
        }

        /// <summary>
        /// Adds specific destinations to a claim.
        /// </summary>
        /// <param name="claim">The <see cref="Claim"/> instance.</param>
        /// <param name="destinations">The destinations.</param>
        public static Claim SetDestinations([NotNull] this Claim claim, params string[] destinations)
            // Note: guarding the destinations parameter against null values
            // is not necessary as AsEnumerable() doesn't throw on null values.
            => claim.SetDestinations(destinations.AsEnumerable());

        /// <summary>
        /// Clones an identity by filtering its claims and the claims of its actor, recursively.
        /// </summary>
        /// <param name="identity">The <see cref="ClaimsIdentity"/> instance to filter.</param>
        /// <param name="filter">
        /// The delegate filtering the claims: return <c>true</c>
        /// to accept the claim, <c>false</c> to remove it.
        /// </param>
        public static ClaimsIdentity Clone(
            [NotNull] this ClaimsIdentity identity,
            [NotNull] Func<Claim, bool> filter)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (filter == null)
            {
                throw new ArgumentNullException(nameof(filter));
            }

            var clone = identity.Clone();

            // Note: make sure to call ToList() to avoid modifying
            // the initial collection iterated by ClaimsIdentity.Claims.
            foreach (var claim in clone.Claims.ToList())
            {
                if (!filter(claim))
                {
                    clone.RemoveClaim(claim);
                }
            }

            if (clone.Actor != null)
            {
                clone.Actor = clone.Actor.Clone(filter);
            }

            return clone;
        }

        /// <summary>
        /// Clones a principal by filtering its identities.
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/> instance to filter.</param>
        /// <param name="filter">
        /// The delegate filtering the claims: return <c>true</c>
        /// to accept the claim, <c>false</c> to remove it.
        /// </param>
        public static ClaimsPrincipal Clone(
            [NotNull] this ClaimsPrincipal principal,
            [NotNull] Func<Claim, bool> filter)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (filter == null)
            {
                throw new ArgumentNullException(nameof(filter));
            }

            var clone = new ClaimsPrincipal();

            foreach (var identity in principal.Identities)
            {
                clone.AddIdentity(identity.Clone(filter));
            }

            return clone;
        }

        /// <summary>
        /// Adds a claim to a given identity.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claim.</param>
        /// <param name="value">The value associated with the claim.</param>
        public static ClaimsIdentity AddClaim(
            [NotNull] this ClaimsIdentity identity,
            [NotNull] string type, [NotNull] string value)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The claim type cannot be null or empty.", nameof(type));
            }

            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException("The claim value cannot be null or empty.", nameof(value));
            }

            identity.AddClaim(new Claim(type, value));
            return identity;
        }

        /// <summary>
        /// Adds a claim to a given identity and specify one or more destinations.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claim.</param>
        /// <param name="value">The value associated with the claim.</param>
        /// <param name="destinations">The destinations associated with the claim.</param>
        public static ClaimsIdentity AddClaim(
            [NotNull] this ClaimsIdentity identity,
            [NotNull] string type, [NotNull] string value,
            [NotNull] IEnumerable<string> destinations)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The claim type cannot be null or empty.", nameof(type));
            }

            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException("The claim value cannot be null or empty.", nameof(value));
            }

            if (destinations == null)
            {
                throw new ArgumentNullException(nameof(destinations));
            }

            identity.AddClaim(new Claim(type, value).SetDestinations(destinations));
            return identity;
        }

        /// <summary>
        /// Adds a claim to a given identity and specify one or more destinations.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claim.</param>
        /// <param name="value">The value associated with the claim.</param>
        /// <param name="destinations">The destinations associated with the claim.</param>
        public static ClaimsIdentity AddClaim(
            [NotNull] this ClaimsIdentity identity,
            [NotNull] string type, [NotNull] string value,
            [NotNull] params string[] destinations)
            // Note: guarding the destinations parameter against null values
            // is not necessary as AsEnumerable() doesn't throw on null values.
            => identity.AddClaim(type, value, destinations.AsEnumerable());

        /// <summary>
        /// Gets the claim value corresponding to the given type.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claim.</param>
        /// <returns>The claim value.</returns>
        public static string GetClaim([NotNull] this ClaimsIdentity identity, [NotNull] string type)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The claim type cannot be null or empty.", nameof(type));
            }

            return identity.FindFirst(type)?.Value;
        }

        /// <summary>
        /// Gets the claim value corresponding to the given type.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="type">The type associated with the claim.</param>
        /// <returns>The claim value.</returns>
        public static string GetClaim([NotNull] this ClaimsPrincipal principal, [NotNull] string type)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The claim type cannot be null or empty.", nameof(type));
            }

            return principal.FindFirst(type)?.Value;
        }

        /// <summary>
        /// Gets the claim values corresponding to the given type.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claims.</param>
        /// <returns>The claim values.</returns>
        public static ImmutableHashSet<string> GetClaims([NotNull] this ClaimsIdentity identity, [NotNull] string type)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The claim type cannot be null or empty.", nameof(type));
            }

            return ImmutableHashSet.CreateRange(StringComparer.Ordinal, identity.FindAll(type).Select(claim => claim.Value));
        }

        /// <summary>
        /// Gets the claim values corresponding to the given type.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="type">The type associated with the claims.</param>
        /// <returns>The claim values.</returns>
        public static ImmutableHashSet<string> GetClaims([NotNull] this ClaimsPrincipal principal, [NotNull] string type)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The claim type cannot be null or empty.", nameof(type));
            }

            return ImmutableHashSet.CreateRange(StringComparer.Ordinal, principal.FindAll(type).Select(claim => claim.Value));
        }

        /// <summary>
        /// Removes all the claims corresponding to the given type.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claims.</param>
        /// <returns>The claims identity.</returns>
        public static ClaimsIdentity RemoveClaims([NotNull] this ClaimsIdentity identity, [NotNull] string type)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The claim type cannot be null or empty.", nameof(type));
            }

            foreach (var claim in identity.FindAll(type).ToList())
            {
                identity.RemoveClaim(claim);
            }

            return identity;
        }

        /// <summary>
        /// Removes all the claims corresponding to the given type.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="type">The type associated with the claims.</param>
        /// <returns>The claims identity.</returns>
        public static ClaimsPrincipal RemoveClaims([NotNull] this ClaimsPrincipal principal, [NotNull] string type)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The claim type cannot be null or empty.", nameof(type));
            }

            foreach (var identity in principal.Identities)
            {
                foreach (var claim in identity.FindAll(type).ToList())
                {
                    identity.RemoveClaim(claim);
                }
            }

            return principal;
        }

        /// <summary>
        /// Sets the claim value corresponding to the given type.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claims.</param>
        /// <param name="value">The claim value.</param>
        /// <returns>The claims identity.</returns>
        public static ClaimsIdentity SetClaims(
            [NotNull] this ClaimsIdentity identity,
            [NotNull] string type, [CanBeNull] string value)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The claim type cannot be null or empty.", nameof(type));
            }

            identity.RemoveClaims(type);

            if (!string.IsNullOrEmpty(value))
            {
                identity.AddClaim(type, value);
            }

            return identity;
        }

        /// <summary>
        /// Sets the claim value corresponding to the given type.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="type">The type associated with the claims.</param>
        /// <param name="value">The claim value.</param>
        /// <returns>The claims identity.</returns>
        public static ClaimsPrincipal SetClaim(
            [NotNull] this ClaimsPrincipal principal,
            [NotNull] string type, [CanBeNull] string value)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The claim type cannot be null or empty.", nameof(type));
            }

            principal.RemoveClaims(type);

            if (!string.IsNullOrEmpty(value))
            {
                ((ClaimsIdentity) principal.Identity).AddClaim(type, value);
            }

            return principal;
        }

        /// <summary>
        /// Sets the claim values corresponding to the given type.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <param name="type">The type associated with the claims.</param>
        /// <param name="values">The claim values.</param>
        /// <returns>The claims identity.</returns>
        public static ClaimsIdentity SetClaims([NotNull] this ClaimsIdentity identity,
            [NotNull] string type, [NotNull] IEnumerable<string> values)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The claim type cannot be null or empty.", nameof(type));
            }

            identity.RemoveClaims(type);

            foreach (var value in values)
            {
                identity.AddClaim(type, value);
            }

            return identity;
        }

        /// <summary>
        /// Sets the claim values corresponding to the given type.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="type">The type associated with the claims.</param>
        /// <param name="values">The claim values.</param>
        /// <returns>The claims identity.</returns>
        public static ClaimsPrincipal SetClaims([NotNull] this ClaimsPrincipal principal,
            [NotNull] string type, [NotNull] IEnumerable<string> values)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The claim type cannot be null or empty.", nameof(type));
            }

            principal.RemoveClaims(type);

            foreach (var value in values)
            {
                ((ClaimsIdentity) principal.Identity).AddClaim(type, value);
            }

            return principal;
        }

        /// <summary>
        /// Gets the creation date stored in the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The creation date or <c>null</c> if the claim cannot be found.</returns>
        public static DateTimeOffset? GetCreationDate([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            var claim = principal.FindFirst(Claims.IssuedAt);
            if (claim == null)
            {
                return null;
            }

            if (!long.TryParse(claim.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
            {
                return null;
            }

            return DateTimeOffset.FromUnixTimeSeconds(value);
        }

        /// <summary>
        /// Gets the expiration date stored in the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The expiration date or <c>null</c> if the claim cannot be found.</returns>
        public static DateTimeOffset? GetExpirationDate([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            var claim = principal.FindFirst(Claims.ExpiresAt);
            if (claim == null)
            {
                return null;
            }

            if (!long.TryParse(claim.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
            {
                return null;
            }

            return DateTimeOffset.FromUnixTimeSeconds(value);
        }

        /// <summary>
        /// Gets the audiences list stored in the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The audiences list or an empty set if the claims cannot be found.</returns>
        public static ImmutableHashSet<string> GetAudiences([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return ImmutableHashSet.CreateRange(StringComparer.Ordinal, principal.GetClaims(Claims.Audience));
        }

        /// <summary>
        /// Gets the presenters list stored in the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The presenters list or an empty set if the claims cannot be found.</returns>
        public static ImmutableHashSet<string> GetPresenters([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return ImmutableHashSet.CreateRange(StringComparer.Ordinal, principal.GetClaims(Claims.Private.Presenters));
        }

        /// <summary>
        /// Gets the resources list stored in the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The resources list or an empty set if the claims cannot be found.</returns>
        public static ImmutableHashSet<string> GetResources([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return ImmutableHashSet.CreateRange(StringComparer.Ordinal, principal.GetClaims(Claims.Private.Resources));
        }

        /// <summary>
        /// Gets the scopes list stored in the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The scopes list or an empty set if the claim cannot be found.</returns>
        public static ImmutableHashSet<string> GetScopes([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return ImmutableHashSet.CreateRange(StringComparer.Ordinal, principal.GetClaims(Claims.Private.Scopes));
        }

        /// <summary>
        /// Gets the access token lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The access token lifetime or <c>null</c> if the claim cannot be found.</returns>

        public static TimeSpan? GetAccessTokenLifetime([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            var value = principal.GetClaim(Claims.Private.AccessTokenLifetime);
            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            if (double.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out double result))
            {
                return TimeSpan.FromSeconds(result);
            }

            return null;
        }

        /// <summary>
        /// Gets the authorization code lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The authorization code lifetime or <c>null</c> if the claim cannot be found.</returns>

        public static TimeSpan? GetAuthorizationCodeLifetime([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            var value = principal.GetClaim(Claims.Private.AuthorizationCodeLifetime);
            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            if (double.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out double result))
            {
                return TimeSpan.FromSeconds(result);
            }

            return null;
        }

        /// <summary>
        /// Gets the device code lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The device code lifetime or <c>null</c> if the claim cannot be found.</returns>

        public static TimeSpan? GetDeviceCodeLifetime([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            var value = principal.GetClaim(Claims.Private.DeviceCodeLifetime);
            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            if (double.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out double result))
            {
                return TimeSpan.FromSeconds(result);
            }

            return null;
        }

        /// <summary>
        /// Gets the identity token lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The identity token lifetime or <c>null</c> if the claim cannot be found.</returns>

        public static TimeSpan? GetIdentityTokenLifetime([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            var value = principal.GetClaim(Claims.Private.IdentityTokenLifetime);
            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            if (double.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out double result))
            {
                return TimeSpan.FromSeconds(result);
            }

            return null;
        }

        /// <summary>
        /// Gets the refresh token lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The refresh token lifetime or <c>null</c> if the claim cannot be found.</returns>

        public static TimeSpan? GetRefreshTokenLifetime([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            var value = principal.GetClaim(Claims.Private.RefreshTokenLifetime);
            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            if (double.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out double result))
            {
                return TimeSpan.FromSeconds(result);
            }

            return null;
        }

        /// <summary>
        /// Gets the user code lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The user code lifetime or <c>null</c> if the claim cannot be found.</returns>

        public static TimeSpan? GetUserCodeLifetime([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            var value = principal.GetClaim(Claims.Private.UserCodeLifetime);
            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            if (double.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out double result))
            {
                return TimeSpan.FromSeconds(result);
            }

            return null;
        }

        /// <summary>
        /// Gets the internal authorization identifier associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The unique identifier or <c>null</c> if the claim cannot be found.</returns>
        public static string GetInternalAuthorizationId([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.GetClaim(Claims.Private.AuthorizationId);
        }

        /// <summary>
        /// Gets the internal token identifier associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The unique identifier or <c>null</c> if the claim cannot be found.</returns>
        public static string GetInternalTokenId([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.GetClaim(Claims.Private.TokenId);
        }

        /// <summary>
        /// Gets the token usage associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns>The token usage or <c>null</c> if the claim cannot be found.</returns>
        public static string GetTokenUsage([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.GetClaim(Claims.Private.TokenUsage);
        }

        /// <summary>
        /// Gets a boolean value indicating whether the
        /// claims principal corresponds to an access token.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns><c>true</c> if the principal corresponds to an access token.</returns>
        public static bool IsAccessToken([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return string.Equals(principal.GetTokenUsage(), TokenUsages.AccessToken, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Gets a boolean value indicating whether the
        /// claims principal corresponds to an access token.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns><c>true</c> if the principal corresponds to an authorization code.</returns>
        public static bool IsAuthorizationCode([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return string.Equals(principal.GetTokenUsage(), TokenUsages.AuthorizationCode, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Gets a boolean value indicating whether the
        /// claims principal corresponds to an identity token.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns><c>true</c> if the principal corresponds to an identity token.</returns>
        public static bool IsIdentityToken([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return string.Equals(principal.GetTokenUsage(), TokenUsages.IdToken, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Gets a boolean value indicating whether the
        /// claims principal corresponds to a refresh token.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns><c>true</c> if the principal corresponds to a refresh token.</returns>
        public static bool IsRefreshToken([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return string.Equals(principal.GetTokenUsage(), TokenUsages.RefreshToken, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the claims principal contains at least one audience.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns><c>true</c> if the principal contains at least one audience.</returns>
        public static bool HasAudience([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.FindAll(Claims.Audience).Any();
        }

        /// <summary>
        /// Determines whether the claims principal contains the given audience.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="audience">The audience.</param>
        /// <returns><c>true</c> if the principal contains the given audience.</returns>
        public static bool HasAudience([NotNull] this ClaimsPrincipal principal, [NotNull] string audience)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(audience))
            {
                throw new ArgumentException("The audience cannot be null or empty.", nameof(audience));
            }

            return principal.GetAudiences().Contains(audience);
        }

        /// <summary>
        /// Determines whether the claims principal contains at least one presenter.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns><c>true</c> if the principal contains at least one presenter.</returns>
        public static bool HasPresenter([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.FindAll(Claims.Private.Presenters).Any();
        }

        /// <summary>
        /// Determines whether the claims principal contains the given presenter.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="presenter">The presenter.</param>
        /// <returns><c>true</c> if the principal contains the given presenter.</returns>
        public static bool HasPresenter([NotNull] this ClaimsPrincipal principal, [NotNull] string presenter)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(presenter))
            {
                throw new ArgumentException("The presenter cannot be null or empty.", nameof(presenter));
            }

            return principal.GetPresenters().Contains(presenter);
        }

        /// <summary>
        /// Determines whether the claims principal contains at least one resource.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns><c>true</c> if the principal contains at least one resource.</returns>
        public static bool HasResource([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.FindAll(Claims.Private.Resources).Any();
        }

        /// <summary>
        /// Determines whether the claims principal contains the given resource.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="resource">The resource.</param>
        /// <returns><c>true</c> if the principal contains the given resource.</returns>
        public static bool HasResource([NotNull] this ClaimsPrincipal principal, [NotNull] string resource)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentException("The resource cannot be null or empty.", nameof(resource));
            }

            return principal.GetResources().Contains(resource);
        }

        /// <summary>
        /// Determines whether the claims principal contains at least one scope.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <returns><c>true</c> if the principal contains at least one scope.</returns>
        public static bool HasScope([NotNull] this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.FindAll(Claims.Private.Scopes).Any();
        }

        /// <summary>
        /// Determines whether the claims principal contains the given scope.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="scope">The scope.</param>
        /// <returns><c>true</c> if the principal contains the given scope.</returns>
        public static bool HasScope([NotNull] this ClaimsPrincipal principal, [NotNull] string scope)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (string.IsNullOrEmpty(scope))
            {
                throw new ArgumentException("The scope cannot be null or empty.", nameof(scope));
            }

            return principal.GetScopes().Contains(scope);
        }

        /// <summary>
        /// Sets the creation date in the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="date">The creation date</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetCreationDate([NotNull] this ClaimsPrincipal principal, [CanBeNull] DateTimeOffset? date)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            principal.RemoveClaims(Claims.IssuedAt);

            if (date.HasValue)
            {
                var value = date?.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
                var claim = new Claim(Claims.IssuedAt, value, ClaimValueTypes.Integer64);
                ((ClaimsIdentity) principal.Identity).AddClaim(claim);
            }

            return principal;
        }

        /// <summary>
        /// Sets the expiration date in the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="date">The expiration date</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetExpirationDate([NotNull] this ClaimsPrincipal principal, [CanBeNull] DateTimeOffset? date)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            principal.RemoveClaims(Claims.ExpiresAt);

            if (date.HasValue)
            {
                var value = date?.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
                var claim = new Claim(Claims.ExpiresAt, value, ClaimValueTypes.Integer64);
                ((ClaimsIdentity) principal.Identity).AddClaim(claim);
            }

            return principal;
        }

        /// <summary>
        /// Sets the audiences list in the claims principal.
        /// Note: this method automatically excludes duplicate audiences.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="audiences">The audiences to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetAudiences(
            [NotNull] this ClaimsPrincipal principal,
            [CanBeNull] IEnumerable<string> audiences)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.SetClaims(Claims.Audience, audiences.Distinct(StringComparer.Ordinal));
        }

        /// <summary>
        /// Sets the audiences list in the claims principal.
        /// Note: this method automatically excludes duplicate audiences.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="audiences">The audiences to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetAudiences(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] params string[] audiences)
            // Note: guarding the audiences parameter against null values
            // is not necessary as AsEnumerable() doesn't throw on null values.
            => principal.SetAudiences(audiences.AsEnumerable());

        /// <summary>
        /// Sets the presenters list in the claims principal.
        /// Note: this method automatically excludes duplicate presenters.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="presenters">The presenters to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetPresenters(
            [NotNull] this ClaimsPrincipal principal,
            [CanBeNull] IEnumerable<string> presenters)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.SetClaims(Claims.Private.Presenters, presenters.Distinct(StringComparer.Ordinal));
        }

        /// <summary>
        /// Sets the presenters list in the claims principal.
        /// Note: this method automatically excludes duplicate presenters.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="presenters">The presenters to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetPresenters(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] params string[] presenters)
            // Note: guarding the presenters parameter against null values
            // is not necessary as AsEnumerable() doesn't throw on null values.
            => principal.SetPresenters(presenters.AsEnumerable());

        /// <summary>
        /// Sets the resources list in the claims principal.
        /// Note: this method automatically excludes duplicate resources.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="resources">The resources to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetResources(
            [NotNull] this ClaimsPrincipal principal,
            [CanBeNull] IEnumerable<string> resources)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.SetClaims(Claims.Private.Resources, resources.Distinct(StringComparer.Ordinal));
        }

        /// <summary>
        /// Sets the resources list in the claims principal.
        /// Note: this method automatically excludes duplicate resources.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="resources">The resources to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetResources(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] params string[] resources)
            // Note: guarding the resources parameter against null values
            // is not necessary as AsEnumerable() doesn't throw on null values.
            => principal.SetResources(resources.AsEnumerable());

        /// <summary>
        /// Sets the scopes list in the claims principal.
        /// Note: this method automatically excludes duplicate scopes.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="scopes">The scopes to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetScopes(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] IEnumerable<string> scopes)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.SetClaims(Claims.Private.Scopes, scopes.Distinct(StringComparer.Ordinal));
        }

        /// <summary>
        /// Sets the scopes list in the claims principal.
        /// Note: this method automatically excludes duplicate scopes.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="scopes">The scopes to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetScopes(
            [NotNull] this ClaimsPrincipal principal, [CanBeNull] params string[] scopes)
            // Note: guarding the scopes parameter against null values
            // is not necessary as AsEnumerable() doesn't throw on null values.
            => principal.SetScopes(scopes.AsEnumerable());

        /// <summary>
        /// Sets the access token lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="lifetime">The access token lifetime to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetAccessTokenLifetime([NotNull] this ClaimsPrincipal principal, TimeSpan? lifetime)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.SetClaim(Claims.Private.AccessTokenLifetime, lifetime?.TotalSeconds.ToString(CultureInfo.InvariantCulture));
        }

        /// <summary>
        /// Sets the authorization code lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="lifetime">The authorization code lifetime to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetAuthorizationCodeLifetime([NotNull] this ClaimsPrincipal principal, TimeSpan? lifetime)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.SetClaim(Claims.Private.AuthorizationCodeLifetime, lifetime?.TotalSeconds.ToString(CultureInfo.InvariantCulture));
        }

        /// <summary>
        /// Sets the device code lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="lifetime">The device code lifetime to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetDeviceCodeLifetime([NotNull] this ClaimsPrincipal principal, TimeSpan? lifetime)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.SetClaim(Claims.Private.DeviceCodeLifetime, lifetime?.TotalSeconds.ToString(CultureInfo.InvariantCulture));
        }

        /// <summary>
        /// Sets the identity token lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="lifetime">The identity token lifetime to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetIdentityTokenLifetime([NotNull] this ClaimsPrincipal principal, TimeSpan? lifetime)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.SetClaim(Claims.Private.IdentityTokenLifetime, lifetime?.TotalSeconds.ToString(CultureInfo.InvariantCulture));
        }

        /// <summary>
        /// Sets the refresh token lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="lifetime">The refresh token lifetime to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetRefreshTokenLifetime([NotNull] this ClaimsPrincipal principal, TimeSpan? lifetime)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.SetClaim(Claims.Private.RefreshTokenLifetime, lifetime?.TotalSeconds.ToString(CultureInfo.InvariantCulture));
        }

        /// <summary>
        /// Sets the user code lifetime associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="lifetime">The user code lifetime to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetUserCodeLifetime([NotNull] this ClaimsPrincipal principal, TimeSpan? lifetime)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.SetClaim(Claims.Private.UserCodeLifetime, lifetime?.TotalSeconds.ToString(CultureInfo.InvariantCulture));
        }

        /// <summary>
        /// Sets the internal authorization identifier associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="identifier">The unique identifier to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetInternalAuthorizationId([NotNull] this ClaimsPrincipal principal, string identifier)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.SetClaim(Claims.Private.AuthorizationId, identifier);
        }

        /// <summary>
        /// Sets the internal token identifier associated with the claims principal.
        /// </summary>
        /// <param name="principal">The claims principal.</param>
        /// <param name="identifier">The unique identifier to store.</param>
        /// <returns>The claims principal.</returns>
        public static ClaimsPrincipal SetInternalTokenId([NotNull] this ClaimsPrincipal principal, string identifier)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.SetClaim(Claims.Private.TokenId, identifier);
        }

        private static IEnumerable<string> GetValues(string source, char[] separators)
        {
            Debug.Assert(!string.IsNullOrEmpty(source), "The source string shouldn't be null or empty.");
            Debug.Assert(separators?.Length != 0, "The separators collection shouldn't be null or empty.");

            foreach (var element in new StringTokenizer(source, separators))
            {
                var segment = Trim(element, separators);
                if (segment.Length == 0)
                {
                    continue;
                }

                yield return segment.Value;
            }

            yield break;
        }

        private static bool HasValue(string source, string value, char[] separators)
        {
            Debug.Assert(!string.IsNullOrEmpty(source), "The source string shouldn't be null or empty.");
            Debug.Assert(!string.IsNullOrEmpty(value), "The value string shouldn't be null or empty.");
            Debug.Assert(separators?.Length != 0, "The separators collection shouldn't be null or empty.");

            foreach (var element in new StringTokenizer(source, separators))
            {
                var segment = Trim(element, separators);
                if (segment.Length == 0)
                {
                    continue;
                }

                if (segment.Equals(value, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }

        private static StringSegment TrimStart(StringSegment segment, char[] separators)
        {
            Debug.Assert(separators?.Length != 0, "The separators collection shouldn't be null or empty.");

            var index = segment.Offset;

            while (index < segment.Offset + segment.Length)
            {
                if (!IsSeparator(segment.Buffer[index], separators))
                {
                    break;
                }

                index++;
            }

            return new StringSegment(segment.Buffer, index, segment.Offset + segment.Length - index);
        }

        private static StringSegment TrimEnd(StringSegment segment, char[] separators)
        {
            Debug.Assert(separators?.Length != 0, "The separators collection shouldn't be null or empty.");

            var index = segment.Offset + segment.Length - 1;

            while (index >= segment.Offset)
            {
                if (!IsSeparator(segment.Buffer[index], separators))
                {
                    break;
                }

                index--;
            }

            return new StringSegment(segment.Buffer, segment.Offset, index - segment.Offset + 1);
        }

        private static StringSegment Trim(StringSegment segment, char[] separators)
        {
            Debug.Assert(separators?.Length != 0, "The separators collection shouldn't be null or empty.");

            return TrimEnd(TrimStart(segment, separators), separators);
        }

        private static bool IsSeparator(char character, char[] separators)
        {
            Debug.Assert(separators?.Length != 0, "The separators collection shouldn't be null or empty.");

            for (var index = 0; index < separators.Length; index++)
            {
                if (character == separators[index])
                {
                    return true;
                }
            }

            return false;
        }
    }
}
