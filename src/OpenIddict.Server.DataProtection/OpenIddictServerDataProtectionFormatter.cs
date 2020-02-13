/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using JetBrains.Annotations;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Properties = OpenIddict.Server.DataProtection.OpenIddictServerDataProtectionConstants.Properties;

namespace OpenIddict.Server.DataProtection
{
    public class OpenIddictServerDataProtectionFormatter : IOpenIddictServerDataProtectionFormatter
    {
        public ClaimsPrincipal ReadToken([NotNull] BinaryReader reader)
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            var (principal, properties) = Read(reader, version: 5);
            if (principal == null)
            {
                return null;
            }

            // Tokens serialized using the ASP.NET Core Data Protection stack are compound
            // of both claims and special authentication properties. To ensure existing tokens
            // can be reused, well-known properties are manually mapped to their claims equivalents.

            return principal
                .SetAudiences(GetArrayProperty(properties, Properties.Audiences))
                .SetCreationDate(GetDateProperty(properties, Properties.Issued))
                .SetExpirationDate(GetDateProperty(properties, Properties.Expires))
                .SetPresenters(GetArrayProperty(properties, Properties.Presenters))
                .SetResources(GetArrayProperty(properties, Properties.Resources))
                .SetScopes(GetArrayProperty(properties, Properties.Scopes))

                .SetClaim(Claims.Private.AccessTokenLifetime, GetProperty(properties, Properties.AccessTokenLifetime))
                .SetClaim(Claims.Private.AuthorizationCodeLifetime, GetProperty(properties, Properties.AuthorizationCodeLifetime))
                .SetClaim(Claims.Private.AuthorizationId, GetProperty(properties, Properties.InternalAuthorizationId))
                .SetClaim(Claims.Private.CodeChallenge, GetProperty(properties, Properties.CodeChallenge))
                .SetClaim(Claims.Private.CodeChallengeMethod, GetProperty(properties, Properties.CodeChallengeMethod))
                .SetClaim(Claims.Private.IdentityTokenLifetime, GetProperty(properties, Properties.IdentityTokenLifetime))
                .SetClaim(Claims.Private.Nonce, GetProperty(properties, Properties.Nonce))
                .SetClaim(Claims.Private.RedirectUri, GetProperty(properties, Properties.OriginalRedirectUri))
                .SetClaim(Claims.Private.RefreshTokenLifetime, GetProperty(properties, Properties.RefreshTokenLifetime))
                .SetClaim(Claims.Private.TokenId, GetProperty(properties, Properties.InternalTokenId));

            static (ClaimsPrincipal principal, ImmutableDictionary<string, string> properties) Read(BinaryReader reader, int version)
            {
                if (version != reader.ReadInt32())
                {
                    return (null, ImmutableDictionary.Create<string, string>());
                }

                // Read the authentication scheme associated to the ticket.
                _ = reader.ReadString();

                // Read the number of identities stored in the serialized payload.
                var count = reader.ReadInt32();
                if (count < 0)
                {
                    return (null, ImmutableDictionary.Create<string, string>());
                }

                var identities = new ClaimsIdentity[count];
                for (var index = 0; index != count; ++index)
                {
                    identities[index] = ReadIdentity(reader);
                }

                var properties = ReadProperties(reader, version);

                return (new ClaimsPrincipal(identities), properties);
            }

            static ClaimsIdentity ReadIdentity(BinaryReader reader)
            {
                var identity = new ClaimsIdentity(
                    authenticationType: reader.ReadString(),
                    nameType: ReadWithDefault(reader, ClaimsIdentity.DefaultNameClaimType),
                    roleType: ReadWithDefault(reader, ClaimsIdentity.DefaultRoleClaimType));

                // Read the number of claims contained in the serialized identity.
                var count = reader.ReadInt32();

                for (int index = 0; index != count; ++index)
                {
                    var claim = ReadClaim(reader, identity);

                    identity.AddClaim(claim);
                }

                // Determine whether the identity has a bootstrap context attached.
                if (reader.ReadBoolean())
                {
                    identity.BootstrapContext = reader.ReadString();
                }

                // Determine whether the identity has an actor identity attached.
                if (reader.ReadBoolean())
                {
                    identity.Actor = ReadIdentity(reader);
                }

                return identity;
            }

            static Claim ReadClaim(BinaryReader reader, ClaimsIdentity identity)
            {
                var type = ReadWithDefault(reader, identity.NameClaimType);
                var value = reader.ReadString();
                var valueType = ReadWithDefault(reader, ClaimValueTypes.String);
                var issuer = ReadWithDefault(reader, ClaimsIdentity.DefaultIssuer);
                var originalIssuer = ReadWithDefault(reader, issuer);

                var claim = new Claim(type, value, valueType, issuer, originalIssuer, identity);

                // Read the number of properties stored in the claim.
                var count = reader.ReadInt32();

                for (var index = 0; index != count; ++index)
                {
                    var key = reader.ReadString();
                    var propertyValue = reader.ReadString();

                    claim.Properties.Add(key, propertyValue);
                }

                return claim;
            }

            static ImmutableDictionary<string, string> ReadProperties(BinaryReader reader, int version)
            {
                if (version != reader.ReadInt32())
                {
                    return ImmutableDictionary.Create<string, string>();
                }

                var properties = ImmutableDictionary.CreateBuilder<string, string>(StringComparer.Ordinal);
                var count = reader.ReadInt32();
                for (var index = 0; index != count; ++index)
                {
                    properties.Add(reader.ReadString(), reader.ReadString());
                }

                return properties.ToImmutable();
            }

            static string ReadWithDefault(BinaryReader reader, string defaultValue)
            {
                var value = reader.ReadString();

                if (string.Equals(value, "\0", StringComparison.Ordinal))
                {
                    return defaultValue;
                }

                return value;
            }

            static string GetProperty(IReadOnlyDictionary<string, string> properties, string name)
                => properties.TryGetValue(name, out var value) ? value : null;

            static ImmutableArray<string> GetArrayProperty(IReadOnlyDictionary<string, string> properties, string name)
                => properties.TryGetValue(name, out var value) ?
                JsonSerializer.Deserialize<ImmutableArray<string>>(value) : ImmutableArray.Create<string>();

            static DateTimeOffset? GetDateProperty(IReadOnlyDictionary<string, string> properties, string name)
                => properties.TryGetValue(name, out var value) ? (DateTimeOffset?)
                DateTimeOffset.ParseExact(value, "r", CultureInfo.InvariantCulture) : null;
        }

        public void WriteToken([NotNull] BinaryWriter writer, [NotNull] ClaimsPrincipal principal)
        {
            if (writer == null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            var properties = new Dictionary<string, string>();

            // Unlike ASP.NET Core Data Protection-based tokens, tokens serialized using the new format
            // can't include authentication properties. To ensure tokens can be used with previous versions
            // of OpenIddict (1.x/2.x), well-known claims are manually mapped to their properties equivalents.

            SetProperty(properties, Properties.Issued, principal.GetCreationDate()?.ToString("r", CultureInfo.InvariantCulture));
            SetProperty(properties, Properties.Expires, principal.GetExpirationDate()?.ToString("r", CultureInfo.InvariantCulture));

            SetProperty(properties, Properties.AccessTokenLifetime, principal.GetClaim(Claims.Private.AccessTokenLifetime));
            SetProperty(properties, Properties.AuthorizationCodeLifetime, principal.GetClaim(Claims.Private.AuthorizationCodeLifetime));
            SetProperty(properties, Properties.IdentityTokenLifetime, principal.GetClaim(Claims.Private.IdentityTokenLifetime));
            SetProperty(properties, Properties.RefreshTokenLifetime, principal.GetClaim(Claims.Private.RefreshTokenLifetime));

            SetProperty(properties, Properties.CodeChallenge, principal.GetClaim(Claims.Private.CodeChallenge));
            SetProperty(properties, Properties.CodeChallengeMethod, principal.GetClaim(Claims.Private.CodeChallengeMethod));

            SetProperty(properties, Properties.InternalAuthorizationId, principal.GetInternalAuthorizationId());
            SetProperty(properties, Properties.InternalTokenId, principal.GetInternalTokenId());

            SetProperty(properties, Properties.Nonce, principal.GetClaim(Claims.Private.Nonce));
            SetProperty(properties, Properties.OriginalRedirectUri, principal.GetClaim(Claims.Private.RedirectUri));

            SetArrayProperty(properties, Properties.Audiences, principal.GetAudiences());
            SetArrayProperty(properties, Properties.Presenters, principal.GetPresenters());
            SetArrayProperty(properties, Properties.Resources, principal.GetResources());
            SetArrayProperty(properties, Properties.Scopes, principal.GetScopes());

            // Copy the principal and exclude the claim that were mapped to authentication properties.
            principal = principal.Clone(claim => claim.Type switch
            {
                Claims.Audience  => false,
                Claims.ExpiresAt => false,
                Claims.IssuedAt  => false,

                Claims.Private.AccessTokenLifetime       => false,
                Claims.Private.AuthorizationCodeLifetime => false,
                Claims.Private.AuthorizationId           => false,
                Claims.Private.CodeChallenge             => false,
                Claims.Private.CodeChallengeMethod       => false,
                Claims.Private.IdentityTokenLifetime     => false,
                Claims.Private.Nonce                     => false,
                Claims.Private.Presenter                 => false,
                Claims.Private.RedirectUri               => false,
                Claims.Private.RefreshTokenLifetime      => false,
                Claims.Private.Resource                  => false,
                Claims.Private.Scope                     => false,
                Claims.Private.TokenId                   => false,

                _ => true
            });

            Write(writer, version: 5, principal.Identity.AuthenticationType, principal, properties);
            writer.Flush();

            // Note: the following local methods closely matches the logic used by ASP.NET Core's
            // authentication stack and MUST NOT be modified to ensure tokens encrypted using
            // the OpenID Connect server middleware can be read by OpenIddict (and vice-versa).

            static void Write(BinaryWriter writer, int version, string scheme,
                ClaimsPrincipal principal, IReadOnlyDictionary<string, string> properties)
            {
                writer.Write(version);
                writer.Write(scheme ?? string.Empty);

                // Write the number of identities contained in the principal.
                writer.Write(principal.Identities.Count());

                foreach (var identity in principal.Identities)
                {
                    WriteIdentity(writer, identity);
                }

                WriteProperties(writer, version, properties);
            }

            static void WriteIdentity(BinaryWriter writer, ClaimsIdentity identity)
            {
                writer.Write(identity.AuthenticationType ?? string.Empty);
                WriteWithDefault(writer, identity.NameClaimType, ClaimsIdentity.DefaultNameClaimType);
                WriteWithDefault(writer, identity.RoleClaimType, ClaimsIdentity.DefaultRoleClaimType);

                // Write the number of claims contained in the identity.
                writer.Write(identity.Claims.Count());

                foreach (var claim in identity.Claims)
                {
                    WriteClaim(writer, claim);
                }

                var bootstrap = identity.BootstrapContext as string;
                if (!string.IsNullOrEmpty(bootstrap))
                {
                    writer.Write(true);
                    writer.Write(bootstrap);
                }

                else
                {
                    writer.Write(false);
                }

                if (identity.Actor != null)
                {
                    writer.Write(true);
                    WriteIdentity(writer, identity.Actor);
                }

                else
                {
                    writer.Write(false);
                }
            }

            static void WriteClaim(BinaryWriter writer, Claim claim)
            {
                if (writer == null)
                {
                    throw new ArgumentNullException(nameof(writer));
                }

                if (claim == null)
                {
                    throw new ArgumentNullException(nameof(claim));
                }

                WriteWithDefault(writer, claim.Type, claim.Subject?.NameClaimType ?? ClaimsIdentity.DefaultNameClaimType);
                writer.Write(claim.Value);
                WriteWithDefault(writer, claim.ValueType, ClaimValueTypes.String);
                WriteWithDefault(writer, claim.Issuer, ClaimsIdentity.DefaultIssuer);
                WriteWithDefault(writer, claim.OriginalIssuer, claim.Issuer);

                // Write the number of properties contained in the claim.
                writer.Write(claim.Properties.Count);

                foreach (var property in claim.Properties)
                {
                    writer.Write(property.Key ?? string.Empty);
                    writer.Write(property.Value ?? string.Empty);
                }
            }

            static void WriteProperties(BinaryWriter writer, int version, IReadOnlyDictionary<string, string> properties)
            {
                writer.Write(version);
                writer.Write(properties.Count);

                foreach (var property in properties)
                {
                    writer.Write(property.Key ?? string.Empty);
                    writer.Write(property.Value ?? string.Empty);
                }
            }

            static void WriteWithDefault(BinaryWriter writer, string value, string defaultValue)
                => writer.Write(string.Equals(value, defaultValue, StringComparison.Ordinal) ? "\0" : value);

            static void SetProperty(IDictionary<string, string> properties, string name, string value)
            {
                if (string.IsNullOrEmpty(value))
                {
                    properties.Remove(name);
                }

                else
                {
                    properties[name] = value;
                }
            }

            static void SetArrayProperty(IDictionary<string, string> properties, string name, ImmutableArray<string> values)
            {
                if (values.IsDefaultOrEmpty)
                {
                    properties.Remove(name);
                }

                else
                {
                    properties[name] = JsonSerializer.Serialize(values, new JsonSerializerOptions
                    {
                        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                        WriteIndented = false
                    });
                }
            }
        }
    }
}
