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
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.DataProtection.OpenIddictServerDataProtectionHandlerFilters;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers.Serialization;
using Properties = OpenIddict.Server.DataProtection.OpenIddictServerDataProtectionConstants.Properties;

namespace OpenIddict.Server.DataProtection
{
    public static partial class OpenIddictServerDataProtectionHandlers
    {
        public static class Serialization
        {
            public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Access token serialization:
                 */
                AttachAccessTokenSerializationProtector.Descriptor,
                SerializeDataProtectionToken<SerializeAccessTokenContext>.Descriptor,

                /*
                 * Authorization code serialization:
                 */
                AttachAuthorizationCodeSerializationProtector.Descriptor,
                SerializeDataProtectionToken<SerializeAuthorizationCodeContext>.Descriptor,

                /*
                 * Refresh token serialization:
                 */
                AttachRefreshTokenSerializationProtector.Descriptor,
                SerializeDataProtectionToken<SerializeRefreshTokenContext>.Descriptor,

                /*
                 * Access token deserialization:
                 */
                AttachAccessTokenDeserializationProtector.Descriptor,
                DeserializeDataProtectionToken<DeserializeAccessTokenContext>.Descriptor,

                /*
                 * Authorization code deserialization:
                 */
                AttachAuthorizationCodeDeserializationProtector.Descriptor,
                DeserializeDataProtectionToken<DeserializeAuthorizationCodeContext>.Descriptor,

                /*
                 * Refresh token deserialization:
                 */
                AttachRefreshTokenDeserializationProtector.Descriptor,
                DeserializeDataProtectionToken<DeserializeRefreshTokenContext>.Descriptor);

            /// <summary>
            /// Contains the logic responsible of generating a Data Protection token.
            /// </summary>
            public class SerializeDataProtectionToken<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseSerializingContext
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                        .AddFilter<RequirePreferDataProtectionFormatEnabled>()
                        .UseSingletonHandler<SerializeDataProtectionToken<TContext>>()
                        .SetOrder(SerializeJwtBearerToken<TContext>.Descriptor.Order - 5000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] TContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (!context.Properties.TryGetValue(Properties.DataProtector, out var property) ||
                       !(property is IDataProtector protector))
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .Append("No suitable data protector was found for the specified token type.")
                            .Append("This may indicate that the OpenIddict Data Protection services were not correctly registered.")
                            .ToString());
                    }

                    var properties = new Dictionary<string, string>();

                    // Unlike ASP.NET Core Data Protection-based tokens, tokens serialized using the new format
                    // can't include authentication properties. To ensure tokens can be used with previous versions
                    // of OpenIddict are issued, well-known claims are manually mapped to their properties equivalents.

                    SetProperty(properties, Properties.AccessTokenLifetime,
                        context.Principal.GetClaim(Claims.Private.AccessTokenLifetime));
                    SetProperty(properties, Properties.AuthorizationCodeLifetime,
                        context.Principal.GetClaim(Claims.Private.AuthorizationCodeLifetime));
                    SetProperty(properties, Properties.CodeChallenge,
                        context.Principal.GetClaim(Claims.Private.CodeChallenge));
                    SetProperty(properties, Properties.CodeChallengeMethod,
                        context.Principal.GetClaim(Claims.Private.CodeChallengeMethod));
                    SetProperty(properties, Properties.Expires,
                        context.Principal.GetExpirationDate()?.ToString("r", CultureInfo.InvariantCulture));
                    SetProperty(properties, Properties.IdentityTokenLifetime,
                        context.Principal.GetClaim(Claims.Private.IdentityTokenLifetime));
                    SetProperty(properties, Properties.Issued,
                        context.Principal.GetCreationDate()?.ToString("r", CultureInfo.InvariantCulture));
                    SetProperty(properties, Properties.OriginalRedirectUri,
                        context.Principal.GetClaim(Claims.Private.RedirectUri));
                    SetProperty(properties, Properties.RefreshTokenLifetime,
                        context.Principal.GetClaim(Claims.Private.RefreshTokenLifetime));

                    SetArrayProperty(properties, Properties.Audiences, context.Principal.GetAudiences());
                    SetArrayProperty(properties, Properties.Presenters, context.Principal.GetPresenters());
                    SetArrayProperty(properties, Properties.Scopes, context.Principal.GetScopes());

                    using var buffer = new MemoryStream();
                    using var writer = new BinaryWriter(buffer);

                    Write(writer, version: 5, context.Principal.Identity.AuthenticationType, context.Principal, properties);
                    writer.Flush();

                    context.Token = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));
                    context.HandleSerialization();

                    return default;

                    // Note: the following local methods closely matches the logic used by ASP.NET Core's
                    // authentication stack and MUST NOT be modified to ensure tokens encrypted using
                    // the OpenID Connect server middleware can be read by OpenIddict (and vice-versa).

                    static void Write(BinaryWriter writer, int version, string scheme,
                        ClaimsPrincipal principal, IReadOnlyDictionary<string, string> properties)
                    {
                        writer.Write(version);
                        writer.Write(scheme);

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

                    static void SetArrayProperty(IDictionary<string, string> properties, string name, IEnumerable<string> values)
                    {
                        var array = new JArray(values);
                        if (array.Count == 0)
                        {
                            properties.Remove(name);
                        }

                        else
                        {
                            properties[name] = array.ToString(Formatting.None);
                        }
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of unprotecting a Data Protection token.
            /// </summary>
            public class DeserializeDataProtectionToken<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseDeserializingContext
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                        .UseSingletonHandler<DeserializeDataProtectionToken<TContext>>()
                        .SetOrder(DeserializeJwtBearerToken<TContext>.Descriptor.Order - 5000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] TContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (!context.Properties.TryGetValue(Properties.DataProtector, out var property) ||
                       !(property is IDataProtector protector))
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .Append("No suitable data protector was found for the specified token type.")
                            .Append("This may indicate that the OpenIddict Data Protection services were not correctly registered.")
                            .ToString());
                    }

                    try
                    {
                        using var buffer = new MemoryStream(protector.Unprotect(Base64UrlEncoder.DecodeBytes(context.Token)));
                        using var reader = new BinaryReader(buffer);

                        var (principal, properties) = Read(reader, version: 5);
                        if (principal == null)
                        {
                            return default;
                        }

                        context.Principal = principal;

                        // Tokens serialized using the ASP.NET Core Data Protection stack are compound
                        // of both claims and special authentication properties. To ensure existing tokens
                        // can be reused, well-known properties are manually mapped to their claims equivalents.

                        context.Principal
                            .SetAudiences(GetArrayProperty(properties, Properties.Audiences))
                            .SetCreationDate(GetDateProperty(properties, Properties.Issued))
                            .SetExpirationDate(GetDateProperty(properties, Properties.Expires))
                            .SetPresenters(GetArrayProperty(properties, Properties.Presenters))
                            .SetScopes(GetArrayProperty(properties, Properties.Scopes))

                            .SetClaim(Claims.Private.AccessTokenLifetime, GetProperty(properties, Properties.AccessTokenLifetime))
                            .SetClaim(Claims.Private.AuthorizationCodeLifetime, GetProperty(properties, Properties.AuthorizationCodeLifetime))
                            .SetClaim(Claims.Private.CodeChallenge, GetProperty(properties, Properties.CodeChallenge))
                            .SetClaim(Claims.Private.CodeChallengeMethod, GetProperty(properties, Properties.CodeChallengeMethod))
                            .SetClaim(Claims.Private.IdentityTokenLifetime, GetProperty(properties, Properties.IdentityTokenLifetime))
                            .SetClaim(Claims.Private.RedirectUri, GetProperty(properties, Properties.OriginalRedirectUri))
                            .SetClaim(Claims.Private.RefreshTokenLifetime, GetProperty(properties, Properties.RefreshTokenLifetime))

                            // Note: since the data format relies on a data protector using different "purposes" strings
                            // per token type, the token processed at this stage is guaranteed to be of the expected type.
                            .SetClaim(Claims.Private.TokenUsage, (string) context.Properties[Properties.TokenUsage]);

                        context.HandleDeserialization();

                        return default;
                    }

                    catch (Exception exception)
                    {
                        context.Logger.LogTrace(exception, "An exception occured while deserializing a token.");

                        return default;
                    }

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

                    static IEnumerable<string> GetArrayProperty(IReadOnlyDictionary<string, string> properties, string name)
                        => properties.TryGetValue(name, out var value) ? JArray.Parse(value).Values<string>() : Enumerable.Empty<string>();

                    static DateTimeOffset? GetDateProperty(IReadOnlyDictionary<string, string> properties, string name)
                        => properties.TryGetValue(name, out var value) ? (DateTimeOffset?)
                        DateTimeOffset.ParseExact(value, "r", CultureInfo.InvariantCulture) : null;
                }
            }

            /// <summary>
            /// Contains the logic responsible of populating the data protector needed to generate an access token.
            /// </summary>
            public class AttachAccessTokenSerializationProtector : IOpenIddictServerHandler<SerializeAccessTokenContext>
            {
                private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

                public AttachAccessTokenSerializationProtector([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                    => _options = options;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<SerializeAccessTokenContext>()
                        .UseSingletonHandler<AttachAccessTokenSerializationProtector>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] SerializeAccessTokenContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Note: the protector MUST be created with the same purposes used by the
                    // OpenID Connect server middleware (aka ASOS) to guarantee compatibility.
                    var purposes = new List<string>(capacity: 4)
                    {
                        "OpenIdConnectServerHandler",
                        "AccessTokenFormat",
                        "ASOS"
                    };

                    if (context.Options.UseReferenceTokens)
                    {
                        purposes.Insert(index: 2, "UseReferenceTokens");
                    }

                    var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(purposes);
                    context.Properties[Properties.DataProtector] = protector;
                    context.Properties[Properties.TokenUsage] = TokenUsages.AccessToken;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of populating the data protector needed to generate an authorization code.
            /// </summary>
            public class AttachAuthorizationCodeSerializationProtector : IOpenIddictServerHandler<SerializeAuthorizationCodeContext>
            {
                private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

                public AttachAuthorizationCodeSerializationProtector([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                    => _options = options;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<SerializeAuthorizationCodeContext>()
                        .UseSingletonHandler<AttachAuthorizationCodeSerializationProtector>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] SerializeAuthorizationCodeContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Note: the protector MUST be created with the same purposes used by the
                    // OpenID Connect server middleware (aka ASOS) to guarantee compatibility.
                    var purposes = new List<string>(capacity: 4)
                    {
                        "OpenIdConnectServerHandler",
                        "AuthorizationCodeFormat",
                        "ASOS"
                    };

                    if (context.Options.UseReferenceTokens)
                    {
                        purposes.Insert(index: 2, "UseReferenceTokens");
                    }

                    var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(purposes);
                    context.Properties[Properties.DataProtector] = protector;
                    context.Properties[Properties.TokenUsage] = TokenUsages.AuthorizationCode;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of populating the data protector needed to generate a refresh token.
            /// </summary>
            public class AttachRefreshTokenSerializationProtector : IOpenIddictServerHandler<SerializeRefreshTokenContext>
            {
                private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

                public AttachRefreshTokenSerializationProtector([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                    => _options = options;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<SerializeRefreshTokenContext>()
                        .UseSingletonHandler<AttachRefreshTokenSerializationProtector>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] SerializeRefreshTokenContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Note: the protector MUST be created with the same purposes used by the
                    // OpenID Connect server middleware (aka ASOS) to guarantee compatibility.
                    var purposes = new List<string>(capacity: 4)
                    {
                        "OpenIdConnectServerHandler",
                        "RefreshTokenFormat",
                        "ASOS"
                    };

                    if (context.Options.UseReferenceTokens)
                    {
                        purposes.Insert(index: 2, "UseReferenceTokens");
                    }

                    var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(purposes);
                    context.Properties[Properties.DataProtector] = protector;
                    context.Properties[Properties.TokenUsage] = TokenUsages.RefreshToken;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of populating the data protector needed to unprotect an access token.
            /// </summary>
            public class AttachAccessTokenDeserializationProtector : IOpenIddictServerHandler<DeserializeAccessTokenContext>
            {
                private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

                public AttachAccessTokenDeserializationProtector([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                    => _options = options;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<DeserializeAccessTokenContext>()
                        .UseSingletonHandler<AttachAccessTokenDeserializationProtector>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] DeserializeAccessTokenContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Note: the protector MUST be created with the same purposes used by the
                    // OpenID Connect server middleware (aka ASOS) to guarantee compatibility.
                    var purposes = new List<string>(capacity: 4)
                    {
                        "OpenIdConnectServerHandler",
                        "AccessTokenFormat",
                        "ASOS"
                    };

                    if (context.Options.UseReferenceTokens)
                    {
                        purposes.Insert(index: 2, "UseReferenceTokens");
                    }

                    var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(purposes);
                    context.Properties[Properties.DataProtector] = protector;
                    context.Properties[Properties.TokenUsage] = TokenUsages.AccessToken;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of populating the data protector needed to unprotect an authorization code.
            /// </summary>
            public class AttachAuthorizationCodeDeserializationProtector : IOpenIddictServerHandler<DeserializeAuthorizationCodeContext>
            {
                private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

                public AttachAuthorizationCodeDeserializationProtector([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                    => _options = options;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<DeserializeAuthorizationCodeContext>()
                        .UseSingletonHandler<AttachAuthorizationCodeDeserializationProtector>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] DeserializeAuthorizationCodeContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Note: the protector MUST be created with the same purposes used by the
                    // OpenID Connect server middleware (aka ASOS) to guarantee compatibility.
                    var purposes = new List<string>(capacity: 4)
                    {
                        "OpenIdConnectServerHandler",
                        "AuthorizationCodeFormat",
                        "ASOS"
                    };

                    if (context.Options.UseReferenceTokens)
                    {
                        purposes.Insert(index: 2, "UseReferenceTokens");
                    }

                    var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(purposes);
                    context.Properties[Properties.DataProtector] = protector;
                    context.Properties[Properties.TokenUsage] = TokenUsages.AuthorizationCode;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of populating the data protector needed to unprotect a refresh token.
            /// </summary>
            public class AttachRefreshTokenDeserializationProtector : IOpenIddictServerHandler<DeserializeRefreshTokenContext>
            {
                private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

                public AttachRefreshTokenDeserializationProtector([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                    => _options = options;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<DeserializeRefreshTokenContext>()
                        .UseSingletonHandler<AttachRefreshTokenDeserializationProtector>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] DeserializeRefreshTokenContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Note: the protector MUST be created with the same purposes used by the
                    // OpenID Connect server middleware (aka ASOS) to guarantee compatibility.
                    var purposes = new List<string>(capacity: 4)
                    {
                        "OpenIdConnectServerHandler",
                        "RefreshTokenFormat",
                        "ASOS"
                    };

                    if (context.Options.UseReferenceTokens)
                    {
                        purposes.Insert(index: 2, "UseReferenceTokens");
                    }

                    var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(purposes);
                    context.Properties[Properties.DataProtector] = protector;
                    context.Properties[Properties.TokenUsage] = TokenUsages.RefreshToken;

                    return default;
                }
            }
        }
    }
}
