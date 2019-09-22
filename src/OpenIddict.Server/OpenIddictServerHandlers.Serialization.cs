/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server
{
    public static partial class OpenIddictServerHandlers
    {
        public static class Serialization
        {
            public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Access token serialization:
                 */
                AttachAccessTokenSerializationParameters.Descriptor,
                SerializeJwtBearerToken<SerializeAccessTokenContext>.Descriptor,

                /*
                 * Authorization code serialization:
                 */
                AttachAuthorizationCodeSerializationParameters.Descriptor,
                SerializeJwtBearerToken<SerializeAuthorizationCodeContext>.Descriptor,

                /*
                 * Identity token serialization:
                 */
                AttachIdentityTokenSerializationParameters.Descriptor,
                SerializeJwtBearerToken<SerializeIdentityTokenContext>.Descriptor,

                /*
                 * Refresh token serialization:
                 */
                AttachRefreshTokenSerializationParameters.Descriptor,
                SerializeJwtBearerToken<SerializeRefreshTokenContext>.Descriptor,

                /*
                 * Access token deserialization:
                 */
                AttachAccessTokenDeserializationParameters.Descriptor,
                DeserializeJwtBearerToken<DeserializeAccessTokenContext>.Descriptor,

                /*
                 * Authorization code deserialization:
                 */
                AttachAuthorizationCodeDeserializationParameters.Descriptor,
                DeserializeJwtBearerToken<DeserializeAuthorizationCodeContext>.Descriptor,

                /*
                 * Identity token deserialization:
                 */
                AttachIdentityTokenDeserializationParameters.Descriptor,
                DeserializeJwtBearerToken<DeserializeIdentityTokenContext>.Descriptor,

                /*
                 * Authorization code deserialization:
                 */
                AttachRefreshTokenDeserializationParameters.Descriptor,
                DeserializeJwtBearerToken<DeserializeRefreshTokenContext>.Descriptor);

            /// <summary>
            /// Contains the logic responsible of generating a JWT bearer token using IdentityModel.
            /// </summary>
            public class SerializeJwtBearerToken<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseSerializingContext
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                        .UseSingletonHandler<SerializeJwtBearerToken<TContext>>()
                        .SetOrder(int.MaxValue - 100_000)
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

                    if (string.IsNullOrEmpty(context.TokenUsage))
                    {
                        throw new InvalidOperationException("The token usage cannot be null or empty.");
                    }

                    var claims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [Claims.Private.TokenUsage] = context.TokenUsage
                    };

                    var destinations = new Dictionary<string, string[]>(StringComparer.Ordinal);
                    foreach (var group in context.Principal.Claims.GroupBy(claim => claim.Type))
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
                        claims[Claims.Private.ClaimDestinations] = destinations;
                    }

                    context.Token = context.SecurityTokenHandler.CreateToken(new SecurityTokenDescriptor
                    {
                        Subject = (ClaimsIdentity) context.Principal.Identity,
                        Claims = new ReadOnlyDictionary<string, object>(claims),
                        EncryptingCredentials = context.EncryptingCredentials,
                        Issuer = context.Issuer?.AbsoluteUri,
                        SigningCredentials = context.SigningCredentials
                    });

                    context.HandleSerialization();

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of unprotecting a JWT bearer token using IdentityModel.
            /// </summary>
            public class DeserializeJwtBearerToken<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseDeserializingContext
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                        .UseSingletonHandler<DeserializeJwtBearerToken<TContext>>()
                        .SetOrder(int.MaxValue - 100_000)
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

                    if (!context.SecurityTokenHandler.CanReadToken(context.Token))
                    {
                        context.Logger.LogTrace("The token '{Token}' was not compatible with the JWT format.", context.Token);

                        return default;
                    }

                    try
                    {
                        var result = context.SecurityTokenHandler.ValidateToken(context.Token, context.TokenValidationParameters);
                        if (result == null || !result.IsValid)
                        {
                            if (result?.Exception != null)
                            {
                                context.Logger.LogTrace(result.Exception, "The JWT token '{Token}' could not be validated.", context.Token);
                            }

                            else
                            {
                                context.Logger.LogTrace("The token '{Token}' could not be validated.", context.Token);
                            }

                            return default;
                        }

                        var assertion = ((JsonWebToken) result.SecurityToken)?.InnerToken ?? (JsonWebToken) result.SecurityToken;

                        if (!assertion.TryGetPayloadValue(Claims.Private.TokenUsage, out string usage) ||
                            !string.Equals(usage, context.TokenUsage, StringComparison.OrdinalIgnoreCase))
                        {
                            context.Logger.LogDebug("The token usage associated to the token {Token} does not match the expected type.");
                            context.HandleDeserialization();

                            return default;
                        }

                        context.Principal = new ClaimsPrincipal(result.ClaimsIdentity);

                        // Restore the claim destinations from the special oi_cl_dstn claim (represented as a dictionary/JSON object).
                        if (assertion.TryGetPayloadValue(Claims.Private.ClaimDestinations, out IDictionary<string, string[]> definitions))
                        {
                            foreach (var definition in definitions)
                            {
                                foreach (var claim in context.Principal.Claims.Where(claim => claim.Type == definition.Key))
                                {
                                    claim.SetDestinations(definition.Value);
                                }
                            }
                        }

                        context.HandleDeserialization();

                        return default;
                    }

                    catch (Exception exception)
                    {
                        context.Logger.LogDebug(exception, "An exception occured while deserializing a token.");
                        context.HandleDeserialization();

                        return default;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of populating the serialization parameters needed to generate an access token.
            /// </summary>
            public class AttachAccessTokenSerializationParameters : IOpenIddictServerHandler<SerializeAccessTokenContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<SerializeAccessTokenContext>()
                        .UseSingletonHandler<AttachAccessTokenSerializationParameters>()
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

                    if (context.Options.SigningCredentials.Count == 0)
                    {
                        throw new InvalidOperationException("No suitable signing credentials could be found.");
                    }

                    context.EncryptingCredentials = context.Options.EncryptionCredentials.FirstOrDefault(
                        credentials => credentials.Key is SymmetricSecurityKey);
                    context.SecurityTokenHandler = context.Options.AccessTokenHandler;
                    context.SigningCredentials = context.Options.SigningCredentials.FirstOrDefault(
                        credentials => credentials.Key is SymmetricSecurityKey) ?? context.Options.SigningCredentials.First();

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of populating the serialization parameters needed to generate an authorization code.
            /// </summary>
            public class AttachAuthorizationCodeSerializationParameters : IOpenIddictServerHandler<SerializeAuthorizationCodeContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<SerializeAuthorizationCodeContext>()
                        .UseSingletonHandler<AttachAuthorizationCodeSerializationParameters>()
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

                    if (context.Options.EncryptionCredentials.Count == 0)
                    {
                        throw new InvalidOperationException("No suitable encryption credentials could be found.");
                    }

                    if (context.Options.SigningCredentials.Count == 0)
                    {
                        throw new InvalidOperationException("No suitable signing credentials could be found.");
                    }

                    context.EncryptingCredentials = context.Options.EncryptionCredentials[0];
                    context.SecurityTokenHandler = context.Options.AuthorizationCodeHandler;
                    context.SigningCredentials = context.Options.SigningCredentials.FirstOrDefault(
                        credentials => credentials.Key is SymmetricSecurityKey) ?? context.Options.SigningCredentials.First();

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of populating the serialization parameters needed to generate an identity token.
            /// </summary>
            public class AttachIdentityTokenSerializationParameters : IOpenIddictServerHandler<SerializeIdentityTokenContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<SerializeIdentityTokenContext>()
                        .UseSingletonHandler<AttachIdentityTokenSerializationParameters>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] SerializeIdentityTokenContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (!context.Options.SigningCredentials.Any(credentials => credentials.Key is AsymmetricSecurityKey))
                    {
                        throw new InvalidOperationException("No suitable signing credentials could be found.");
                    }

                    context.SecurityTokenHandler = context.Options.IdentityTokenHandler;
                    context.SigningCredentials = context.Options.SigningCredentials.First(
                        credentials => credentials.Key is AsymmetricSecurityKey);

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of populating the serialization parameters needed to generate a refresh token.
            /// </summary>
            public class AttachRefreshTokenSerializationParameters : IOpenIddictServerHandler<SerializeRefreshTokenContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<SerializeRefreshTokenContext>()
                        .UseSingletonHandler<AttachRefreshTokenSerializationParameters>()
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

                    if (context.Options.EncryptionCredentials.Count == 0)
                    {
                        throw new InvalidOperationException("No suitable encryption credentials could be found.");
                    }

                    if (context.Options.SigningCredentials.Count == 0)
                    {
                        throw new InvalidOperationException("No suitable signing credentials could be found.");
                    }

                    context.EncryptingCredentials = context.Options.EncryptionCredentials[0];
                    context.SecurityTokenHandler = context.Options.AuthorizationCodeHandler;
                    context.SigningCredentials = context.Options.SigningCredentials.FirstOrDefault(
                        credentials => credentials.Key is SymmetricSecurityKey) ?? context.Options.SigningCredentials.First();

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of populating the deserialization parameters needed to unprotect an access token.
            /// </summary>
            public class AttachAccessTokenDeserializationParameters : IOpenIddictServerHandler<DeserializeAccessTokenContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<DeserializeAccessTokenContext>()
                        .UseSingletonHandler<AttachAccessTokenDeserializationParameters>()
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

                    context.SecurityTokenHandler = context.Options.AccessTokenHandler;

                    context.TokenValidationParameters.IssuerSigningKeys = context.Options.SigningCredentials
                        .Select(credentials => credentials.Key);
                    context.TokenValidationParameters.NameClaimType = Claims.Name;
                    context.TokenValidationParameters.RoleClaimType = Claims.Role;
                    context.TokenValidationParameters.TokenDecryptionKeys = context.Options.EncryptionCredentials
                        .Select(credentials => credentials.Key)
                        .Where(key => key is SymmetricSecurityKey);
                    context.TokenValidationParameters.ValidIssuer = context.Issuer?.AbsoluteUri;
                    context.TokenValidationParameters.ValidateAudience = false;
                    context.TokenValidationParameters.ValidateLifetime = false;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of populating the deserialization parameters needed to unprotect an authorization code.
            /// </summary>
            public class AttachAuthorizationCodeDeserializationParameters : IOpenIddictServerHandler<DeserializeAuthorizationCodeContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<DeserializeAuthorizationCodeContext>()
                        .UseSingletonHandler<AttachAuthorizationCodeDeserializationParameters>()
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

                    context.SecurityTokenHandler = context.Options.AuthorizationCodeHandler;

                    context.TokenValidationParameters.IssuerSigningKeys = context.Options.SigningCredentials
                        .Select(credentials => credentials.Key);
                    context.TokenValidationParameters.NameClaimType = Claims.Name;
                    context.TokenValidationParameters.RoleClaimType = Claims.Role;
                    context.TokenValidationParameters.TokenDecryptionKeys = context.Options.EncryptionCredentials
                        .Select(credentials => credentials.Key);
                    context.TokenValidationParameters.ValidIssuer = context.Issuer?.AbsoluteUri;
                    context.TokenValidationParameters.ValidateAudience = false;
                    context.TokenValidationParameters.ValidateLifetime = false;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of populating the deserialization parameters needed to unprotect an identity token.
            /// </summary>
            public class AttachIdentityTokenDeserializationParameters : IOpenIddictServerHandler<DeserializeIdentityTokenContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<DeserializeIdentityTokenContext>()
                        .UseSingletonHandler<AttachIdentityTokenDeserializationParameters>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] DeserializeIdentityTokenContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    context.SecurityTokenHandler = context.Options.IdentityTokenHandler;

                    context.TokenValidationParameters.IssuerSigningKeys = context.Options.SigningCredentials
                        .Select(credentials => credentials.Key)
                        .OfType<AsymmetricSecurityKey>();
                    context.TokenValidationParameters.NameClaimType = Claims.Name;
                    context.TokenValidationParameters.RoleClaimType = Claims.Role;
                    context.TokenValidationParameters.ValidIssuer = context.Issuer?.AbsoluteUri;
                    context.TokenValidationParameters.ValidateAudience = false;
                    context.TokenValidationParameters.ValidateLifetime = false;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of populating the deserialization parameters needed to unprotect a refresh token.
            /// </summary>
            public class AttachRefreshTokenDeserializationParameters : IOpenIddictServerHandler<DeserializeRefreshTokenContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<DeserializeRefreshTokenContext>()
                        .UseSingletonHandler<AttachRefreshTokenDeserializationParameters>()
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

                    context.SecurityTokenHandler = context.Options.AuthorizationCodeHandler;

                    context.TokenValidationParameters.IssuerSigningKeys = context.Options.SigningCredentials
                        .Select(credentials => credentials.Key);
                    context.TokenValidationParameters.NameClaimType = Claims.Name;
                    context.TokenValidationParameters.RoleClaimType = Claims.Role;
                    context.TokenValidationParameters.TokenDecryptionKeys = context.Options.EncryptionCredentials
                        .Select(credentials => credentials.Key);
                    context.TokenValidationParameters.ValidIssuer = context.Issuer?.AbsoluteUri;
                    context.TokenValidationParameters.ValidateAudience = false;
                    context.TokenValidationParameters.ValidateLifetime = false;

                    return default;
                }
            }
        }
    }
}
