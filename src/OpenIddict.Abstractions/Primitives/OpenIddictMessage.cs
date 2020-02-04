/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using JetBrains.Annotations;
using Microsoft.Extensions.Primitives;

namespace OpenIddict.Abstractions
{
    /// <summary>
    /// Represents an abstract OpenIddict message.
    /// </summary>
    /// <remarks>
    /// Security notice: developers instantiating this type are responsible of ensuring that the
    /// imported parameters are safe and won't cause the resulting message to grow abnormally,
    /// which may result in an excessive memory consumption and a potential denial of service.
    /// </remarks>
    [DebuggerDisplay("Parameters: {Parameters.Count}")]
    [JsonConverter(typeof(OpenIddictConverter))]
    public class OpenIddictMessage
    {
        /// <summary>
        /// Initializes a new OpenIddict message.
        /// </summary>
        public OpenIddictMessage()
        {
        }

        /// <summary>
        /// Initializes a new OpenIddict message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        public OpenIddictMessage(JsonElement parameters)
        {
            if (parameters.ValueKind != JsonValueKind.Object)
            {
                throw new ArgumentException("The specified JSON element is not an object.", nameof(parameters));
            }

            foreach (var parameter in parameters.EnumerateObject())
            {
                // While generally discouraged, JSON objects can contain multiple properties with
                // the same name. In this case, the last occurrence replaces the previous ones.
                if (HasParameter(parameter.Name))
                {
                    RemoveParameter(parameter.Name);
                }

                AddParameter(parameter.Name, parameter.Value);
            }
        }

        /// <summary>
        /// Initializes a new OpenIddict message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        public OpenIddictMessage([NotNull] IEnumerable<KeyValuePair<string, OpenIddictParameter>> parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters)
            {
                AddParameter(parameter.Key, parameter.Value);
            }
        }

        /// <summary>
        /// Initializes a new OpenIddict message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        public OpenIddictMessage([NotNull] IEnumerable<KeyValuePair<string, string>> parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters.GroupBy(parameter => parameter.Key))
            {
                var values = parameter.Select(parameter => parameter.Value).ToArray();

                // Note: the core OAuth 2.0 specification requires that request parameters
                // not be present more than once but derived specifications like the
                // token exchange specification deliberately allow specifying multiple
                // parameters with the same name to represent a multi-valued parameter.
                AddParameter(parameter.Key, values.Length switch
                {
                    0 => default,
                    1 => values[0],
                    _ => values
                });
            }
        }

        /// <summary>
        /// Initializes a new OpenIddict message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        public OpenIddictMessage([NotNull] IEnumerable<KeyValuePair<string, string[]>> parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters)
            {
                // Note: the core OAuth 2.0 specification requires that request parameters
                // not be present more than once but derived specifications like the
                // token exchange specification deliberately allow specifying multiple
                // parameters with the same name to represent a multi-valued parameter.
                AddParameter(parameter.Key, parameter.Value?.Length switch
                {
                    null => default,
                    0    => default,
                    1    => parameter.Value[0],
                    _    => parameter.Value
                });
            }
        }

        /// <summary>
        /// Initializes a new OpenIddict message.
        /// </summary>
        /// <param name="parameters">The message parameters.</param>
        public OpenIddictMessage([NotNull] IEnumerable<KeyValuePair<string, StringValues>> parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters)
            {
                // Note: the core OAuth 2.0 specification requires that request parameters
                // not be present more than once but derived specifications like the
                // token exchange specification deliberately allow specifying multiple
                // parameters with the same name to represent a multi-valued parameter.
                AddParameter(parameter.Key, parameter.Value.Count switch
                {
                    0 => default,
                    1 => parameter.Value[0],
                    _ => parameter.Value.ToArray()
                });
            }
        }

        /// <summary>
        /// Gets or sets a parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns>The parameter value.</returns>
        public OpenIddictParameter? this[string name]
        {
            get => GetParameter(name);
            set => SetParameter(name, value);
        }

        /// <summary>
        /// Gets the number of parameters contained in the current message.
        /// </summary>
        public int Count => Parameters.Count;

        /// <summary>
        /// Gets the dictionary containing the parameters.
        /// </summary>
        protected Dictionary<string, OpenIddictParameter> Parameters { get; }
            = new Dictionary<string, OpenIddictParameter>(StringComparer.Ordinal);

        /// <summary>
        /// Adds a parameter. Note: an exception is thrown if a parameter with the same name was already added.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <param name="value">The parameter value.</param>
        /// <returns>The current instance, which allows chaining calls.</returns>
        public OpenIddictMessage AddParameter([NotNull] string name, OpenIddictParameter value)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            if (Parameters.ContainsKey(name))
            {
                throw new ArgumentException("A parameter with the same name already exists.", nameof(name));
            }

            Parameters.Add(name, value);

            return this;
        }

        /// <summary>
        /// Gets the value corresponding to a given parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns>The parameter value, or <c>null</c> if it cannot be found.</returns>
        public OpenIddictParameter? GetParameter([NotNull] string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            if (Parameters.TryGetValue(name, out OpenIddictParameter value))
            {
                return value;
            }

            return null;
        }

        /// <summary>
        /// Gets all the parameters associated with this instance.
        /// </summary>
        /// <returns>The parameters associated with this instance.</returns>
        public IReadOnlyDictionary<string, OpenIddictParameter> GetParameters()
            => new ReadOnlyDictionary<string, OpenIddictParameter>(Parameters);

        /// <summary>
        /// Determines whether the current message contains the specified parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns><c>true</c> if the parameter is present, <c>false</c> otherwise.</returns>
        public bool HasParameter([NotNull] string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            return Parameters.ContainsKey(name);
        }

        /// <summary>
        /// Removes a parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns>The current instance, which allows chaining calls.</returns>
        public OpenIddictMessage RemoveParameter([NotNull] string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            Parameters.Remove(name);

            return this;
        }

        /// <summary>
        /// Adds, replaces or removes a parameter.
        /// Note: this method automatically removes empty parameters.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <param name="value">The parameter value.</param>
        /// <returns>The current instance, which allows chaining calls.</returns>
        public OpenIddictMessage SetParameter([NotNull] string name, [CanBeNull] OpenIddictParameter? value)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            // If the parameter value is null or empty, remove the corresponding entry from the collection.
            if (value == null || OpenIddictParameter.IsNullOrEmpty(value.GetValueOrDefault()))
            {
                Parameters.Remove(name);
            }

            else
            {
                Parameters[name] = value.GetValueOrDefault();
            }

            return this;
        }

        /// <summary>
        /// Tries to get the value corresponding to a given parameter.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <param name="value">The parameter value.</param>
        /// <returns><c>true</c> if the parameter could be found, <c>false</c> otherwise.</returns>
        public bool TryGetParameter([NotNull] string name, out OpenIddictParameter value)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            return Parameters.TryGetValue(name, out value);
        }

        /// <summary>
        /// Returns a <see cref="string"/> representation of the current instance that can be used in logs.
        /// Note: sensitive parameters like client secrets are automatically removed for security reasons.
        /// </summary>
        /// <returns>The indented JSON representation corresponding to this message.</returns>
        public override string ToString()
        {
            using var stream = new MemoryStream();
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                Indented = true
            });

            writer.WriteStartObject();

            foreach (var parameter in Parameters)
            {
                writer.WritePropertyName(parameter.Key);

                // Remove sensitive parameters from the generated payload.
                switch (parameter.Key)
                {
                    case OpenIddictConstants.Parameters.AccessToken:
                    case OpenIddictConstants.Parameters.Assertion:
                    case OpenIddictConstants.Parameters.ClientAssertion:
                    case OpenIddictConstants.Parameters.ClientSecret:
                    case OpenIddictConstants.Parameters.Code:
                    case OpenIddictConstants.Parameters.IdToken:
                    case OpenIddictConstants.Parameters.IdTokenHint:
                    case OpenIddictConstants.Parameters.Password:
                    case OpenIddictConstants.Parameters.RefreshToken:
                    case OpenIddictConstants.Parameters.Token:
                        writer.WriteStringValue("[redacted]");
                        continue;
                }

                parameter.Value.WriteTo(writer);
            }

            writer.WriteEndObject();
            writer.Flush();

            return Encoding.UTF8.GetString(stream.ToArray());
        }

        /// <summary>
        /// Writes the message to the specified JSON writer.
        /// </summary>
        /// <param name="writer">The UTF-8 JSON writer.</param>
        public void WriteTo(Utf8JsonWriter writer)
        {
            if (writer == null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            writer.WriteStartObject();

            foreach (var parameter in Parameters)
            {
                writer.WritePropertyName(parameter.Key);
                parameter.Value.WriteTo(writer);
            }

            writer.WriteEndObject();
        }
    }
}
