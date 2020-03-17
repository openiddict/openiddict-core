/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using JetBrains.Annotations;

namespace OpenIddict.Abstractions
{
    /// <summary>
    /// Represents a JSON.NET converter able to convert OpenIddict primitives.
    /// </summary>
    public class OpenIddictConverter : JsonConverter<OpenIddictMessage>
    {
        /// <summary>
        /// Determines whether the specified type is supported by this converter.
        /// </summary>
        /// <param name="type">The type to convert.</param>
        /// <returns><c>true</c> if the type is supported, <c>false</c> otherwise.</returns>
        public override bool CanConvert([NotNull] Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            return type == typeof(OpenIddictMessage) ||
                   type == typeof(OpenIddictRequest) ||
                   type == typeof(OpenIddictResponse);
        }

        /// <summary>
        /// Deserializes an <see cref="OpenIddictMessage"/> instance.
        /// </summary>
        /// <param name="reader">The JSON reader.</param>
        /// <param name="type">The type of the deserialized instance.</param>
        /// <param name="options">The JSON serializer options.</param>
        /// <returns>The deserialized <see cref="OpenIddictMessage"/> instance.</returns>
        public override OpenIddictMessage Read(ref Utf8JsonReader reader, Type type, JsonSerializerOptions options)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            using var document = JsonDocument.ParseValue(ref reader);

            return type == typeof(OpenIddictMessage) ? new OpenIddictMessage(document.RootElement.Clone()) :
                   type == typeof(OpenIddictRequest) ? (OpenIddictMessage) new OpenIddictRequest(document.RootElement.Clone()) :
                   type == typeof(OpenIddictResponse) ? new OpenIddictResponse(document.RootElement.Clone()) :
                   throw new ArgumentException("The specified type is not supported.", nameof(type));
        }

        /// <summary>
        /// Serializes an OpenIddict primitive.
        /// </summary>
        /// <param name="writer">The JSON writer.</param>
        /// <param name="value">The instance.</param>
        /// <param name="options">The JSON serializer options.</param>
        public override void Write(Utf8JsonWriter writer, OpenIddictMessage value, JsonSerializerOptions options)
        {
            if (writer == null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            value.WriteTo(writer);
        }
    }
}
