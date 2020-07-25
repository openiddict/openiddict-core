/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using JetBrains.Annotations;
using SR = OpenIddict.Abstractions.OpenIddictResources;

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
        /// <param name="typeToConvert">The type to convert.</param>
        /// <returns><c>true</c> if the type is supported, <c>false</c> otherwise.</returns>
        public override bool CanConvert([NotNull] Type typeToConvert)
        {
            if (typeToConvert == null)
            {
                throw new ArgumentNullException(nameof(typeToConvert));
            }

            return typeToConvert == typeof(OpenIddictMessage) ||
                   typeToConvert == typeof(OpenIddictRequest) ||
                   typeToConvert == typeof(OpenIddictResponse);
        }

        /// <summary>
        /// Deserializes an <see cref="OpenIddictMessage"/> instance.
        /// </summary>
        /// <param name="reader">The JSON reader.</param>
        /// <param name="typeToConvert">The type of the deserialized instance.</param>
        /// <param name="options">The JSON serializer options.</param>
        /// <returns>The deserialized <see cref="OpenIddictMessage"/> instance.</returns>
        public override OpenIddictMessage Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (typeToConvert == null)
            {
                throw new ArgumentNullException(nameof(typeToConvert));
            }

            using var document = JsonDocument.ParseValue(ref reader);

            return typeToConvert == typeof(OpenIddictMessage)  ? new OpenIddictMessage(document.RootElement.Clone()) :
                   typeToConvert == typeof(OpenIddictRequest)  ? new OpenIddictRequest(document.RootElement.Clone()) :
                   typeToConvert == typeof(OpenIddictResponse) ? (OpenIddictMessage) new OpenIddictResponse(document.RootElement.Clone()) :
                   throw new ArgumentException(SR.GetResourceString(SR.ID1175), nameof(typeToConvert));
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
