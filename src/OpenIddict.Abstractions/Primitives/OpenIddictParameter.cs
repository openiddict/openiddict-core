/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using JetBrains.Annotations;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OpenIddict.Abstractions
{
    /// <summary>
    /// Represents an OpenID Connect parameter value, that can be either a primitive value,
    /// an array of strings or a complex JSON representation containing child nodes.
    /// </summary>
    public readonly struct OpenIddictParameter : IEquatable<OpenIddictParameter>
    {
        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIddictParameter(bool value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIddictParameter(bool? value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIddictParameter(JToken value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIddictParameter(long value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIddictParameter(long? value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIddictParameter(string value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIddictParameter(string[] value) => Value = value;

        /// <summary>
        /// Gets the child item corresponding to the specified index.
        /// </summary>
        /// <param name="index">The index of the child item.</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
        public OpenIddictParameter? this[int index] => GetParameter(index);

        /// <summary>
        /// Gets the child item corresponding to the specified name.
        /// </summary>
        /// <param name="name">The name of the child item.</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
        public OpenIddictParameter? this[string name] => GetParameter(name);

        /// <summary>
        /// Gets the associated value, that can be either a primitive CLR type
        /// (e.g bool, string, long), an array of strings or a complex JSON object.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public object Value { get; }

        /// <summary>
        /// Determines whether the current <see cref="OpenIddictParameter"/>
        /// instance is equal to the specified <see cref="OpenIddictParameter"/>.
        /// </summary>
        /// <param name="parameter">The other object to which to compare this instance.</param>
        /// <returns><c>true</c> if the two instances are equal, <c>false</c> otherwise.</returns>
        public bool Equals(OpenIddictParameter parameter) => Value switch
        {
            // If the two parameters reference the same instance, return true.
            // Note: true will also be returned if the two parameters are null.
            var value when ReferenceEquals(value, parameter.Value) => true,

            // If one of the two parameters is null, return false.
            null => false,
            var _ when parameter.Value == null => false,

            // If the two parameters are string arrays, use SequenceEqual().
            string[] array when parameter.Value is string[] other => array.SequenceEqual(other),

            // If the two parameters are JSON values, use JToken.DeepEquals().
            JToken token when parameter.Value is JToken other => JToken.DeepEquals(token, other),

            // If the current instance is a JValue, compare the
            // underlying value to the other parameter value.
            JValue value => value.Value != null && value.Value.Equals(parameter.Value),

            // If the other parameter is a JValue, compare the
            // underlying value to the current parameter value.
            var value when parameter.Value is JValue other => other.Value != null && other.Value.Equals(value),

            // Otherwise, directly compare the two underlying values.
            _ => Value.Equals(parameter.Value)
        };

        /// <summary>
        /// Determines whether the current <see cref="OpenIddictParameter"/>
        /// instance is equal to the specified <see cref="object"/>.
        /// </summary>
        /// <param name="value">The other object to which to compare this instance.</param>
        /// <returns><c>true</c> if the two instances are equal, <c>false</c> otherwise.</returns>
        public override bool Equals(object value)
            => value is OpenIddictParameter parameter && Equals(parameter);

        /// <summary>
        /// Returns the hash code of the current <see cref="OpenIddictParameter"/> instance.
        /// </summary>
        /// <returns>The hash code for the current instance.</returns>
        // Note: if the value is a JValue, JSON.NET will automatically
        // return the hash code corresponding to the underlying value.
        public override int GetHashCode() => Value?.GetHashCode() ?? 0;

        /// <summary>
        /// Gets the child item corresponding to the specified index.
        /// </summary>
        /// <param name="index">The index of the child item.</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
        public OpenIddictParameter? GetParameter(int index)
        {
            if (index < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(index), "The item index cannot be negative.");
            }

            if (Value is string[] array)
            {
                // If the specified index goes beyond the
                // number of items in the array, return null.
                if (index >= array.Length)
                {
                    return null;
                }

                return new OpenIddictParameter(array[index]);
            }

            // If the value is not a JSON array, return null.
            if (Value is JArray token)
            {
                // If the specified index goes beyond the
                // number of items in the array, return null.
                if (index >= token.Count)
                {
                    return null;
                }

                // If the item doesn't exist, return a null parameter.
                var value = token[index];
                if (value == null)
                {
                    return null;
                }

                return new OpenIddictParameter(value);
            }

            return null;
        }

        /// <summary>
        /// Gets the child item corresponding to the specified name.
        /// </summary>
        /// <param name="name">The name of the child item.</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
        public OpenIddictParameter? GetParameter([NotNull] string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The item name cannot be null or empty.", nameof(name));
            }

            if (Value is JObject dictionary)
            {
                // If the item doesn't exist, return a null parameter.
                var value = dictionary[name];
                if (value == null)
                {
                    return null;
                }

                return new OpenIddictParameter(value);
            }

            return null;
        }

        /// <summary>
        /// Gets the child items associated with the current parameter.
        /// </summary>
        /// <returns>An enumeration of all the parameters associated with the current instance.</returns>
        public IEnumerable<KeyValuePair<string, OpenIddictParameter>> GetParameters()
        {
            if (Value is string[] array)
            {
                for (var index = 0; index < array.Length; index++)
                {
                    yield return new KeyValuePair<string, OpenIddictParameter>(null, array[index]);
                }
            }

            if (Value is JToken token)
            {
                foreach (var child in token.Children())
                {
                    if (!(child is JProperty property))
                    {
                        yield return new KeyValuePair<string, OpenIddictParameter>(null, child);

                        continue;
                    }

                    yield return new KeyValuePair<string, OpenIddictParameter>(property.Name, property.Value);
                }
            }

            yield break;
        }

        /// <summary>
        /// Returns the <see cref="string"/> representation of the current instance.
        /// </summary>
        /// <returns>The <see cref="string"/> representation associated with the parameter value.</returns>
        public override string ToString() => Value switch
        {
            null => string.Empty,
            JValue value when value.Value == null => string.Empty,

            string[] array => string.Join(", ", array),

            JValue value => value.Value.ToString(),
            JToken token => token.ToString(Formatting.None),

            _ => Value.ToString()
        };

        /// <summary>
        /// Determines whether two <see cref="OpenIddictParameter"/> instances are equal.
        /// </summary>
        /// <param name="left">The first instance.</param>
        /// <param name="right">The second instance.</param>
        /// <returns><c>true</c> if the two instances are equal, <c>false</c> otherwise.</returns>
        public static bool operator ==(OpenIddictParameter left, OpenIddictParameter right) => left.Equals(right);

        /// <summary>
        /// Determines whether two <see cref="OpenIddictParameter"/> instances are not equal.
        /// </summary>
        /// <param name="left">The first instance.</param>
        /// <param name="right">The second instance.</param>
        /// <returns><c>true</c> if the two instances are not equal, <c>false</c> otherwise.</returns>
        public static bool operator !=(OpenIddictParameter left, OpenIddictParameter right) => !left.Equals(right);

        /// <summary>
        /// Converts an <see cref="OpenIddictParameter"/> instance to a boolean.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator bool(OpenIddictParameter? parameter) => Convert<bool>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIddictParameter"/> instance to a nullable boolean.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator bool?(OpenIddictParameter? parameter) => Convert<bool?>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="JArray"/>.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator JArray(OpenIddictParameter? parameter) => Convert<JArray>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="JObject"/>.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator JObject(OpenIddictParameter? parameter) => Convert<JObject>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="JToken"/>.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator JToken(OpenIddictParameter? parameter) => Convert<JToken>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="JValue"/>.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator JValue(OpenIddictParameter? parameter) => Convert<JValue>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIddictParameter"/> instance to a long integer.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator long(OpenIddictParameter? parameter) => Convert<long>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIddictParameter"/> instance to a nullable long integer.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator long?(OpenIddictParameter? parameter) => Convert<long?>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIddictParameter"/> instance to a string.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator string(OpenIddictParameter? parameter) => Convert<string>(parameter);

        /// <summary>
        /// Converts an <see cref="OpenIddictParameter"/> instance to an array of strings.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator string[](OpenIddictParameter? parameter) => Convert<string[]>(parameter);

        /// <summary>
        /// Converts a boolean to an <see cref="OpenIddictParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
        public static implicit operator OpenIddictParameter(bool value) => new OpenIddictParameter(value);

        /// <summary>
        /// Converts a nullable boolean to an <see cref="OpenIddictParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
        public static implicit operator OpenIddictParameter(bool? value) => new OpenIddictParameter(value);

        /// <summary>
        /// Converts a <see cref="JToken"/> to an <see cref="OpenIddictParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
        public static implicit operator OpenIddictParameter(JToken value) => new OpenIddictParameter(value);

        /// <summary>
        /// Converts a long integer to an <see cref="OpenIddictParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
        public static implicit operator OpenIddictParameter(long value) => new OpenIddictParameter(value);

        /// <summary>
        /// Converts a nullable long integer to an <see cref="OpenIddictParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
        public static implicit operator OpenIddictParameter(long? value) => new OpenIddictParameter(value);

        /// <summary>
        /// Converts a string to an <see cref="OpenIddictParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
        public static implicit operator OpenIddictParameter(string value) => new OpenIddictParameter(value);

        /// <summary>
        /// Converts an array of strings to an <see cref="OpenIddictParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
        public static implicit operator OpenIddictParameter(string[] value) => new OpenIddictParameter(value);

        /// <summary>
        /// Converts the parameter to the specified generic type.
        /// </summary>
        /// <typeparam name="T">The type the parameter will be converted to.</typeparam>
        /// <param name="parameter">The <see cref="OpenIddictParameter"/> instance.</param>
        /// <returns>The converted parameter.</returns>
        private static T Convert<T>(OpenIddictParameter? parameter)
        {
            try
            {
                return parameter?.Value switch
                {
                    null => default,

                    T value => value,

                    string value when typeof(T) == typeof(string[]) => (T) (object) new string[] { value },

                    // Note: when the parameter is represented as a string, try to
                    // deserialize it if the requested type is a JArray or a JObject.
                    string value when typeof(T) == typeof(JArray) => (T) (object) JArray.Parse(value),

                    string value when typeof(T) == typeof(JObject) => (T) (object) JObject.Parse(value),

                    string[] array => new JArray(array).ToObject<T>(),

                    JValue value when typeof(T) == typeof(string[]) => (T) (object) new string[]
                    {
                        value.ToObject<string>()
                    },

                    JToken token => token.ToObject<T>(),

                    var value when typeof(T) == typeof(string[]) => (T) (object) new string[]
                    {
                        new JValue(value).ToObject<string>()
                    },

                    _ => new JValue(parameter?.Value).ToObject<T>()
                };
            }

            // Swallow the conversion exceptions thrown by JSON.NET.
            catch (Exception exception) when (exception is ArgumentException ||
                                              exception is FormatException ||
                                              exception is InvalidCastException ||
                                              exception is JsonReaderException ||
                                              exception is JsonSerializationException)
            {
                return default;
            }

            // Other exceptions will be automatically re-thrown.
        }

        /// <summary>
        /// Determines whether an OpenID Connect parameter is null or empty.
        /// </summary>
        /// <param name="parameter">The OpenID Connect parameter.</param>
        /// <returns><c>true</c> if the parameter is null or empty, <c>false</c> otherwise.</returns>
        public static bool IsNullOrEmpty(OpenIddictParameter parameter) => parameter.Value switch
        {
            null => true,

            string value => string.IsNullOrEmpty(value),

            string[] array => array.Length == 0,

            JValue value when value.Value is string text => string.IsNullOrEmpty(text),
            JArray array => !array.HasValues,
            JToken token => !token.HasValues,

            _ => false
        };
    }
}
