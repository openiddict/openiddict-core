/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.ObjectModel;
using System.Data;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Primitives;

namespace OpenIddict.Extensions;

/// <summary>
/// Exposes common helpers used by the OpenIddict assemblies.
/// </summary>
internal static class OpenIddictHelpers
{
    /// <summary>
    /// Determines whether the specified array contains at least one value present in the specified set.
    /// </summary>
    /// <typeparam name="T">The type of the elements.</typeparam>
    /// <param name="array">The array.</param>
    /// <param name="set">The set.</param>
    /// <returns>
    /// <see langword="true"/> if the specified array contains at least one
    /// value present in the specified set, <see langword="false"/> otherwise.
    /// </returns>
    public static bool IncludesAnyFromSet<T>(IReadOnlyList<T> array, ISet<T> set)
    {
        ArgumentNullException.ThrowIfNull(set);

        for (var index = 0; index < array.Count; index++)
        {
            var value = array[index];
            if (set.Contains(value))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Determines whether the specified <paramref name="exception"/> is considered fatal.
    /// </summary>
    /// <param name="exception">The exception.</param>
    /// <returns>
    /// <see langword="true"/> if the exception is considered fatal, <see langword="false"/> otherwise.
    /// </returns>
    public static bool IsFatal(Exception exception)
    {
        RuntimeHelpers.EnsureSufficientExecutionStack();

        return exception switch
        {
            ThreadAbortException => true,
            OutOfMemoryException and not InsufficientMemoryException => true,

            AggregateException { InnerExceptions: var exceptions } => IsAnyFatal(exceptions),
            Exception { InnerException: Exception inner } => IsFatal(inner),

            _ => false
        };

        static bool IsAnyFatal(ReadOnlyCollection<Exception> exceptions)
        {
            for (var index = 0; index < exceptions.Count; index++)
            {
                if (IsFatal(exceptions[index]))
                {
                    return true;
                }
            }

            return false;
        }
    }

    /// <summary>
    /// Computes an absolute URI from the specified <paramref name="left"/> and <paramref name="right"/> URIs.
    /// Note: if the <paramref name="right"/> URI is already absolute, it is directly returned.
    /// </summary>
    /// <param name="left">The left part.</param>
    /// <param name="right">The right part.</param>
    /// <returns>An absolute URI from the specified <paramref name="left"/> and <paramref name="right"/>.</returns>
    /// <exception cref="InvalidOperationException"><paramref name="left"/> is not an absolute URI.</exception>
    [return: NotNullIfNotNull(nameof(right))]
    public static Uri? CreateAbsoluteUri(Uri? left, Uri? right)
    {
        if (right is null)
        {
            return null;
        }

        if (right.IsAbsoluteUri)
        {
            return right;
        }

        if (left is not { IsAbsoluteUri: true })
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(left));
        }

        // Ensure the left part ends with a trailing slash, as it is necessary
        // for Uri's constructor to include the last path segment in the base URI.
        left = left.AbsolutePath switch
        {
            null or { Length: 0 } => new UriBuilder(left) { Path = "/" }.Uri,
            [.., not '/'] => new UriBuilder(left) { Path = left.AbsolutePath + "/" }.Uri,
            ['/'] or _ => left
        };

        return new Uri(left, right);
    }

    /// <summary>
    /// Determines whether the <paramref name="left"/> URI is a base of the <paramref name="right"/> URI.
    /// </summary>
    /// <param name="left">The left part.</param>
    /// <param name="right">The right part.</param>
    /// <returns><see langword="true"/> if <paramref name="left"/> is base of
    /// <paramref name="right"/>, <see langword="false"/> otherwise.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="left"/> or
    /// <paramref name="right"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException"><paramref name="left"/> is not an absolute URI.</exception>
    public static bool IsBaseOf(Uri left, Uri right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        if (left is not { IsAbsoluteUri: true })
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(left));
        }

        // Ensure the left part ends with a trailing slash, as it is necessary
        // for Uri's constructor to include the last path segment in the base URI.
        left = left.AbsolutePath switch
        {
            null or { Length: 0 } => new UriBuilder(left) { Path = "/" }.Uri,
            [.., not '/'] => new UriBuilder(left) { Path = left.AbsolutePath + "/" }.Uri,
            ['/'] or _ => left
        };

        return left.IsBaseOf(right);
    }

    /// <summary>
    /// Determines whether the specified <paramref name="uri"/> represents an implicit file URI.
    /// </summary>
    /// <param name="uri">The URI.</param>
    /// <returns>
    /// <see langword="true"/> if <paramref name="uri"/> represents
    /// an implicit file URI, <see langword="false"/> otherwise.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="uri"/> is <see langword="null"/>.</exception>
    public static bool IsImplicitFileUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return uri.IsAbsoluteUri && uri.IsFile &&
            !uri.OriginalString.StartsWith(uri.Scheme, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Adds a query string parameter to the specified <see cref="Uri"/>.
    /// </summary>
    /// <param name="uri">The URI to which the query string parameter will be appended.</param>
    /// <param name="name">The name of the query string parameter to append.</param>
    /// <param name="value">The value of the query string parameter to append.</param>
    /// <returns>The final <see cref="Uri"/> instance, with the specified parameter appended.</returns>
    public static Uri AddQueryStringParameter(Uri uri, string name, string? value)
    {
        ArgumentNullException.ThrowIfNull(uri);

        var builder = new StringBuilder(uri.Query);
        if (builder.Length is > 0)
        {
            builder.Append('&');
        }

        builder.Append(Uri.EscapeDataString(name));

        if (!string.IsNullOrEmpty(value))
        {
            builder.Append('=');
            builder.Append(Uri.EscapeDataString(value));
        }

        return new UriBuilder(uri) { Query = builder.ToString() }.Uri;
    }

    /// <summary>
    /// Adds query string parameters to the specified <see cref="Uri"/>.
    /// </summary>
    /// <param name="uri">The URI to which the query string parameters will be appended.</param>
    /// <param name="parameters">The query string parameters to append.</param>
    /// <returns>The final <see cref="Uri"/> instance, with the specified parameters appended.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="uri"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="parameters"/> is <see langword="null"/>.</exception>
    public static Uri AddQueryStringParameters(Uri uri, IReadOnlyDictionary<string, StringValues> parameters)
    {
        ArgumentNullException.ThrowIfNull(uri);
        ArgumentNullException.ThrowIfNull(parameters);

        if (parameters.Count is 0)
        {
            return uri;
        }

        var builder = new StringBuilder(uri.Query);

        foreach (var parameter in parameters)
        {
            // If the parameter doesn't include any string value,
            // only append the parameter key to the query string.
            if (parameter.Value.Count is 0)
            {
                if (builder.Length is > 0)
                {
                    builder.Append('&');
                }

                builder.Append(Uri.EscapeDataString(parameter.Key));
            }

            // Otherwise, iterate the string values and create
            // a new "name=value" pair for each iterated value.
            else
            {
                foreach (var value in parameter.Value)
                {
                    if (builder.Length is > 0)
                    {
                        builder.Append('&');
                    }

                    builder.Append(Uri.EscapeDataString(parameter.Key));

                    if (!string.IsNullOrEmpty(value))
                    {
                        builder.Append('=');
                        builder.Append(Uri.EscapeDataString(value));
                    }
                }
            }
        }

        return new UriBuilder(uri) { Query = builder.ToString() }.Uri;
    }

    /// <summary>
    /// Extracts the parameters from the specified query string.
    /// </summary>
    /// <param name="query">The query string, which may start with a '?'.</param>
    /// <returns>The parameters extracted from the specified query string.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="query"/> is <see langword="null"/>.</exception>
    public static IReadOnlyDictionary<string, StringValues> ParseQuery(string query)
    {
        ArgumentNullException.ThrowIfNull(query);

        return query.TrimStart(Separators.QuestionMark[0])
            .Split([Separators.Ampersand[0], Separators.Semicolon[0]], StringSplitOptions.RemoveEmptyEntries)
            .Select(static parameter => parameter.Split(Separators.EqualsSign, StringSplitOptions.RemoveEmptyEntries))
            .Select(static parts => (
                Key: parts[0] is string key ? Uri.UnescapeDataString(key) : null,
                Value: parts.Length is > 1 && parts[1] is string value ? Uri.UnescapeDataString(value) : null))
            .Where(static pair => !string.IsNullOrEmpty(pair.Key))
            .GroupBy(static pair => pair.Key, StringComparer.Ordinal)
            .ToDictionary(static pair => pair.Key!, static pair => new StringValues([.. pair.Select(parts => parts.Value)]), StringComparer.Ordinal);
    }

    /// <summary>
    /// Extracts the parameters from the specified fragment.
    /// </summary>
    /// <param name="fragment">The fragment string, which may start with a '#'.</param>
    /// <returns>The parameters extracted from the specified fragment.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="fragment"/> is <see langword="null"/>.</exception>
    public static IReadOnlyDictionary<string, StringValues> ParseFragment(string fragment)
    {
        ArgumentNullException.ThrowIfNull(fragment);

        return fragment.TrimStart(Separators.Hash[0])
            .Split([Separators.Ampersand[0], Separators.Semicolon[0]], StringSplitOptions.RemoveEmptyEntries)
            .Select(static parameter => parameter.Split(Separators.EqualsSign, StringSplitOptions.RemoveEmptyEntries))
            .Select(static parts => (
                Key: parts[0] is string key ? Uri.UnescapeDataString(key) : null,
                Value: parts.Length is > 1 && parts[1] is string value ? Uri.UnescapeDataString(value) : null))
            .Where(static pair => !string.IsNullOrEmpty(pair.Key))
            .GroupBy(static pair => pair.Key, StringComparer.Ordinal)
            .ToDictionary(static pair => pair.Key!, static pair => new StringValues([.. pair.Select(parts => parts.Value)]), StringComparer.Ordinal);
    }

    /// <summary>
    /// Extracts the parameters from the specified stream.
    /// </summary>
    /// <param name="stream">The stream containing the formurl-encoded data.</param>
    /// <param name="encoding">The encoding used to decode the data.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The parameters extracted from the specified stream.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="stream"/> is <see langword="null"/>.</exception>
    public static async ValueTask<IReadOnlyDictionary<string, StringValues>> ParseFormAsync(
        Stream stream, Encoding encoding, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(encoding);

        var reader = new FormReader(stream, encoding);
        return await reader.ReadFormAsync(cancellationToken);
    }

    /// <summary>
    /// Removes the characters that are not part of <paramref name="charset"/>
    /// from the specified <paramref name="value"/> string.
    /// </summary>
    /// <remarks>
    /// Note: if no character is present in <paramref name="charset"/>, all characters are considered valid.
    /// </remarks>
    /// <param name="value">The original string.</param>
    /// <param name="charset">The list of allowed characters.</param>
    /// <returns>The original string with the disallowed characters removed.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="charset"/> is <see langword="null"/>.</exception>
    public static string? RemoveDisallowedCharacters(string? value, IReadOnlyCollection<string> charset)
    {
        ArgumentNullException.ThrowIfNull(charset);

        if (charset.Count is 0 || string.IsNullOrEmpty(value))
        {
            return value;
        }

        var builder = new StringBuilder();

        var enumerator = StringInfo.GetTextElementEnumerator(value);
        while (enumerator.MoveNext())
        {
            var element = enumerator.GetTextElement();
            if (charset.Contains(element, StringComparer.Ordinal))
            {
                builder.Append(element);
            }
        }

        return builder.ToString();
    }

    /// <summary>
    /// Determines whether the specified <paramref name="element"/> represents a null, undefined or empty JSON node.
    /// </summary>
    /// <param name="element">The <see cref="JsonElement"/>.</param>
    /// <returns>
    /// <see langword="true"/> if the JSON node is null, undefined or empty <see langword="false"/> otherwise.
    /// </returns>
    public static bool IsNullOrEmpty(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Undefined or JsonValueKind.Null => true,

        JsonValueKind.String => string.IsNullOrEmpty(element.GetString()),
        JsonValueKind.Array  => element.GetArrayLength() is 0,
        JsonValueKind.Object => element.GetPropertyCount() is 0,

        _ => false,
    };

    /// <summary>
    /// Determines whether the specified <paramref name="node"/> represents a null or empty JSON node.
    /// </summary>
    /// <param name="node">The <see cref="JsonNode"/>.</param>
    /// <returns>
    /// <see langword="true"/> if the JSON node is null or empty, <see langword="false"/> otherwise.
    /// </returns>
    public static bool IsNullOrEmpty([NotNullWhen(false)] JsonNode? node) => node switch
    {
        null => true,

        JsonArray value  => value.Count is 0,
        JsonObject value => value.Count is 0,

        JsonValue value when value.TryGetValue(out string? result) => string.IsNullOrEmpty(result),
        JsonValue value when value.TryGetValue(out JsonElement element) => IsNullOrEmpty(element),

        // If the JSON node cannot be mapped to a primitive type, convert it to
        // a JsonElement instance and infer the corresponding claim value type.
        JsonNode value => IsNullOrEmpty(value.Deserialize(OpenIddictSerializer.Default.JsonElement))
    };

    /// <summary>
    /// Determines whether the specified <paramref name="certificate"/> is a certificate authority.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate2"/>.</param>
    /// <returns>
    /// <see langword="true"/> if the certificate is a certificate authority, <see langword="false"/> otherwise.
    /// </returns>
    public static bool IsCertificateAuthority(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        return certificate.Extensions.OfType<X509BasicConstraintsExtension>()
            .Any(static extension => extension.CertificateAuthority);
    }

    /// <summary>
    /// Determines whether the specified <paramref name="certificate"/> has the specified extended key usage.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate2"/>.</param>
    /// <param name="usage">The extended key usage.</param>
    /// <returns>
    /// <see langword="true"/> if the certificate has the specified extended key usage, <see langword="false"/> otherwise.
    /// </returns>
    public static bool HasExtendedKeyUsage(X509Certificate2 certificate, string usage)
    {
        for (var index = 0; index < certificate.Extensions.Count; index++)
        {
            if (certificate.Extensions[index] is X509EnhancedKeyUsageExtension extension &&
                HasOid(extension.EnhancedKeyUsages, usage))
            {
                return true;
            }
        }

        return false;

        static bool HasOid(OidCollection collection, string value)
        {
            for (var index = 0; index < collection.Count; index++)
            {
                if (collection[index] is Oid oid && string.Equals(oid.Value, value, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }

    /// <summary>
    /// Determines whether the specified <paramref name="certificate"/> has the specified key usage.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate2"/>.</param>
    /// <param name="usage">The <see cref="X509KeyUsageFlags"/>.</param>
    /// <returns>
    /// <see langword="true"/> if the certificate has the specified key usage, <see langword="false"/> otherwise.
    /// </returns>
    public static bool HasKeyUsage(X509Certificate2 certificate, X509KeyUsageFlags usage)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        for (var index = 0; index < certificate.Extensions.Count; index++)
        {
            if (certificate.Extensions[index] is X509KeyUsageExtension extension &&
                extension.KeyUsages.HasFlag(usage))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Determines whether the specified <paramref name="certificate"/> is self-issued.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate2"/>.</param>
    /// <returns>
    /// <see langword="true"/> if the certificate is self-issued, <see langword="false"/> otherwise.
    /// </returns>
    public static bool IsSelfIssuedCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        return certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
    }

    /// <summary>
    /// Determines whether the specified <paramref name="certificate"/> is suitable for client authentication.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate2"/>.</param>
    /// <returns>
    /// <see langword="true"/> if the certificate is suitable for client authentication, <see langword="false"/> otherwise.
    /// </returns>
    public static bool IsClientAuthenticationCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        return certificate.Version is >= 3 &&
            OpenIddictHelpers.HasKeyUsage(certificate, X509KeyUsageFlags.DigitalSignature) &&
            OpenIddictHelpers.HasExtendedKeyUsage(certificate, ObjectIdentifiers.ExtendedKeyUsages.ClientAuthentication);
    }

    /// <summary>
    /// Determines whether the items contained in <paramref name="element"/>
    /// are of the specified <paramref name="kind"/>.
    /// </summary>
    /// <param name="element">The <see cref="JsonElement"/>.</param>
    /// <param name="kind">The expected <see cref="JsonValueKind"/>.</param>
    /// <returns>
    /// <see langword="true"/> if the array doesn't contain any value or if all the items
    /// are of the specified <paramref name="kind"/>, <see langword="false"/> otherwise.
    /// </returns>
    public static bool ValidateArrayElements(JsonElement element, JsonValueKind kind)
    {
        if (element.ValueKind is not JsonValueKind.Array)
        {
            throw new ArgumentOutOfRangeException(nameof(element));
        }

        foreach (var item in element.EnumerateArray())
        {
            if (item.ValueKind != kind)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Determines whether the items contained in <paramref name="element"/>
    /// are of the specified <paramref name="kind"/>.
    /// </summary>
    /// <param name="element">The <see cref="JsonElement"/>.</param>
    /// <param name="kind">The expected <see cref="JsonValueKind"/>.</param>
    /// <returns>
    /// <see langword="true"/> if the object doesn't contain any value or if all the items
    /// are of the specified <paramref name="kind"/>, <see langword="false"/> otherwise.
    /// </returns>
    public static bool ValidateObjectElements(JsonElement element, JsonValueKind kind)
    {
        if (element.ValueKind is not JsonValueKind.Object)
        {
            throw new ArgumentOutOfRangeException(nameof(element));
        }

        foreach (var property in element.EnumerateObject())
        {
            if (property.Value.ValueKind != kind)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Note: this implementation was taken from ASP.NET Core.
    /// </summary>
    private class FormReader
    {
        public const int DefaultValueCountLimit = 1024;
        public const int DefaultKeyLengthLimit = 1024 * 2;
        public const int DefaultValueLengthLimit = 1024 * 1024 * 4;

        private readonly TextReader _reader;
        private readonly char[] _buffer;
        private readonly StringBuilder _builder = new();
        private int _bufferOffset;
        private int _bufferCount;
        private string? _currentKey;
        private string? _currentValue;
        private bool _endOfStream;

        public FormReader(Stream stream, Encoding encoding)
        {
            _buffer = new char[8192];
            _reader = new StreamReader(stream, encoding, detectEncodingFromByteOrderMarks: true, bufferSize: 1024 * 2, leaveOpen: true);
        }

        public int ValueCountLimit { get; set; } = DefaultValueCountLimit;
        public int KeyLengthLimit { get; set; } = DefaultKeyLengthLimit;
        public int ValueLengthLimit { get; set; } = DefaultValueLengthLimit;

        public KeyValuePair<string, string>? ReadNextPair()
        {
            ReadNextPairImpl();
            if (ReadSucceeded())
            {
                return KeyValuePair.Create(_currentKey, _currentValue);
            }
            return null;
        }

        private void ReadNextPairImpl()
        {
            StartReadNextPair();
            while (!_endOfStream)
            {
                // Empty
                if (_bufferCount == 0)
                {
                    Buffer();
                }
                if (TryReadNextPair())
                {
                    break;
                }
            }
        }

        public async Task<KeyValuePair<string, string>?> ReadNextPairAsync(CancellationToken cancellationToken = new CancellationToken())
        {
            await ReadNextPairAsyncImpl(cancellationToken);
            if (ReadSucceeded())
            {
                return KeyValuePair.Create(_currentKey, _currentValue);
            }
            return null;
        }

        private async Task ReadNextPairAsyncImpl(CancellationToken cancellationToken = new CancellationToken())
        {
            StartReadNextPair();
            while (!_endOfStream)
            {
                if (_bufferCount == 0)
                {
                    await BufferAsync(cancellationToken);
                }
                if (TryReadNextPair())
                {
                    break;
                }
            }
        }

        private void StartReadNextPair()
        {
            _currentKey = null;
            _currentValue = null;
        }

        private bool TryReadNextPair()
        {
            if (_currentKey == null)
            {
                if (!TryReadWord('=', KeyLengthLimit, out _currentKey))
                {
                    return false;
                }

                if (_bufferCount == 0)
                {
                    return false;
                }
            }

            if (_currentValue == null)
            {
                if (!TryReadWord('&', ValueLengthLimit, out _currentValue))
                {
                    return false;
                }
            }
            return true;
        }

        private bool TryReadWord(char separator, int limit, [NotNullWhen(true)] out string? value)
        {
            do
            {
                if (ReadChar(separator, limit, out value))
                {
                    return true;
                }
            } while (_bufferCount > 0);
            return false;
        }

        private bool ReadChar(char separator, int limit, [NotNullWhen(true)] out string? word)
        {
            if (_bufferCount == 0)
            {
                word = BuildWord();
                return true;
            }

            var c = _buffer[_bufferOffset++];
            _bufferCount--;

            if (c == separator)
            {
                word = BuildWord();
                return true;
            }
            if (_builder.Length >= limit)
            {
                throw new InvalidDataException($"Form key or value length limit {limit} exceeded.");
            }
            _builder.Append(c);
            word = null;
            return false;
        }

        private string BuildWord()
        {
            _builder.Replace('+', ' ');
            var result = _builder.ToString();
            _builder.Clear();
            return Uri.UnescapeDataString(result);
        }

        private void Buffer()
        {
            _bufferOffset = 0;
            _bufferCount = _reader.Read(_buffer, 0, _buffer.Length);
            _endOfStream = _bufferCount == 0;
        }

        private async Task BufferAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _bufferOffset = 0;
            _bufferCount = await _reader.ReadAsync(_buffer, 0, _buffer.Length);
            _endOfStream = _bufferCount == 0;
        }

        public Dictionary<string, StringValues> ReadForm()
        {
            var accumulator = new KeyValueAccumulator();
            while (!_endOfStream)
            {
                ReadNextPairImpl();
                Append(ref accumulator);
            }
            return accumulator.GetResults();
        }

        public async Task<Dictionary<string, StringValues>> ReadFormAsync(CancellationToken cancellationToken = new CancellationToken())
        {
            var accumulator = new KeyValueAccumulator();
            while (!_endOfStream)
            {
                await ReadNextPairAsyncImpl(cancellationToken);
                Append(ref accumulator);
            }
            return accumulator.GetResults();
        }

        [MemberNotNullWhen(true, nameof(_currentKey), nameof(_currentValue))]
        private bool ReadSucceeded()
        {
            return _currentKey != null && _currentValue != null;
        }

        private void Append(ref KeyValueAccumulator accumulator)
        {
            if (ReadSucceeded())
            {
                accumulator.Append(_currentKey, _currentValue);
                if (accumulator.ValueCount > ValueCountLimit)
                {
                    throw new InvalidDataException($"Form value count limit {ValueCountLimit} exceeded.");
                }
            }
        }
    }

    /// <summary>
    /// Note: this implementation was taken from ASP.NET Core.
    /// </summary>
    private struct KeyValueAccumulator
    {
        private Dictionary<string, StringValues> _accumulator;
        private Dictionary<string, List<string>> _expandingAccumulator;

        public void Append(string key, string value)
        {
            if (_accumulator == null)
            {
                _accumulator = new Dictionary<string, StringValues>(StringComparer.OrdinalIgnoreCase);
            }

            StringValues values;
            if (_accumulator.TryGetValue(key, out values))
            {
                if (values.Count == 0)
                {
                    _expandingAccumulator[key].Add(value);
                }
                else if (values.Count == 1)
                {
                    _accumulator[key] = new string[] { values[0]!, value };
                }
                else
                {
                    _accumulator[key] = default(StringValues);

                    if (_expandingAccumulator == null)
                    {
                        _expandingAccumulator = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
                    }

                    var list = new List<string>(8);
                    var array = values.ToArray();

                    list.Add(array[0]!);
                    list.Add(array[1]!);
                    list.Add(value);

                    _expandingAccumulator[key] = list;
                }
            }
            else
            {
                _accumulator[key] = new StringValues(value);
            }

            ValueCount++;
        }

        public bool HasValues => ValueCount > 0;
        public int KeyCount => _accumulator?.Count ?? 0;
        public int ValueCount { get; private set; }

        public Dictionary<string, StringValues> GetResults()
        {
            if (_expandingAccumulator != null)
            {
                foreach (var entry in _expandingAccumulator)
                {
                    _accumulator[entry.Key] = new StringValues([.. entry.Value]);
                }
            }

            return _accumulator ?? new Dictionary<string, StringValues>(0, StringComparer.OrdinalIgnoreCase);
        }
    }
}
