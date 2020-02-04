using System;
using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;

namespace OpenIddict.Abstractions
{
    /// <summary>
    /// Exposes common exceptions thrown by OpenIddict.
    /// </summary>
    public static class OpenIddictExceptions
    {
        /// <summary>
        /// Represents an OpenIddict concurrency exception.
        /// </summary>
        public class ConcurrencyException : Exception
        {
            /// <summary>
            /// Creates a new <see cref="ConcurrencyException"/>.
            /// </summary>
            /// <param name="message">The exception message.</param>
            public ConcurrencyException(string message)
                : this(message, exception: null)
            {
            }

            /// <summary>
            /// Creates a new <see cref="ConcurrencyException"/>.
            /// </summary>
            /// <param name="message">The exception message.</param>
            /// <param name="exception">The inner exception.</param>
            public ConcurrencyException(string message, Exception exception)
                : base(message, exception)
            {
            }
        }

        /// <summary>
        /// Represents a generic OpenIddict exception.
        /// </summary>
        public class GenericException : Exception
        {
            /// <summary>
            /// Creates a new <see cref="GenericException"/>.
            /// </summary>
            /// <param name="message">The exception message.</param>
            public GenericException(string message)
                : this(message, null)
            {
            }

            /// <summary>
            /// Creates a new <see cref="GenericException"/>.
            /// </summary>
            /// <param name="message">The exception message.</param>
            /// <param name="error">The error type.</param>
            public GenericException(string message, string error)
                : this(message, error, description: null)
            {
            }

            /// <summary>
            /// Creates a new <see cref="GenericException"/>.
            /// </summary>
            /// <param name="message">The exception message.</param>
            /// <param name="error">The error type.</param>
            /// <param name="description">The error description.</param>
            public GenericException(string message, string error, string description)
                : this(message, error, description, uri: null)
            {
            }

            /// <summary>
            /// Creates a new <see cref="GenericException"/>.
            /// </summary>
            /// <param name="message">The exception message.</param>
            /// <param name="error">The error type.</param>
            /// <param name="description">The error description.</param>
            /// <param name="uri">The error URI.</param>
            public GenericException(string message, string error, string description, string uri)
                : base(message)
            {
                Error = error;
                ErrorDescription = description;
                ErrorUri = uri;
            }

            /// <summary>
            /// Gets the error type.
            /// </summary>
            public string Error { get; }

            /// <summary>
            /// Gets the error description.
            /// </summary>
            public string ErrorDescription { get; }

            /// <summary>
            /// Gets the error URI.
            /// </summary>
            public string ErrorUri { get; }
        }

        /// <summary>
        /// Represents an OpenIddict validation exception.
        /// </summary>
        public class ValidationException : Exception
        {
            /// <summary>
            /// Creates a new <see cref="ValidationException"/>.
            /// </summary>
            /// <param name="message">The exception message.</param>
            public ValidationException(string message)
                : this(message, ImmutableArray.Create<ValidationResult>())
            {
            }

            /// <summary>
            /// Creates a new <see cref="ValidationException"/>.
            /// </summary>
            /// <param name="message">The exception message.</param>
            /// <param name="results">The validation results.</param>
            public ValidationException(string message, ImmutableArray<ValidationResult> results)
                : this(message, results, exception: null)
            {
            }

            /// <summary>
            /// Creates a new <see cref="ValidationException"/>.
            /// </summary>
            /// <param name="message">The exception message.</param>
            /// <param name="results">The validation results.</param>
            /// <param name="exception">The inner exception.</param>
            public ValidationException(string message, ImmutableArray<ValidationResult> results, Exception exception)
                : base(message, exception)
            {
                Results = results;
            }

            /// <summary>
            /// Gets the validation results associated with this exception.
            /// </summary>
            public ImmutableArray<ValidationResult> Results { get; }
        }
    }
}
