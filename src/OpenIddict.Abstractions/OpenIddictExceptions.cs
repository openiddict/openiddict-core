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
