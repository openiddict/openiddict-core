using System;

namespace OpenIddict.Abstractions
{
    /// <summary>
    /// Represents an OpenIddict exception.
    /// </summary>
    public class OpenIddictException : Exception
    {
        /// <summary>
        /// Creates a new <see cref="OpenIddictException"/>.
        /// </summary>
        /// <param name="reason">The reason of the exception.</param>
        /// <param name="message">The exception message.</param>
        public OpenIddictException(string reason, string message)
            : base(message)
        {
            Reason = reason;
        }

        /// <summary>
        /// Creates a new <see cref="OpenIddictException"/>.
        /// </summary>
        /// <param name="reason">The reason of the exception.</param>
        /// <param name="message">The exception message.</param>
        /// <param name="innerException">The inner exception.</param>
        public OpenIddictException(string reason, string message, Exception innerException)
            : base(message, innerException)
        {
            Reason = reason;
        }

        /// <summary>
        /// Gets the reason that caused the exception to be thrown.
        /// </summary>
        public string Reason { get; }
    }
}
