using System;
using System.Runtime.Serialization;

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
        /// Creates a new <see cref="OpenIddictException"/>.
        /// </summary>
        /// <param name="info">
        /// The <see cref="SerializationInfo"/> that holds the serialized object data about the exception being thrown.
        /// </param>
        /// <param name="context">
        /// The <see cref="StreamingContext"/> that contains contextual information about the source or destination.
        /// </param>
        protected OpenIddictException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            Reason = info.GetString(nameof(Reason));
        }

        /// <summary>
        /// Gets the reason that caused the exception to be thrown.
        /// </summary>
        public string Reason { get; }

        /// <summary>
        /// Serializes the members of this class.
        /// </summary>
        /// <param name="info">
        /// The <see cref="SerializationInfo"/> that holds the serialized object data about the exception being thrown.
        /// </param>
        /// <param name="context">
        /// The <see cref="StreamingContext"/> that contains contextual information about the source or destination.
        /// </param>
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            if (info == null)
            {
                throw new ArgumentNullException(nameof(info));
            }

            info.AddValue(nameof(Reason), Reason);

            base.GetObjectData(info, context);
        }
    }
}
