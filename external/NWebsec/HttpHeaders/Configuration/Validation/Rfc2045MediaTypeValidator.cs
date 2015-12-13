// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Text.RegularExpressions;

namespace NWebsec.Core.HttpHeaders.Configuration.Validation
{
    public class Rfc2045MediaTypeValidator
    {
        private static readonly string[] ValidTypes = { "application", "audio", "image","model", "text", "video" };

        public void Validate(string mediaType)
        {
            if (String.IsNullOrEmpty(mediaType)) throw new ArgumentException("String was null or empty", "mediaType");

            var components = mediaType.Split(new[] { '/' }, 2);
            var type = components[0];

            if (!ValidTypes.Any(t => t.Equals(type, StringComparison.OrdinalIgnoreCase)))
            {
                var message = String.Format("Media type \"{0}\" did not match any of the expected types: {1}", mediaType, String.Join(", ", ValidTypes));
                throw new Exception(message);
            }

            if (components.Length != 2)
            {
                throw new Exception("Invalid format for media type. Expected \"type/subtype\" but was: " + mediaType);
            }

            var subType = components[1];

            if (!Regex.IsMatch(subType, @"^[\x00-\x7F]*$"))
            {
                throw new Exception("Subtype contained characters from outside the US-ASCII range, was: " + subType);
            }

            if (Regex.IsMatch(subType, @"[\x00-\x20\x7F]+"))
            {
                throw new Exception("Subtype contained the space character, or an ASCII control character.");
            }

            var escapedTspecials = @"[()<>@,;:""\\/[\]?=]+";

            if (Regex.IsMatch(subType, escapedTspecials))
            {
                throw new Exception("Subtype contained one of the forbidden tspecial characters: " + Regex.Unescape(escapedTspecials));
            }
        }
    }
}