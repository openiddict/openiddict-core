// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;

namespace NWebsec.Core.Exceptions
{
    public class RedirectValidationException : Exception
    {
        public RedirectValidationException(string message) : base(message)
        {
        }
    }
}