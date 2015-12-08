// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System.Collections.Generic;
using NWebsec.Core;

namespace NWebsec.Middleware.Core
{
    //TODO Get rid of these?
    internal class OwinEnvironment
    {
        private readonly IDictionary<string, object> _environment;

        internal OwinEnvironment(IDictionary<string, object> env)
        {
            _environment = env;
            RequestHeaders = new RequestHeaders((IDictionary<string, string[]>)_environment[OwinKeys.RequestHeaders]);
            ResponseHeaders = new ResponseHeaders((IDictionary<string, string[]>)_environment[OwinKeys.ResponseHeaders]);
        }

        internal string RequestScheme => (string)_environment[OwinKeys.RequestScheme];

        internal string RequestPathBase => (string)_environment[OwinKeys.RequestPathBase];

        internal string RequestPath => (string)_environment[OwinKeys.RequestPath];

        internal int ResponseStatusCode
        {
            get { return (int)_environment[OwinKeys.ResponseStatusCode]; }
            set { _environment[OwinKeys.ResponseStatusCode] = value; }
        }

        internal RequestHeaders RequestHeaders { get; private set; }

        internal ResponseHeaders ResponseHeaders { get; private set; }

        internal NWebsecContext NWebsecContext
        {
            get
            {
                if (!_environment.ContainsKey(NWebsecContext.ContextKey))
                {
                    _environment[NWebsecContext.ContextKey] = new NWebsecContext();
                }

                return _environment[NWebsecContext.ContextKey] as NWebsecContext;
            }
        }
    }
}