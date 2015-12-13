// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using NWebsec.Core.Fluent;

namespace NWebsec.Middleware
{
    public interface IFluentCspSandboxDirective : IFluentInterface
    {
        /// <summary>
        ///     Sets the 'allow-forms' source for the CSP sandbox directive.
        /// </summary>
        IFluentCspSandboxDirective AllowForms();

        /// <summary>
        ///     Sets the 'allow-pointer-lock' source for the CSP sandbox directive.
        /// </summary>
        IFluentCspSandboxDirective AllowPointerLock();

        /// <summary>
        ///     Sets the 'allow-popups' source for the CSP sandbox directive.
        /// </summary>
        IFluentCspSandboxDirective AllowPopups();

        /// <summary>
        ///     Sets the 'allow-same-origin' source for the CSP sandbox directive.
        /// </summary>
        IFluentCspSandboxDirective AllowSameOrigin();

        /// <summary>
        ///     Sets the 'allow-scripts' source for the CSP sandbox directive.
        /// </summary>
        IFluentCspSandboxDirective AllowScripts();

        /// <summary>
        ///     Sets the 'allow-top-navigation' source for the CSP sandbox directive.
        /// </summary>
        IFluentCspSandboxDirective AllowTopNavigation();
    }
}