/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using NHibernate.Mapping.ByCode;
using NHibernate.Mapping.ByCode.Conformist;
using OpenIddict.NHibernate.Models;

namespace OpenIddict.NHibernate
{
    /// <summary>
    /// Defines a relational mapping for the Scope entity.
    /// </summary>
    /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
    /// <typeparam name="TKey">The type of the Key entity.</typeparam>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictScopeMapping<TScope, TKey> : ClassMapping<TScope>
        where TScope : OpenIddictScope<TKey>
        where TKey : IEquatable<TKey>
    {
        public OpenIddictScopeMapping()
        {
            Id(scope => scope.Id, map =>
            {
                map.Generator(Generators.Identity);
            });

            Version(scope => scope.Version, map =>
            {
                map.Insert(true);
            });

            Property(scope => scope.Description, map =>
            {
                map.Length(10000);
            });

            Property(scope => scope.DisplayName);

            Property(scope => scope.Name, map =>
            {
                map.NotNullable(true);
                map.Unique(true);
            });

            Property(scope => scope.Properties, map =>
            {
                map.Length(10000);
            });

            Property(scope => scope.Resources, map =>
            {
                map.Length(10000);
            });

            Table("OpenIddictScopes");
        }
    }
}
