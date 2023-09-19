using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenIddict.EntityFrameworkCore.Factory;

public interface IOpeniddictEntityFrameworkCoreContextFactory
{
    DbContext CreateDbContext();
}
