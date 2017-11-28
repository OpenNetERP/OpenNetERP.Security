using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenNetERP.Security.Principal
{
    /// <summary>
    /// Defines the basic functionality of a principal object.
    /// </summary>
    [System.Runtime.InteropServices.ComVisible(true)]
    public interface IPrincipal
    {
        /// <summary>
        /// Gets the identity of the current principal.
        /// </summary>
        /// <value>The <see cref="IIdentity">IIdentity</see> object associated with the current principal.</value>
        IIdentity Identity
        {
            get;
        }

        /// <summary>
        /// Determines whether the current GenericUser belongs to the specified role.
        /// </summary>
        /// <param name="role">The name of the role for which to check membership.</param>
        /// <returns><b>true</b> if the current GenericPrincipal is a member of the specified role; otherwise, <b>false</b>.</returns>
        bool IsInRole(string role);
    }
}
