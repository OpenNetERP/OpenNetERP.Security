using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenNetERP.Security.Principal
{

    /// <summary>
    /// Defines the basic functionality of an identity object.
    /// </summary>
    [System.Runtime.InteropServices.ComVisible(true)]
    interface IIdentity
    {
        /// <summary>
        /// Gets the name of the current user.
        /// </summary>
        /// <value>The name of the user on whose behalf the code is running.</value>
        string Name { get; }

        /// <summary>
        /// Gets the type of authentication used.
        /// </summary>
        /// <value>The type of authentication used to identify the user.</value>
        string AuthenticationType { get; }

        /// <summary>
        /// Gets a value that indicates whether the user has been authenticated.
        /// </summary>
        /// <value><b>true</b> if the user was authenticated; otherwise, <b>false</b>.</value>
        bool IsAuthenticated { get; }
    }
}
