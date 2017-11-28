using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenNetERP.Security.Principal
{
    /// <summary>
    /// Represents a generic principal.
    /// </summary>
    [Serializable]
    [System.Runtime.InteropServices.ComVisible(true)]
    public class GenericPrincipal : IPrincipal
    {
        #region Variables

        /// <summary>
        /// The IIdentity object associated with the current principal.
        /// </summary>
        private IIdentity m_identity;

        /// <summary>
        /// An array of role names to which the user represented by the identity parameter belongs.
        /// </summary>
        private string[] m_roles;

        #endregion

        #region Properties

        /// <summary>
        /// Gets the identity of the current principal.
        /// </summary>
        /// <value>The <see cref="IIdentity">IIdentity</see> object associated with the current principal.</value>
        public virtual IIdentity Identity
        {
            get { return m_identity; }
        }

        #endregion

        #region Methods

        /// <summary>
        /// Determines whether the current GenericUser belongs to the specified role.
        /// </summary>
        /// <param name="role">The name of the role for which to check membership.</param>
        /// <returns><b>true</b> if the current GenericPrincipal is a member of the specified role; otherwise, <b>false</b>.</returns>
        public virtual bool IsInRole(string role)
        {
            if (role == null || m_roles == null)
                return false;

            for (int i = 0; i < m_roles.Length; ++i)
            {
                if (m_roles[i] != null && String.Compare(m_roles[i], role, StringComparison.OrdinalIgnoreCase) == 0)
                    return true;
            }

            return false;
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the GenericPrincipal class from a user identity and an array of role names to which the user represented by that identity belongs.
        /// </summary>
        /// <param name="identity">A basic implementation of <see cref="IIdentity">IIdentity</see> that represents any user.</param>
        /// <param name="roles">An array of role names to which the user represented by the identity parameter belongs.</param>
        /// <exception cref="ArgumentNullException">The identity parameter is <b>null</b>.</exception>
        public GenericPrincipal(IIdentity identity, string[] roles)
        {
            if (identity == null)
                throw new ArgumentNullException("identity");
            //Contract.EndContractBlock();

            m_identity = identity;
            if (roles != null)
            {
                m_roles = new string[roles.Length];
                for (int i = 0; i < roles.Length; ++i)
                {
                    m_roles[i] = roles[i];
                }
            }
            else
            {
                m_roles = null;
            }
        }

        #endregion
    }
}
