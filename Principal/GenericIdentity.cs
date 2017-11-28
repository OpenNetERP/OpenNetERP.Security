using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenNetERP.Security.Principal
{
    /// <summary>
    /// Represents a generic user.
    /// </summary>
    [Serializable]
    [System.Runtime.InteropServices.ComVisible(true)]
    public class GenericIdentity : IIdentity
    {
        #region Variables

        /// <summary>
        /// The name of the user on whose behalf the code is running.
        /// </summary>
        private string m_name;

        /// <summary>
        /// The type of authentication used to identify the user.
        /// </summary>
        private string m_type;

        #endregion

        #region Properties

        /// <summary>
        /// Gets the name of the current user.
        /// </summary>
        /// <value>The name of the user on whose behalf the code is running.</value>
        public virtual string Name
        {
            get
            {
                return m_name;
            }
        }

        /// <summary>
        /// Gets the type of authentication used.
        /// </summary>
        /// <value>The type of authentication used to identify the user.</value>
        public virtual string AuthenticationType
        {
            get
            {
                return m_type;
            }
        }

        /// <summary>
        /// Gets a value that indicates whether the user has been authenticated.
        /// </summary>
        /// <value><b>true</b> if the user was authenticated; otherwise, <b>false</b>.</value>
        public virtual bool IsAuthenticated
        {
            get
            {
                return !m_name.Equals("");
            }
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the GenericIdentity class representing the user with the specified name.
        /// </summary>
        /// <param name="name">The name of the user on whose behalf the code is running.</param>
        /// <exception cref="ArgumentNullException">The name parameter is <b>null</b>.</exception>
        public GenericIdentity(string name)
        {
            if (name == null)
                throw new ArgumentNullException("name");
            //Contract.EndContractBlock();

            m_name = name;
            m_type = "";
        }

        /// <summary>
        /// Initializes a new instance of the GenericIdentity class representing the user with the specified name and authentication type.
        /// </summary>
        /// <param name="name">The name of the user on whose behalf the code is running.</param>
        /// <param name="type">The type of authentication used to identify the user.</param>
        /// <exception cref="ArgumentNullException">
        /// The name parameter is <b>null</b>.
        /// -or-
        /// The type parameter is <b>null</b>.
        /// </exception>
        public GenericIdentity(string name, string type)
        {
            if (name == null)
                throw new ArgumentNullException("name");
            if (type == null)
                throw new ArgumentNullException("type");
            //Contract.EndContractBlock();

            m_name = name;
            m_type = type;
        }

        #endregion
    }
}
