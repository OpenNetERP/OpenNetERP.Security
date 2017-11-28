using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Permissions;
using System.Text;
using System.Threading.Tasks;

namespace OpenNetERP.Security
{

    /// <summary>
    /// Provides credentials for password-based authentication schemes such as basic, digest, NTLM, and Kerberos authentication.
    /// </summary>
    /// <remarks>
    /// The <see cref="Credential">Credential</see> class is a base class that supplies credentials in password-based authentication schemes such as basic, digest, NTLM, and Kerberos. Classes that implement the <see cref="ICredentials">ICredentials</see> interface, such as the <see cref="System.Net.CredentialCache">CredentialCache</see> class, return <see cref="Credential">Credential</see> objects.
    /// 
    /// This class does not support public key-based authentication methods such as Secure Sockets Layer(SSL) client authentication.
    /// </remarks>
    public class Credential : ICredentials
    {

        #region Variables
        private static readonly object lockingObject = new object();
        private static volatile EnvironmentPermission m_environmentDomainNamePermission;
        private static volatile EnvironmentPermission m_environmentUserNamePermission;

        private string m_domain;
        private string m_userName;
#if !FEATURE_PAL
        private System.Security.SecureString m_password;
#else  //FEATURE_PAL
        private string m_password;
#endif //FEATURE_PAL

        #endregion

        #region Properties

        /// <summary>
        /// Gets or sets the domain or computer name that verifies the credentials.
        /// </summary>
        /// <value>The name of the domain associated with the credentials.</value>
        /// <remarks>
        /// The Domain property specifies the domain or realm to which the user name belongs. 
        /// Typically, this is the host computer name where the application runs or the user 
        /// domain for the currently logged in user.
        /// </remarks>
        public string Domain
        {
            get
            {
                InitializePart1();
                m_environmentDomainNamePermission.Demand();
                return InternalGetDomain();
            }
            set
            {
                if (value == null)
                    m_domain = String.Empty;
                else
                    m_domain = value;
                //                GlobalLog.Print("NetworkCredential::set_Domain: m_domain: \"" + m_domain + "\"" );
            }
        }

        /// <summary>
        /// Gets or sets the password for the user name associated with the credentials.
        /// </summary>
        /// <value>
        /// The password associated with the credentials. If this <see cref="Security.Credential">Credentials</see> 
        /// instance was initialized with the password parameter set to null, then the Password property 
        /// will return an empty string.
        /// </value>
        public string Password
        {
            get
            {
                SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
                securityPermission.Demand();
                return InternalGetPassword();
            }
            set
            {
#if FEATURE_PAL
                if (value == null)
                    m_password = String.Empty;
                else
                    m_password = value;
//                GlobalLog.Print("NetworkCredential::set_Password: m_password: \"" + m_password + "\"" );
#else //!FEATURE_PAL
                m_password = UnsafeNclNativeMethods.SecureStringHelper.CreateSecureString(value);
                //                GlobalLog.Print("NetworkCredential::set_Password: value = " + value);
                //                GlobalLog.Print("NetworkCredential::set_Password: m_password:");
                //                GlobalLog.Dump(m_password);
#endif //!FEATURE_PAL
            }
        }

#if !FEATURE_PAL
        /// <summary>
        /// Gets or sets the password as a <see cref="SecureString">SecureString</see> instance.
        /// </summary>
        /// <value>he password for the user name associated with the credentials.</value>
        /// <exception cref="NotSupportedException">
        /// The <see cref="SecureString">SecureString</see> class is not supported on this platform.
        /// </exception>
        public SecureString SecurePassword
        {
            get
            {
                SecurityPermission securityPermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
                securityPermission.Demand();
                return InternalGetSecurePassword().Copy();
            }
            set
            {
                if (value == null)
                    m_password = new SecureString(); // makes 0 length string
                else
                    m_password = value.Copy();
            }
        }
#endif //!FEATURE_PAL

        /// <summary>
        /// Gets or sets the user name associated with the credentials.
        /// </summary>
        /// <value>The user name associated with the credentials.</value>
        public string UserName
        {
            get
            {
                InitializePart1();
                m_environmentUserNamePermission.Demand();
                return InternalGetUserName();
            }
            set
            {
                if (value == null)
                    m_userName = String.Empty;
                else
                    m_userName = value;
                // GlobalLog.Print("NetworkCredential::set_UserName: m_userName: \"" + m_userName + "\"" );
            }
        }

        #endregion

        #region Methods

        void InitializePart1()
        {
            if (m_environmentUserNamePermission == null)
            {
                lock (lockingObject)
                {
                    if (m_environmentUserNamePermission == null)
                    {
                        m_environmentDomainNamePermission = new EnvironmentPermission(EnvironmentPermissionAccess.Read, "USERDOMAIN");
                        m_environmentUserNamePermission = new EnvironmentPermission(EnvironmentPermissionAccess.Read, "USERNAME");
                    }
                }
            }
        }

        internal string InternalGetDomain()
        {
            // GlobalLog.Print("NetworkCredential::get_Domain: returning \"" + m_domain + "\"");
            return m_domain;
        }

        internal string InternalGetPassword()
        {
#if FEATURE_PAL
            // GlobalLog.Print("NetworkCredential::get_Password: returning \"" + m_password + "\"");
            return m_password;
#else //!FEATURE_PAL
            string decryptedString = UnsafeNclNativeMethods.SecureStringHelper.CreateString(m_password);

            // GlobalLog.Print("NetworkCredential::get_Password: returning \"" + decryptedString + "\"");
            return decryptedString;
#endif //!FEATURE_PAL
        }

#if !FEATURE_PAL
        internal SecureString InternalGetSecurePassword()
        {
            return m_password;
        }
#endif //!FEATURE_PAL

        internal string InternalGetUserName()
        {
            // GlobalLog.Print("NetworkCredential::get_UserName: returning \"" + m_userName + "\"");
            return m_userName;
        }

        #endregion


        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="Credential">Credential</see> class.
        /// </summary>
        /// <remarks>
        /// The default constructor for the <see cref="Credential">Credential</see> class initializes all properties to <b>null</b>.
        /// </remarks>
        public Credential()
        : this(string.Empty, string.Empty, string.Empty) {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Credential">Credential</see> class with the specified user name and password.
        /// </summary>
        /// <param name="userName">The user name associated with the credentials.</param>
        /// <param name="password">The password for the user name associated with the credentials.</param>
        /// <remarks>
        /// The constructor initializes a <see cref="Credential">Credential</see> object with the UserName property set to <i>userName</i> and the Password property set to <i>password</i>.
        /// </remarks>
        public Credential(string userName, string password)
        : this(userName, password, string.Empty) {
        }

#if !FEATURE_PAL
        /// <summary>
        /// Initializes a new instance of the <see cref="Credential">Credential</see> class with the specified user name and password.
        /// </summary>
        /// <param name="userName">The user name associated with the credentials.</param>
        /// <param name="password">The password for the user name associated with the credentials.</param>
        /// <exception cref="NotSupportedException">The <see cref="SecureString">SecureString</see> class is not supported on this platform.</exception>
        /// <remarks>
        /// The constructor initializes a <see cref="Credential">Credential</see> object with the UserName property set to <i>userName</i> and the Password property set to <i>password</i>.
        /// The password parameter is a <see cref="SecureString">SecureString</see> instance.
        /// If this constructor is called with the <i>password</i> parameter set to <b>null</b>, a new instance of <see cref="SecureString">SecureString</see> is initialized, If secure strings are not supported on this platform, then the <see cref="NotSupportedException">NotSupportedException</see> is thrown.
        /// </remarks>
        public Credential(string userName, SecureString password)
        : this(userName, password, string.Empty) {
        }
#endif //!FEATURE_PAL        

        /// <summary>
        /// Initializes a new instance of the <see cref="Credential">Credential</see> class with the specified user name, password, and domain.
        /// </summary>
        /// <param name="userName">The user name associated with the credentials.</param>
        /// <param name="password">The password for the user name associated with the credentials.</param>
        /// <param name="domain">The domain associated with these credentials.</param>
        /// <remarks>
        /// The constructor initializes a <see cref="Credential">Credential</see> object with the UserName property set to <i>userName</i>, the Password property set to <i>password</i>, and the Domain property set to <i>domain</i>.
        /// </remarks>
        public Credential(string userName, string password, string domain)
        {
            UserName = userName;
            Password = password;
            Domain = domain;
        }

#if !FEATURE_PAL
        /// <summary>
        /// Initializes a new instance of the <see cref="Credential">Credential</see> class with the specified user name, password, and domain.
        /// </summary>
        /// <param name="userName">The user name associated with the credentials.</param>
        /// <param name="password">The password for the user name associated with the credentials.</param>
        /// <param name="domain">The domain associated with these credentials.</param>
        /// <exception cref="NotSupportedException">The <see cref="SecureString">SecureString</see> class is not supported on this platform.</exception>
        /// <remarks>
        /// The constructor initializes a <see cref="Credential">Credential</see> object with the UserName property set to <i>userName</i> and the Password property set to <i>password</i>, and the Domain property set to <i>domain</i>.
        /// The password parameter is a <see cref="SecureString">SecureString</see> instance.
        /// If this constructor is called with the <i>password</i> parameter set to <b>null</b>, a new instance of <see cref="SecureString">SecureString</see> is initialized, If secure strings are not supported on this platform, then the <see cref="NotSupportedException">NotSupportedException</see> is thrown.
        /// </remarks>
        public Credential(string userName, SecureString password, string domain)
        {
            UserName = userName;
            SecurePassword = password;
            Domain = domain;
        }
#endif //!FEATURE_PAL        

        #endregion

    }
}