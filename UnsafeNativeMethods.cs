using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace OpenNetERP.Security
{
    [System.Security.SuppressUnmanagedCodeSecurityAttribute()]
    internal static class UnsafeNclNativeMethods
    {

#if !FEATURE_PAL

        [SuppressUnmanagedCodeSecurity]
        internal unsafe static class SecureStringHelper
        {
            internal static string CreateString(SecureString secureString)
            {
                string plainString;
                IntPtr bstr = IntPtr.Zero;

                if (secureString == null || secureString.Length == 0)
                    return String.Empty;

                try
                {
                    bstr = Marshal.SecureStringToBSTR(secureString);
                    plainString = Marshal.PtrToStringBSTR(bstr);
                }
                finally
                {
                    if (bstr != IntPtr.Zero)
                        Marshal.ZeroFreeBSTR(bstr);
                }
                return plainString;
            }

            internal static SecureString CreateSecureString(string plainString)
            {
                SecureString secureString;

                if (plainString == null || plainString.Length == 0)
                    return new SecureString();

                fixed (char* pch = plainString)
                {
                    secureString = new SecureString(pch, plainString.Length);
                }

                return secureString;
            }
        }

#endif // !FEATURE_PAL
        }
    }
