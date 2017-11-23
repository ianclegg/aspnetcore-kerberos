using System;
using System.Reflection;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssContext
    {
        public static Encoding iso8859 = Encoding.GetEncoding("iso-8859-1");

        public static void main()
        {
            using(var principal = GssBuffer.FromString("hello"))
            {
                var serverName = IntPtr.Zero;
                uint minorStatus = 0;
                
                NativeMethods.gss_import_name(
                    ref minorStatus,
                    ref principal.Value,
                    ref NativeMethods.GssKrb5MechOidDescStruct,
                    ref serverName);
            }
        }
    }
}