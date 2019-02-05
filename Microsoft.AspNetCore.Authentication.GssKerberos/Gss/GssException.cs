using System;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssException : Exception
    {      
        private const int GssCGssCode = 1;
        private const int GssCMechCode = 2;
        
        public GssException(string message, uint majorStatus) :
            this(message, majorStatus, 0, default(Krb5Interop.GssOidDesc))
        {
        }

        public GssException(string message, uint majorStatus, uint minorStatus, Krb5Interop.GssOidDesc oid) :
            base(FormatGssMessage(message, majorStatus, minorStatus, oid))
        {
        }

        private static string FormatGssMessage(string message, uint majorStatus, uint minorStatus, Krb5Interop.GssOidDesc oid)
        {
            var majorMessage = TranslateMajorStatusCode(majorStatus);
            var minorMessage = TranslateMinorStatusCode(minorStatus ,oid);
            return $"{message}{Environment.NewLine}" +
                   $"GSS Major: ({majorStatus:x8}) {majorMessage}{Environment.NewLine}" +
                   $"GSS Minor: ({minorStatus:x8}) {minorMessage}";
        }

        private static string TranslateMajorStatusCode(uint status)
        {
            var context = IntPtr.Zero;
            var buffer = default(Krb5Interop.GssBufferStruct);
            var oid = default(Krb5Interop.GssOidDesc);

            Krb5Interop.gss_display_status(out var _ ,status, GssCGssCode, ref oid, ref context, ref buffer);
            return buffer.value == IntPtr.Zero ? string.Empty : Marshal.PtrToStringAnsi(buffer.value);
        }

        private static string TranslateMinorStatusCode(uint status, Krb5Interop.GssOidDesc oid)
        {
            var context = IntPtr.Zero;
            var buffer = default(Krb5Interop.GssBufferStruct);

            Krb5Interop.gss_display_status(out var _ , status, GssCMechCode, ref oid, ref context, ref buffer);
            return buffer.value == IntPtr.Zero ? string.Empty : Marshal.PtrToStringAnsi(buffer.value);
        }
    }
}
