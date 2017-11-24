using System;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssException : Exception
    {
        private const int GssCMechCode = 2;
        private const int GssCGssCode = 2;

        public GssException(uint majorStatus) :
            this(majorStatus, 0, new NativeMethods.GssOidDescStruct())
        {
        }

        public GssException(uint majorStatus, uint minorStatus, NativeMethods.GssOidDescStruct oid) :
            base(FormatGssMessage(majorStatus, minorStatus, oid))
        {
        }

        private static string FormatGssMessage(uint majorStatus, uint minorStatus, NativeMethods.GssOidDescStruct oid)
        {
            var majorMessage = TranslateMajorStatusCode(majorStatus);
            var minorMessage = TranslateMinorStatusCode(minorStatus ,oid);
            return $"{majorMessage} {minorMessage}";
        }

        private static string TranslateMajorStatusCode(uint status)
        {
            var oid = new NativeMethods.GssOidDescStruct();
            NativeMethods.gss_display_status(out var _, status, GssCGssCode, ref oid, IntPtr.Zero, out var buffer);
            return Marshal.PtrToStringAnsi(buffer.value, (int)buffer.length);
        }

        private static string TranslateMinorStatusCode(uint status, NativeMethods.GssOidDescStruct oid)
        {
            NativeMethods.gss_display_status(out var _, status, GssCMechCode, ref oid, IntPtr.Zero, out var buffer);
            return Marshal.PtrToStringAnsi(buffer.value, (int)buffer.length);
        }
    }
}
