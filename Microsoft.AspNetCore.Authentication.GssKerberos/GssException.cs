using System;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssException : Exception
    {      
        private const int GssCGssCode = 1;
        private const int GssCMechCode = 2;
        
        public GssException(uint majorStatus) :
            this(majorStatus, 0, default(NativeMethods.GssOidDesc))
        {
        }

        public GssException(uint majorStatus, uint minorStatus, NativeMethods.GssOidDesc oid) :
            base(FormatGssMessage(majorStatus, minorStatus, oid))
        {
        }

        private static string FormatGssMessage(uint majorStatus, uint minorStatus, NativeMethods.GssOidDesc oid)
        {
            var majorMessage = TranslateMajorStatusCode(majorStatus);
            var minorMessage = TranslateMinorStatusCode(minorStatus ,oid);
            return $"major: {majorMessage} minor: {minorMessage}";
        }

        private static string TranslateMajorStatusCode(uint status)
        {
            var context = IntPtr.Zero;
            var buffer = default(NativeMethods.GssBufferDescStruct);
            var oid = default(NativeMethods.GssOidDesc);
            
            NativeMethods.gss_display_status(out var _,status, GssCGssCode, ref oid, ref context, ref buffer);
            return buffer.value == IntPtr.Zero ? string.Empty : Marshal.PtrToStringAnsi(buffer.value);
        }

        private static string TranslateMinorStatusCode(uint status, NativeMethods.GssOidDesc oid)
        {
            var context = IntPtr.Zero;
            var buffer = default(NativeMethods.GssBufferDescStruct);
            
            NativeMethods.gss_display_status(out var _, status, GssCMechCode, ref oid, ref context, ref buffer);
            return buffer.value == IntPtr.Zero ? string.Empty : Marshal.PtrToStringAnsi(buffer.value);
        }
    }
}
