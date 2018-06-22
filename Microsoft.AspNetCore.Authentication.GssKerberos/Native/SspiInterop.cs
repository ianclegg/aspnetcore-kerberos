using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Authentication.GssKerberos.Sspi;
using Microsoft.Win32.SafeHandles;

#pragma warning disable IDE1006
// ReSharper disable InconsistentNaming
// ReSharper disable MemberHidesStaticFromOuterClass

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Native
{
    internal enum SecurityStatus
    {
        OK = 0x00000000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityHandle
    {
        public IntPtr dwLower;
        public IntPtr dwUpper;
    }

    internal sealed class SafeSspiAuthDataHandle : SafeHandleZeroOrMinusOneIsInvalid {
        public SafeSspiAuthDataHandle() : base(true) {
        }
 
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle() {
            return SspiInterop.SspiFreeAuthIdentity(handle) == SecurityStatus.OK;
        }
    }

    internal static class SspiInterop
    {
        internal const uint ISC_REQ_REPLAY_DETECT = 0x00000004;
        internal const uint ISC_REQ_SEQUENCE_DETECT = 0x00000008;
        internal const uint ISC_REQ_CONNECTION = 0x00000800;
        internal const int ISC_REQ_CONFIDENTIALITY = 0x00000010;
        internal const uint ISC_REQ_ALLOCATE_MEMORY = 0x00000100;

        internal const int SECURITY_NATIVE_DREP = 0x10;

        public const int SECPKG_CRED_BOTH = 2;
        public const int SECURITY_STATUS_SUCCESS = 0;
        public const int SEC_E_OK = 0x0;
        public const int SEC_I_CONTINUE_NEEDED = 0x90312;

        private const string SECUR32 = "secur32.dll";

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int AcquireCredentialsHandle(
            string pszPrincipal,
            string pszPackage,
            int fCredentialUse,
            IntPtr PAuthenticationID,
            SafeSspiAuthDataHandle pAuthData,
            int pGetKeyFn,
            IntPtr pvGetKeyArgument,
            ref SecurityHandle phCredential,
            ref long ptsExpiry);

        [DllImport(SECUR32, CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int AcceptSecurityContext(
            ref SecurityHandle phCredential,
            ref SecurityHandle phContext,
            [In, Out][MarshalAs(UnmanagedType.CustomMarshaler, MarshalCookie = "input", MarshalTypeRef = typeof(SecurityBufferMarshaler))]
            SecurityBufferDescription pInput,
            uint fContextReq,
            uint TargetDataRep,
            ref SecurityHandle phNewContext,
            [In, Out][MarshalAs(UnmanagedType.CustomMarshaler, MarshalCookie = "output", MarshalTypeRef = typeof(SecurityBufferMarshaler))]
            SecurityBufferDescription pOutput,
            out uint pfContextAttr,
            out long timeStamp);

        [DllImport(SECUR32, CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int AcceptSecurityContext(
            ref SecurityHandle phCredential,
            IntPtr phContext,
            [In, Out][MarshalAs(UnmanagedType.CustomMarshaler, MarshalCookie = "input", MarshalTypeRef = typeof(SecurityBufferMarshaler))]
            SecurityBufferDescription pInput,
            uint fContextReq,
            uint TargetDataRep,
            ref SecurityHandle phNewContext,
            [In, Out][MarshalAs(UnmanagedType.CustomMarshaler, MarshalCookie = "output", MarshalTypeRef = typeof(SecurityBufferMarshaler))]
            SecurityBufferDescription pOutput,
            out uint pfContextAttr,
            out long timeStamp);

        [DllImport(SECUR32, ExactSpelling = true, SetLastError = true)]
        internal static extern SecurityStatus SspiFreeAuthIdentity(
            [In] IntPtr authData);

        [DllImport("kernel32.dll")]
        public static extern int CloseHandle(IntPtr hObject);
    }
}
