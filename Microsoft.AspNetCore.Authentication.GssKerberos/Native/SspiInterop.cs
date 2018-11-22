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

    [StructLayout(LayoutKind.Sequential)]
    public struct SEC_WINNT_AUTH_IDENTITY
    {
        public string User;
        public int UserLength;
        public string Domain;
        public int DomainLength;
        public string Password;
        public int PasswordLength;
        public uint Flags;
    };

    internal static class SspiInterop
    {
        internal const uint SEC_WINNT_AUTH_IDENTITY_UNICODE = 0x00000002;

        internal const uint ISC_REQ_REPLAY_DETECT = 0x00000004;
        internal const uint ISC_REQ_SEQUENCE_DETECT = 0x00000008;
        internal const uint ISC_REQ_CONNECTION = 0x00000800;
        internal const int ISC_REQ_CONFIDENTIALITY = 0x00000010;
        internal const uint ISC_REQ_ALLOCATE_MEMORY = 0x00000100;

        internal const int SECURITY_NATIVE_DREP = 0x10;

        public const int SECPKG_CRED_INBOUND = 1;
        public const int SECPKG_CRED_OUTBOUND = 2;
        public const int SECPKG_CRED_BOTH = 3;
        
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
            SEC_WINNT_AUTH_IDENTITY pAuthData,
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
            IntPtr input,
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

        [DllImport("secur32.Dll", CharSet = CharSet.None, SetLastError = false)]
        public static extern int QueryContextAttributes(
            ref SecurityHandle phContext,
            uint ulAttribute,
            out IntPtr pContextAttributes);


        [DllImport("kernel32.dll")]
        public static extern int CloseHandle(IntPtr hObject);
    }
}
