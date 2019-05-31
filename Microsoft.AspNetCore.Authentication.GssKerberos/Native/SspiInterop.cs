using System;
using System.Runtime.InteropServices;

#pragma warning disable IDE1006
// ReSharper disable InconsistentNaming
// ReSharper disable MemberHidesStaticFromOuterClass

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Native
{
    internal enum SecurityStatus
    {
        OK = 0x00000000
    }

    internal enum TokenInformationClass
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityHandle
    {
        public UIntPtr dwLower;
        public UIntPtr dwUpper;
    }

    public struct SecurityContextBuffer
    {
        public IntPtr Buffer;
    }

    public struct SecurityContextNamesBuffer
    {
        public IntPtr clientname;
        public IntPtr servername;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SEC_WINNT_AUTH_IDENTITY
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string User;
        public int UserLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Domain;
        public int DomainLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Password;
        public int PasswordLength;
        public uint Flags;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_GROUPS
    {
        public int GroupCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public SID_AND_ATTRIBUTES[] Groups;
    };

    internal static class SspiInterop
    {
        private const string SECUR32 = "secur32.dll";

        internal const uint SEC_WINNT_AUTH_IDENTITY_UNICODE = 0x00000002;
        internal const uint SE_GROUP_LOGON_ID = 0xC0000000;
        internal const int TokenGroups = 2;

        internal const uint ISC_REQ_REPLAY_DETECT = 0x00000004;
        internal const uint ISC_REQ_SEQUENCE_DETECT = 0x00000008;
        internal const uint ISC_REQ_CONNECTION = 0x00000800;
        internal const uint ISC_REQ_CONFIDENTIALITY = 0x00000010;
        internal const uint ISC_REQ_ALLOCATE_MEMORY = 0x00000100;
        internal const uint ISC_REQ_USE_SUPPLIED_CREDS = 0x00000080;

        internal const int SECURITY_NATIVE_DREP = 0x10;
        internal const int SECURITY_NETWORK_DREP = 0x00;

        public const int SECPKG_CRED_INBOUND = 1;
        public const int SECPKG_CRED_OUTBOUND = 2;
        public const int SECPKG_CRED_BOTH = 3;
        
        public const int SECURITY_STATUS_SUCCESS = 0;
        public const int SEC_E_OK = 0x0;
        public const int SEC_I_CONTINUE_NEEDED = 0x90312;
        public const int SEC_I_COMPLETE_AND_CONTINUE = 0x90314;

        public const int SECPKG_ATTR_NAMES = 1;
        public const int SECPKG_ATTR_NATIVE_NAMES = 13;
        public const int SECPKG_ATTR_ACCESS_TOKEN = 18;

        
        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int AcquireCredentialsHandle(
            IntPtr principal,
            string pszPackage,
            int fCredentialUse,
            IntPtr pvLogonID,
            IntPtr pAuthData,
            int pGetKeyFn,
            IntPtr pvGetKeyArgument,
            ref SecurityHandle phCredential,
            ref long ptsExpiry);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int AcquireCredentialsHandle(
            string pszPrincipal,
            string pszPackage,
            int fCredentialUse,
            IntPtr pvLogonID,
            SEC_WINNT_AUTH_IDENTITY pAuthData,
            int pGetKeyFn,
            IntPtr pvGetKeyArgument,
            ref SecurityHandle phCredential,
            ref long ptsExpiry);

        [DllImport(SECUR32, CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int AcceptSecurityContext(
            ref SecurityHandle phCredential,
            ref SecurityHandle phContext,
            [In,Out][MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(SecurityBufferMarshaler))]
            SecurityBufferDescription pInput,
            uint fContextReq,
            uint TargetDataRep,
            ref SecurityHandle phNewContext,
            [In,Out][MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(SecurityBufferMarshaler))]
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
            [In, Out][MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(SecurityBufferMarshaler))]
            SecurityBufferDescription pOutput,
            out uint pfContextAttr,
            out long timeStamp);

        [DllImport(SECUR32, CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int AcceptSecurityContext(
            ref SecurityHandle phCredential,
            IntPtr phContext,
            [In,Out][MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(SecurityBufferMarshaler))]
            SecurityBufferDescription pInput,
            uint fContextReq,
            uint TargetDataRep,
            ref SecurityHandle phNewContext,
            [In, Out][MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(SecurityBufferMarshaler))]
            SecurityBufferDescription pOutput,
            out uint pfContextAttr,
            out long timeStamp);

        [DllImport("secur32.dll", SetLastError=true)]
        public static extern int InitializeSecurityContext(
            ref SecurityHandle phCredential,
            IntPtr phContext,
            string pszTargetName,
            uint fContextReq,
            int Reserved1,
            uint TargetDataRep,
            IntPtr pInput,
            int Reserved2,
            ref SecurityHandle phNewContext,
            [In, Out][MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(SecurityBufferMarshaler))]
            SecurityBufferDescription pOutput,
            out uint pfContextAttr,
            out long timeStamp);


        [DllImport("secur32.Dll", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int QueryContextAttributes(
            ref SecurityHandle phContext,
            uint ulAttribute,
            IntPtr pContextAttributes);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr hToken,
            TokenInformationClass TokenInformationClass,
            IntPtr TokenInformation,
            int length,
            out int requiredLength);

        // Using IntPtr for pSID instead of Byte[]
        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport(SECUR32, ExactSpelling=true, SetLastError=true)]
        internal static extern int FreeContextBuffer(
            [In] IntPtr contextBuffer);

        [DllImport("kernel32.dll")]
        public static extern int CloseHandle(IntPtr hObject);
    }
}
