using System;
using System.Runtime.InteropServices;


#pragma warning disable IDE1006
// ReSharper disable InconsistentNaming
// ReSharper disable MemberHidesStaticFromOuterClass

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Native
{
    public static class Krb5Interop
    {
        #region GSS Constants
        internal const uint GSS_S_COMPLETE = 0x00000000;
        internal const uint GSS_S_CONTINUE_NEEDED = 0x00000001;

        internal const uint GSS_C_INDEFINITE = 0xffffffff;

        internal static IntPtr GSS_C_NO_BUFFER = new IntPtr(0);

        internal static GssOidDesc GSS_C_NO_OID = default(GssOidDesc);
        internal static GssOidSet GSS_C_NO_OID_SET = default(GssOidSet);
        #endregion

        #region GSS OIDs
        private static readonly byte[] GssNtHostBasedServiceOid = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04 };

        internal static GssOidDesc GssNtHostBasedService = new GssOidDesc
        {
            length = 10,
            elements = GCHandle.Alloc(GssNtHostBasedServiceOid, GCHandleType.Pinned).AddrOfPinnedObject()
        };
        
        private static readonly byte[] GssNtPrincipalNameOid = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01 };

        internal static GssOidDesc GssNtPrincipalName = new GssOidDesc
        {
            length = 10,
            elements = GCHandle.Alloc(GssNtPrincipalNameOid, GCHandleType.Pinned).AddrOfPinnedObject()
        };
        
        /// <summary>
        /// GSS_KRB5_MECH_OID_DESC
        /// </summary>
        private static readonly byte[] GssKrb5MechOid = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 };
        
        internal static GssOidDesc GssKrb5MechOidDesc = new GssOidDesc
        {
            length = 10,
            elements = GCHandle.Alloc(GssKrb5MechOid, GCHandleType.Pinned).AddrOfPinnedObject()
        };

        /// <summary>
        /// GSS_SPNEGO_MECH_OID_DESC
        /// </summary>
        internal static readonly byte[] GssSpnegoMechOid = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };

        internal static GssOidDesc GssSpnegoMechOidDesc = new GssOidDesc
        {
            length = 6,
            elements = GCHandle.Alloc(GssSpnegoMechOid, GCHandleType.Pinned).AddrOfPinnedObject()
        };
        
        /// <summary>
        /// GSS_SPNEGO_MECH_OID_DESC Set
        /// </summary>
        internal static GssOidSet GssSpnegoMechOidSet = new GssOidSet
        {
            count = 1,
            elements = GCHandle.Alloc(GssSpnegoMechOidDesc, GCHandleType.Pinned).AddrOfPinnedObject()
        };
        #endregion

        #region GSS Structures

        [StructLayout(LayoutKind.Sequential)]
        public struct GssOidSet
        {
            internal uint count;

            internal IntPtr elements;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct GssOidDesc
        {
            internal uint length;

            internal IntPtr elements;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct GssBufferStruct
        {
            /// size_t->unsigned int
            internal uint length;

            /// void*
            internal IntPtr value;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct GssBufferSet
        {
            /// size_t->unsigned int
           internal uint count;

            /// void*
            internal IntPtr elements;
        }
        #endregion

        #region  MIT Kerberos 5 GSS Platform Thunk

        internal static uint gss_import_name(
            out uint minorStatus,
            ref GssBufferStruct inputNameBuffer,
            ref GssOidDesc inputNameType,
            out IntPtr outputName)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_import_name(out minorStatus, ref inputNameBuffer, ref inputNameType, out outputName)
                    : Win32.gss_import_name(out minorStatus, ref inputNameBuffer, ref inputNameType, out outputName)
                : Linux.gss_import_name(out minorStatus, ref inputNameBuffer, ref inputNameType, out outputName);
        }

        internal static uint gss_acquire_cred(
            out uint minorStatus,
            IntPtr desiredName,
            uint timeRequired,
            ref GssOidSet desiredMechanisms,
            int credentialUsage,
            ref IntPtr credentialHandle,
            IntPtr actualMech,
            out uint expiryTime)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_acquire_cred(out minorStatus, desiredName, timeRequired, ref desiredMechanisms,
                        credentialUsage, ref credentialHandle, actualMech, out expiryTime)
                    : Win32.gss_acquire_cred(out minorStatus, desiredName, timeRequired, ref desiredMechanisms,
                        credentialUsage, ref credentialHandle, actualMech, out expiryTime)
                : Linux.gss_acquire_cred(out minorStatus, desiredName, timeRequired, ref desiredMechanisms,
                    credentialUsage, ref credentialHandle, actualMech, out expiryTime);
        }

        internal static uint gss_acquire_cred_with_password(
            out uint minorStatus,
            IntPtr desiredName,
            ref GssBufferStruct password,
            uint timeRequired,
            ref GssOidSet desiredMechanisms,
            int credentialUsage,
            ref IntPtr credentialHandle,
            IntPtr actualMechs,
            out uint expiryTime)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_acquire_cred_with_password(out minorStatus, desiredName, ref password, timeRequired,
                        ref desiredMechanisms, credentialUsage, ref credentialHandle, actualMechs, out expiryTime)
                    : Win32.gss_acquire_cred_with_password(out minorStatus, desiredName, ref password, timeRequired,
                        ref desiredMechanisms, credentialUsage, ref credentialHandle, actualMechs, out expiryTime)
                : Linux.gss_acquire_cred_with_password(out minorStatus, desiredName, ref password, timeRequired,
                    ref desiredMechanisms, credentialUsage, ref credentialHandle, actualMechs, out expiryTime);
        }

        internal static uint gss_inquire_name(
            out uint minorStatus,
            IntPtr name,
            out int mechName,
            out GssOidSet oids,
            out IntPtr attrs)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_inquire_name(out minorStatus, name, out mechName, out oids, out attrs)
                    : Win32.gss_inquire_name(out minorStatus, name, out mechName, out oids, out attrs)
                : Linux.gss_inquire_name(out minorStatus, name, out mechName, out oids, out attrs);
        }

        internal static uint gss_get_name_attribute(
            out uint minorStatus,
            IntPtr name,
            ref GssBufferStruct attribute,
            out int authenticated,
            out int complete,
            out GssBufferStruct value,
            out GssBufferStruct displayValue,
            ref int more)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_get_name_attribute(out minorStatus, name, ref attribute, out authenticated,
                        out complete, out value, out displayValue, ref more)
                    : Win32.gss_get_name_attribute(out minorStatus, name, ref attribute, out authenticated,
                        out complete, out value, out displayValue, ref more)
                : Linux.gss_get_name_attribute(out minorStatus, name, ref attribute, out authenticated, out complete,
                    out value, out displayValue, ref more);
        }

        internal static uint gss_init_sec_context(
            out uint minorStatus,
            IntPtr claimantCredHandle,
            ref IntPtr contextHandle,
            IntPtr targetName,
            ref GssOidDesc mechType,
            uint reqFlags,
            uint timeReq,
            IntPtr inputChanBindings,
            ref GssBufferStruct inputToken,
            IntPtr actualMechType,
            out GssBufferStruct outputToken,
            IntPtr retFlags,
            IntPtr timeRec)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_init_sec_context(out minorStatus, claimantCredHandle, ref contextHandle, targetName,
                        ref mechType, reqFlags, timeReq, inputChanBindings, ref inputToken, actualMechType,
                        out outputToken, retFlags, timeRec)
                    : Win32.gss_init_sec_context(out minorStatus, claimantCredHandle, ref contextHandle, targetName,
                        ref mechType, reqFlags, timeReq, inputChanBindings, ref inputToken, actualMechType,
                        out outputToken, retFlags, timeRec)
                : Linux.gss_init_sec_context(out minorStatus, claimantCredHandle, ref contextHandle, targetName,
                    ref mechType, reqFlags, timeReq, inputChanBindings, ref inputToken, actualMechType,
                    out outputToken, retFlags, timeRec);
        }

        internal static uint gss_accept_sec_context(
            out uint minorStatus,
            ref IntPtr contextHandle,
            IntPtr acceptorCredHandle,
            ref GssBufferStruct inputToken,
            IntPtr channelBindings,
            out IntPtr sourceName,
            IntPtr mechType,
            out GssBufferStruct outputToken,
            out uint retFlags,
            out uint timeRec,
            IntPtr delegated)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_accept_sec_context(out minorStatus, ref contextHandle, acceptorCredHandle,
                        ref inputToken, channelBindings, out sourceName, mechType, out outputToken, out retFlags,
                        out timeRec, delegated)
                    : Win32.gss_accept_sec_context(out minorStatus, ref contextHandle, acceptorCredHandle,
                        ref inputToken, channelBindings, out sourceName, mechType, out outputToken, out retFlags,
                        out timeRec, delegated)
                : Linux.gss_accept_sec_context(out minorStatus, ref contextHandle, acceptorCredHandle,
                    ref inputToken, channelBindings, out sourceName, mechType, out outputToken, out retFlags,
                    out timeRec, delegated);
        }

        internal static uint gss_display_name(
                out uint minorStatus,
                IntPtr inputName,
                out GssBufferStruct NameBuffer,
                out GssOidDesc nameType)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_display_name(out minorStatus, inputName, out NameBuffer, out nameType)
                    : Win32.gss_display_name(out minorStatus, inputName, out NameBuffer, out nameType)
                : Linux.gss_display_name(out minorStatus, inputName, out NameBuffer, out nameType);
        }

        internal static uint gss_display_status(
            out uint minorStatus,
            uint status,
            int statusType,
            ref GssOidDesc mechType,
            ref IntPtr messageContext,
            ref GssBufferStruct statusString)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_display_status(out minorStatus, status, statusType, ref mechType, ref messageContext,
                        ref statusString)
                    : Win32.gss_display_status(out minorStatus, status, statusType, ref mechType, ref messageContext,
                        ref statusString)
                : Linux.gss_display_status(out minorStatus, status, statusType, ref mechType, ref messageContext,
                    ref statusString);
        }

        internal static uint gss_release_buffer(
            out uint minorStatus,
            ref GssBufferStruct buffer)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_release_buffer(out minorStatus, ref buffer)
                    : Win32.gss_release_buffer(out minorStatus, ref buffer)
                : Linux.gss_release_buffer(out minorStatus, ref buffer);
        }

        internal static uint gss_delete_sec_context(
            out uint minorStatus,
            ref IntPtr contextHandle)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
           ? Environment.Is64BitProcess
               ? Win64.gss_delete_sec_context(out minorStatus, ref contextHandle, GSS_C_NO_BUFFER)
               : Win32.gss_delete_sec_context(out minorStatus, ref contextHandle, GSS_C_NO_BUFFER)
           : Linux.gss_delete_sec_context(out minorStatus, ref contextHandle, GSS_C_NO_BUFFER);
        }

        internal static uint gss_release_name(
            out uint minorStatus,
            ref IntPtr inputName)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_release_name(out minorStatus, ref inputName)
                    : Win32.gss_release_name(out minorStatus, ref inputName)
                : Linux.gss_release_name(out minorStatus, ref inputName);
        }

        internal static uint gss_release_cred(
            out uint minorStatus,
            ref IntPtr credentialHandle)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_release_cred(out minorStatus, ref credentialHandle)
                    : Win32.gss_release_cred(out minorStatus, ref credentialHandle)
                : Linux.gss_release_cred(out minorStatus, ref credentialHandle);
        }

        #endregion

        #region MIT Kerberos 5 GSS Bindings Windows 32bit
        private static class Win32
        {
            private const string GssModulename = "gssapi32.dll";

            [DllImport(GssModulename, EntryPoint = "gss_import_name")]

            internal static extern uint gss_import_name(
                out uint minorStatus,
                ref GssBufferStruct inputNameBuffer,
                ref GssOidDesc inputNameType,
                out IntPtr outputName);

            [DllImport(GssModulename, EntryPoint = "gss_acquire_cred")]
            internal static extern uint gss_acquire_cred(
                out uint minorStatus,
                IntPtr desiredName,
                uint timeRequired,
                ref GssOidSet desiredMechanisms,
                int credentialUsage,
                ref IntPtr credentialHandle,
                IntPtr actualMech,
                out uint expiryTime);

            [DllImport(GssModulename, EntryPoint = "gss_acquire_cred_with_password")]
            internal static extern uint gss_acquire_cred_with_password(
                out uint minorStatus,
                IntPtr desiredName,
                ref GssBufferStruct password,
                uint timeRequired,
                ref GssOidSet desiredMechanisms,
                int credentialUsage,
                ref IntPtr credentialHandle,
                IntPtr actualMechs,
                out uint expiryTime);

            [DllImport(GssModulename, EntryPoint = "gss_inquire_name")]
            internal static extern uint gss_inquire_name(
                out uint minorStatus,
                IntPtr name,
                out int mechName,
                out GssOidSet oids,
                out IntPtr attrs);

            [DllImport(GssModulename, EntryPoint = "gss_get_name_attribute")]
            internal static extern uint gss_get_name_attribute(
                out uint minorStatus,
                IntPtr name,
                ref GssBufferStruct attribute,
                out int authenticated,
                out int complete,
                out GssBufferStruct value,
                out GssBufferStruct displayValue,
                ref int more);

            [DllImport(GssModulename, EntryPoint = "gss_init_sec_context")]
            internal static extern uint gss_init_sec_context(
                out uint minorStatus,
                IntPtr claimantCredHandle,
                ref IntPtr contextHandle,
                IntPtr targetName,
                ref GssOidDesc mechType,
                uint reqFlags,
                uint timeReq,
                IntPtr inputChanBindings,
                ref GssBufferStruct inputToken,
                IntPtr actualMechType,
                out GssBufferStruct outputToken,
                IntPtr retFlags,
                IntPtr timeRec);

            [DllImport(GssModulename, EntryPoint = "gss_accept_sec_context")]
            internal static extern uint gss_accept_sec_context(
                out uint minorStatus,
                ref IntPtr contextHandle,
                IntPtr acceptorCredHandle,
                ref GssBufferStruct inputToken,
                IntPtr channelBindings,
                out IntPtr sourceName,
                IntPtr mechType,
                out GssBufferStruct outputToken,
                out uint retFlags,
                out uint timeRec,
                IntPtr delegated);

            [DllImport(GssModulename, EntryPoint = "gss_display_name")]
            internal static extern uint gss_display_name(
                out uint minorStatus,
                IntPtr inputName,
                out GssBufferStruct NameBuffer,
                out GssOidDesc nameType);

            [DllImport(GssModulename, EntryPoint = "gss_display_status")]
            internal static extern uint gss_display_status(
                out uint minorStatus,
                uint status,
                int statusType,
                ref GssOidDesc mechType,
                ref IntPtr messageContext,
                ref GssBufferStruct statusString);

            [DllImport(GssModulename, EntryPoint = "gss_release_buffer")]
            internal static extern uint gss_release_buffer(
                out uint minorStatus,
                ref GssBufferStruct buffer);

            [DllImport(GssModulename, EntryPoint = "gss_release_cred")]
            internal static extern uint gss_release_cred(
                out uint minorStatus,
                ref IntPtr credentialHandle);

            [DllImport(GssModulename, EntryPoint = "gss_release_name")]
            internal static extern uint gss_release_name(
                out uint minorStatus,
                ref IntPtr inputName);

            [DllImport(GssModulename, EntryPoint = "gss_delete_sec_context")]
            internal static extern uint gss_delete_sec_context(
                out uint minorStatus,
                ref IntPtr contextHandle,
                IntPtr outputToken);
        }
        #endregion

        #region MIT Kerberos 5 GSS Bindings Windows 64bit
        private static class Win64
        {
            private const string GssModulename = "gssapi64.dll";

            [DllImport(GssModulename, EntryPoint = "gss_import_name")]
            internal static extern uint gss_import_name(
                out uint minorStatus,
                ref GssBufferStruct inputNameBuffer,
                ref GssOidDesc inputNameType,
                out IntPtr outputName);

            [DllImport(GssModulename, EntryPoint = "gss_acquire_cred")]
            internal static extern uint gss_acquire_cred(
                out uint minorStatus,
                IntPtr desiredName,
                uint timeRequired,
                ref GssOidSet desiredMechanisms,
                int credentialUsage,
                ref IntPtr credentialHandle,
                IntPtr actualMechs,
                out uint expiryTime);

            [DllImport(GssModulename, EntryPoint = "gss_acquire_cred_with_password")]
            internal static extern uint gss_acquire_cred_with_password(
                out uint minorStatus,
                IntPtr desiredName,
                ref GssBufferStruct password,
                uint timeRequired,
                ref GssOidSet desiredMechanisms,
                int credentialUsage,
                ref IntPtr credentialHandle,
                IntPtr actualMech,
                out uint expiryTime);

            [DllImport(GssModulename, EntryPoint = "gss_inquire_name")]
            internal static extern uint gss_inquire_name(
                out uint minorStatus,
                IntPtr name,
                out int mechName,
                out GssOidSet oids,
                out IntPtr attrs);

            [DllImport(GssModulename, EntryPoint = "gss_get_name_attribute")]
            internal static extern uint gss_get_name_attribute(
                out uint minorStatus,
                IntPtr name,
                ref GssBufferStruct attribute,
                out int authenticated,
                out int complete,
                out GssBufferStruct value,
                out GssBufferStruct displayValue,
                ref int more);

            [DllImport(GssModulename, EntryPoint = "gss_init_sec_context")]
            internal static extern uint gss_init_sec_context(
                out uint minorStatus,
                IntPtr claimantCredHandle,
                ref IntPtr contextHandle,
                IntPtr targetName,
                ref GssOidDesc mechType,
                uint reqFlags,
                uint timeReq,
                IntPtr inputChanBindings,
                ref GssBufferStruct inputToken,
                IntPtr actualMechType,
                out GssBufferStruct outputToken,
                IntPtr retFlags,
                IntPtr timeRec);

            [DllImport(GssModulename, EntryPoint = "gss_accept_sec_context")]
            internal static extern uint gss_accept_sec_context(
                out uint minorStatus,
                ref IntPtr contextHandle,
                IntPtr acceptorCredHandle,
                ref GssBufferStruct inputToken,
                IntPtr channelBindings,
                out IntPtr sourceName,
                IntPtr mechType,
                out GssBufferStruct outputToken,
                out uint retFlags,
                out uint timeRec,
                IntPtr delegated);

            [DllImport(GssModulename, EntryPoint = "gss_display_name")]
            internal static extern uint gss_display_name(
                out uint minorStatus,
                IntPtr inputName,
                out GssBufferStruct NameBuffer,
                out GssOidDesc nameType);

            [DllImport(GssModulename, EntryPoint = "gss_display_status")]
            internal static extern uint gss_display_status(
                out uint minorStatus,
                uint status,
                int statusType,
                ref GssOidDesc mechType,
                ref IntPtr messageContext,
                ref GssBufferStruct statusString);

            [DllImport(GssModulename, EntryPoint = "gss_release_buffer")]
            internal static extern uint gss_release_buffer(
                out uint minorStatus,
                ref GssBufferStruct buffer);

            [DllImport(GssModulename, EntryPoint = "gss_release_cred")]
            internal static extern uint gss_release_cred(
                out uint minorStatus,
                ref IntPtr credentialHandle);

            [DllImport(GssModulename, EntryPoint = "gss_release_name")]
            internal static extern uint gss_release_name(
                out uint minorStatus,
                ref IntPtr inputName);

            [DllImport(GssModulename, EntryPoint = "gss_delete_sec_context")]
            internal static extern uint gss_delete_sec_context(
                out uint minorStatus,
                ref IntPtr contextHandle,
                IntPtr outputToken);
        }
        #endregion

        #region Linux MIT Kerberos 5 GSS Bindings

        private static class Linux
        {
            private const string GssModulename = "libgssapi_krb5.so.2";

            [DllImport(GssModulename, EntryPoint = "gss_import_name")]
            internal static extern uint gss_import_name(
                out uint minorStatus,
                ref GssBufferStruct inputNameBuffer,
                ref GssOidDesc inputNameType,
                out IntPtr outputName);


            [DllImport(GssModulename, EntryPoint = "gss_acquire_cred")]
            internal static extern uint gss_acquire_cred(
                out uint minorStatus,
                IntPtr desiredName,
                uint timeRequired,
                ref GssOidSet desiredMechanisms,
                int credentialUsage,
                ref IntPtr credentialHandle,
                IntPtr actualMech,
                out uint expiryTime);

            [DllImport(GssModulename, EntryPoint = "gss_acquire_cred_with_password")]
            internal static extern uint gss_acquire_cred_with_password(
                out uint minorStatus,
                IntPtr desiredName,
                ref GssBufferStruct password,
                uint timeRequired,
                ref GssOidSet desiredMechanisms,
                int credentialUsage,
                ref IntPtr credentialHandle,
                IntPtr actualMechs,
                out uint expiryTime);

            [DllImport(GssModulename, EntryPoint = "gss_inquire_name")]
            internal static extern uint gss_inquire_name(
                out uint minorStatus,
                IntPtr name,
                out int mechName,
                out GssOidSet oids,
                out IntPtr attrs);

            [DllImport(GssModulename, EntryPoint = "gss_get_name_attribute")]
            internal static extern uint gss_get_name_attribute(
                out uint minorStatus,
                IntPtr name,
                ref GssBufferStruct attribute,
                out int authenticated,
                out int complete,
                out GssBufferStruct value,
                out GssBufferStruct displayValue,
                ref int more);

            [DllImport(GssModulename, EntryPoint = "gss_init_sec_context")]
            internal static extern uint gss_init_sec_context(
                out uint minorStatus,
                IntPtr claimantCredHandle,
                ref IntPtr contextHandle,
                IntPtr targetName,
                ref GssOidDesc mechType,
                uint reqFlags,
                uint timeReq,
                IntPtr inputChanBindings,
                ref GssBufferStruct inputToken,
                IntPtr actualMechType,
                out GssBufferStruct outputToken,
                IntPtr retFlags,
                IntPtr timeRec);

            [DllImport(GssModulename, EntryPoint = "gss_accept_sec_context")]
            internal static extern uint gss_accept_sec_context(
                out uint minorStatus,
                ref IntPtr contextHandle,
                IntPtr acceptorCredHandle,
                ref GssBufferStruct inputToken,
                IntPtr channelBindings,
                out IntPtr sourceName,
                IntPtr mechType,
                out GssBufferStruct outputToken,
                out uint retFlags,
                out uint timeRec,
                IntPtr delegated);

            [DllImport(GssModulename, EntryPoint = "gss_display_name")]
            internal static extern uint gss_display_name(
                out uint minorStatus,
                IntPtr inputName,
                out GssBufferStruct NameBuffer,
                out GssOidDesc nameType);

            [DllImport(GssModulename, EntryPoint = "gss_display_status")]
            internal static extern uint gss_display_status(
                out uint minorStatus,
                uint status,
                int statusType,
                ref GssOidDesc mechType,
                ref IntPtr messageContext,
                ref GssBufferStruct statusString);

            [DllImport(GssModulename, EntryPoint = "gss_release_buffer")]
            internal static extern uint gss_release_buffer(
                out uint minorStatus,
                ref GssBufferStruct buffer);

            [DllImport(GssModulename, EntryPoint = "gss_release_cred")]
            internal static extern uint gss_release_cred(
                out uint minorStatus,
                ref IntPtr credentialHandle);

            [DllImport(GssModulename, EntryPoint = "gss_release_name")]
            internal static extern uint gss_release_name(
                out uint minorStatus,
                ref IntPtr inputName);

            [DllImport(GssModulename, EntryPoint = "gss_delete_sec_context")]
            internal static extern uint gss_delete_sec_context(
                out uint minorStatus,
                ref IntPtr contextHandle,
                IntPtr outputToken);
        }
        #endregion
    }
}
