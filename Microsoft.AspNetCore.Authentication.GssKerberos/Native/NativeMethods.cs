using System;
using System.Net;
using System.Runtime.InteropServices;

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Native
{
    public static class NativeMethods
    {
        #region GSS OIDs
        private static readonly byte[] GssNtServiceName = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04 };

        internal static GssOidDescStruct GssNtServiceNameStruct = new GssOidDescStruct
        {
            elements = Marshal.UnsafeAddrOfPinnedArrayElement(GssNtServiceName, 0),
            length = 10
        };
        
        /// <summary>
        /// GSS_KRB5_MECH_OID_DESC
        /// </summary>
        private static readonly byte[] GssKrb5MechOidDesc = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 };
        
        internal static GssOidDescStruct GssKrb5MechOidDescStruct = new GssOidDescStruct
        {
            elements = Marshal.UnsafeAddrOfPinnedArrayElement(GssKrb5MechOidDesc, 0),
            length = 10
        };
        #endregion
        
        #region GSS Structures
        [StructLayout(LayoutKind.Sequential)]
        public struct GssOidDescStruct
        {
            /// OM_uint32->gss_uint32->unsigned int
            internal uint length;

            /// void*
            internal IntPtr elements;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct GssBufferDescStruct
        {
            /// size_t->unsigned int
            internal uint length;

            /// void*
            internal IntPtr value;
        }
        #endregion
        
        #region MIT Kerberos GSS Functions
        /// <summary>
        /// Converts a contiguous string name to GSS_API internal format
        /// <para>The gss_import_name() function converts a contiguous string name to internal form. In general, the internal name returned by means of the output_name parameter will not be a mechanism name; the exception to this is if the input_name_type indicates that the contiguous string provided by means of the input_name_buffer parameter is of type GSS_C_NT_EXPORT_NAME, in which case, the returned internal name will be a mechanism name for the mechanism that exported the name.</para>
        /// </summary>
        /// <param name="minorStatus">Status code returned by the underlying mechanism.</param>
        /// <param name="inputNameBuffer">The gss_buffer_desc structure containing the name to be imported.</param>
        /// <param name="inputNameType">A gss_OID that specifies the format that the input_name_buffer is in.</param>
        /// <param name="outputName">The gss_name_t structure to receive the returned name in internal form. Storage associated with this name must be freed by the application after use with a call to gss_release_name().</param>
        /// <returns>
        /// <para>The gss_import_name() function may return the following status codes:</para>
        /// <para></para>
        /// <para>GSS_S_COMPLETE</para>
        /// <para>The gss_import_name() function completed successfully.</para>
        /// <para></para>
        /// <para>GSS_S_BAD_NAMETYPE</para>
        /// <para>The input_name_type was unrecognized.</para>
        /// <para></para>
        /// <para>GSS_S_BAD_NAME</para>
        /// <para>The input_name parameter could not be interpreted as a name of the specified type.</para>
        /// <para></para>
        /// <para>GSS_S_BAD_MECH</para>
        /// <para>The input_name_type was GSS_C_NT_EXPORT_NAME, but the mechanism contained within the input_name is not supported.</para>
        /// <para></para>
        /// <para>GSS_S_FAILURE</para>
        /// <para>The underlying mechanism detected an error for which no specific GSS status code is defined. The mechanism-specific status code reported by means of the minor_status parameter details the error condition.</para>
        /// </returns>
        [DllImport("libgssapi_krb5.so.2", EntryPoint = "gss_import_name")]
        internal static extern uint gss_import_name(
            ref uint minorStatus,
            ref GssBufferDescStruct inputNameBuffer,
            ref GssOidDescStruct inputNameType,
            ref IntPtr outputName);


        /// <summary>
        /// Initiates a GSS-API security context with a peer application
        /// <para>The gss_init_sec_context() function initiates the establishment of a security context between the application and a remote peer. Initially, the input_token parameter should be specified either as GSS_C_NO_BUFFER, or as a pointer to a gss_buffer_desc object with a length field that contains a zero value. The routine may return a output_token, which should be transferred to the peer application, which will present it to gss_accept_sec_context. If no token need be sent, gss_init_sec_context() will indicate this by setting the length field of the output_token argument to zero. To complete context establishment, one or more reply tokens may be required from the peer application; if so, gss_init_sec_context() will return a status code that contains the supplementary information bit GSS_S_CONTINUE_NEEDED . In this case, make another call to gss_init_sec_context() when the reply token is received from the peer application and pass the reply token to gss_init_sec_context() by means of the input_token parameter.</para>
        /// <para></para>
        /// <para>Construct portable applications to use the token length and return status to determine whether to send or wait for a token.</para>
        /// <para></para>
        /// <para>Whenever the routine returns a major status that includes the value GSS_S_CONTINUE_NEEDED, the context is not fully established, and the following restrictions apply to the output parameters:</para>
        /// <para></para>
        /// <para> - The value returned by means of the time_rec parameter is undefined. Unless the accompanying ret_flags parameter contains the bit GSS_C_PROT_READY_FLAG, which indicates that per-message services may be applied in advance of a successful completion status, the value returned by means of the actual_mech_type parameter is undefined until the routine returns a major status value of GSS_S_COMPLETE.</para>
        /// <para></para>
        /// <para> - The values of the GSS_C_DELEG_FLAG, GSS_C_MUTUAL_FLAG, GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG, GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG and GSS_C_ANON_FLAG bits returned by the ret_flags parameter contain values that will be valid if context establishment succeeds. For example, if the application requests a service such as delegation or anonymous authentication by means of the req_flags argument, and the service is unavailable from the underlying mechanism, gss_init_sec_context() generates a token that will not provide the service, and it indicate by means of the ret_flags argument that the service will not be supported. The application may choose to abort context establishment by calling gss_delete_sec_context if it cannot continue without the service, or if the service was merely desired but not mandatory, it may transmit the token and continue context establishment.</para>
        /// <para></para>
        /// <para> - The values of the GSS_C_PROT_READY_FLAG and GSS_C_TRANS_FLAG bits within ret_flags indicate the actual state at the time gss_init_sec_context() returns, whether or not the context is fully established.</para>
        /// <para></para>
        /// <para> - The GSS-API sets the GSS_C_PROT_READY_FLAG in the final ret_flags returned to a caller, for example, when accompanied by a GSS_S_COMPLETE status code. However, applications should not rely on this behavior, as the flag was not defined in Version 1 of the GSS-API. Instead, applications should determine what per-message services are available after a successful context establishment according to the GSS_C_INTEG_FLAG and GSS_C_CONF_FLAG values.</para>
        /// <para></para>
        /// <para> - All other bits within the ret_flags argument are set to zero.</para>
        /// <para></para>
        /// <para>If the initial call of gss_init_sec_context() fails, the GSS-API does not create a context object; it leaves the value of the context_handle parameter set to GSS_C_NO_CONTEXT to indicate this. In the event of failure on a subsequent call, the GSS-API leaves the security context untouched for the application to delete using gss_delete_sec_context.</para>
        /// <para></para>
        /// <para>During context establishment, the informational status bits GSS_S_OLD_TOKEN and GSS_S_DUPLICATE_TOKEN indicate fatal errors, and GSS-API mechanisms should always return them in association with a status code of GSS_S_FAILURE. This pairing requirement was not part of Version 1 of the GSS-API specification, so applications that wish to run on Version 1 implementations must special-case these codes.</para>
        /// </summary>
        /// <param name="minorStatus">A mechanism specific status code.</param>
        /// <param name="claimantCredHandle">The handle for the credentials claimed. Supply GSS_C_NO_CREDENTIAL to act as a default initiator principal. If no default initiator is defined, the function returns GSS_S_NO_CRED.</param>
        /// <param name="contextHandle">The context handle for a new context. Supply the value GSS_C_NO_CONTEXT for the first call, and use the value returned in any continuation calls. The resources associated with context_handle must be released by the application after use by a call to gss_delete_sec_context.</param>
        /// <param name="targetName">The name of the context acceptor.</param>
        /// <param name="mechType">The object ID of the desired mechanism. To obtain a specific default, supply the value GSS_C_NO_OID.</param>
        /// <param name="reqFlags">Contains independent flags, each of which will request that the context support a specific service option. A symbolic name is provided for each flag. Logically-OR the symbolic name to the corresponding required flag to form the bit-mask value.</param>
        /// <param name="timeReq">The number of seconds for which the context will remain valid. Supply a zero value to time_req to request a default validity period.</param>
        /// <param name="inputChanBindings">Optional application-specified bindings. Allows application to securely bind channel identification information to the security context. Set to GSS_C_NO_CHANNEL_BINDINGS if you do not want to use channel bindings.</param>
        /// <param name="inputToken">Token received from the peer application. On the initial call, supply GSS_C_NO_BUFFER or a pointer to a buffer containing the value GSS_C_EMPTY_BUFFER.</param>
        /// <param name="actualMechType">The actual mechanism used. The OID returned by means of this parameter will be pointer to static storage that should be treated as read-only. The application should not attempt to free it. To obtain a specific default, supply the value GSS_C_NO_OID. Specify NULL if the parameter is not required.</param>
        /// <param name="outputToken">The token to send to the peer application. If the length field of the returned buffer is zero, no token need be sent to the peer application. After use storage associated with this buffer must be freed by the application by a call to gss_release_buffer.</param>
        /// <param name="retFlags">Contains various independent flags, each of which indicates that the context supports a specific service option. If not needed, specify NULL. Test the returned bit-mask ret_flags value against its symbolic name to determine if the given option is supported by the context.</param>
        /// <param name="timeRec">The number of seconds for which the context will remain valid. Specify NULL if the parameter is not required.</param>
        /// <returns>
        /// <para>gss_init_sec_context() may return the following status codes:</para>
        /// <para></para>
        /// <para>GSS_S_COMPLETE</para>
        /// <para>Successful completion.</para>
        /// <para></para>
        /// <para>GSS_S_CONTINUE_NEEDED</para>
        /// <para>A token from the peer application is required to complete the context, and gss_init_sec_context() must be called again with that token.</para>
        /// <para></para>
        /// <para>GSS_S_DEFECTIVE_TOKEN</para>
        /// <para>Consistency checks performed on the input_token failed.</para>
        /// <para></para>
        /// <para>GSS_S_DEFECTIVE_CREDENTIAL</para>
        /// <para>Consistency checks performed on the credential failed.</para>
        /// <para></para>
        /// <para>GSS_S_NO_CRED</para>
        /// <para>The supplied credentials are not valid for context acceptance, or the credential handle does not reference any credentials.</para>
        /// <para></para>
        /// <para>GSS_S_CREDENTIALS_EXPIRED</para>
        /// <para>The referenced credentials have expired.</para>
        /// <para></para>
        /// <para>GSS_S_BAD_BINDINGS</para>
        /// <para>The input_token contains different channel bindings than those specified by means of the input_chan_bindings parameter.</para>
        /// <para></para>
        /// <para>GSS_S_BAD_SIG</para>
        /// <para>The input_token contains an invalid MIC or a MIC that cannot be verified.</para>
        /// <para></para>
        /// <para>GSS_S_OLD_TOKEN</para>
        /// <para>The input_token is too old. This is a fatal error while establishing context.</para>
        /// <para></para>
        /// <para>GSS_S_DUPLICATE_TOKEN</para>
        /// <para>The input_token is valid, but it is a duplicate of a token already processed.This is a fatal error while establishing context.</para>
        /// <para></para>
        /// <para>GSS_S_NO_CONTEXT</para>
        /// <para>The supplied context handle does not refer to a valid context.</para>
        /// <para></para>
        /// <para>GSS_S_BAD_NAMETYPE</para>
        /// <para>The provided target_name parameter contains an invalid or unsupported name type.</para>
        /// <para></para>
        /// <para>GSS_S_BAD_NAME</para>
        /// <para>The supplied target_name parameter is ill-formed.</para>
        /// <para></para>
        /// <para>GSS_S_BAD_MECH</para>
        /// <para>The token received specifies a mechanism that is not supported by the implementation or the provided credential.</para>
        /// <para></para>
        /// <para>GSS_S_FAILURE</para>
        /// <para>The underlying mechanism detected an error for which no specific GSS status code is defined.The mechanism-specific status code reported by means of the minor_status parameter details the error condition.</para>
        /// </returns>
        [DllImport("libgssapi_krb5.so.2", EntryPoint = "gss_init_sec_context")]
        internal static extern uint gss_init_sec_context(
            ref uint minorStatus,
            IntPtr claimantCredHandle,
            ref IntPtr contextHandle, 
            IntPtr targetName,
            ref GssOidDescStruct mechType,
            uint reqFlags,
            uint timeReq,
            IntPtr inputChanBindings,
            ref GssBufferDescStruct inputToken,
            IntPtr actualMechType,
            ref GssBufferDescStruct outputToken,
            IntPtr retFlags,
            IntPtr timeRec);


        /// <summary>
        /// Frees buffer storage allocated by a GSS-API function
        /// <para>The gss_release_buffer() function frees buffer storage allocated by a GSS-API function. The gss_release_buffer() function also zeros the length field in the descriptor to which the buffer parameter refers, while the GSS-API function sets the pointer field in the descriptor to NULL. Any buffer object returned by a GSS-API function may be passed to gss_release_buffer(), even if no storage is associated with the buffer.</para>
        /// </summary>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <param name="buffer">The storage associated with the buffer will be deleted. The gss_buffer_desc() object will not be freed; however, its length field will be zeroed.</param>
        /// <returns>
        /// <para>The gss_release_buffer() function may return the following status codes:</para>
        /// <para></para>
        /// <para>GSS_S_COMPLETE</para>
        /// <para>Successful completion</para>
        /// <para></para>
        /// <para>GSS_S_FAILURE</para>
        /// <para>The underlying mechanism detected an error for which no specific GSS status code is defined. The mechanism-specific status code reported by means of the minor_status parameter details the error condition.</para>
        /// </returns>
        [DllImport("libgssapi_krb5.so.2", EntryPoint = "gss_release_buffer")]
        internal static extern uint gss_release_buffer(
            ref uint minorStatus,
            ref GssBufferDescStruct buffer);

        /// <summary>
        /// Deletes a GSS-API security context
        /// <para>Use the gss_delete_sec_context() function to delete a security context. The gss_delete_sec_context() function will delete the local data structures associated with the specified security context. You may not obtain further security services that use the context specified by context_handle.</para>
        /// <para></para>
        /// <para>In addition to deleting established security contexts, gss_delete_sec_context() will delete any half-built security contexts that result from incomplete sequences of calls to gss_init_sec_context and gss_accept_sec_context.</para>
        /// <para></para>
        /// <para>The Solaris implementation of the GSS-API retains the output_token parameter for compatibility with version 1 of the GSS-API. Both peer applications should invoke gss_delete_sec_context(), passing the value GSS_C_NO_BUFFER to the output_token parameter; this indicates that no token is required. If the application passes a valid buffer to gss_delete_sec_context(), it will return a zero-length token, indicating that no token should be transferred by the application.</para>
        /// </summary>
        /// <param name="minorStatus">A mechanism specific status code.</param>
        /// <param name="contextHandle">Context handle identifying specific context to delete. After deleting the context, the GSS-API will set context_handle to GSS_C_NO_CONTEXT.</param>
        /// <param name="outputToken">A token to be sent to remote applications that instructs them to delete the context.</param>
        /// <returns>
        /// <para>gss_delete_sec_context() may return the following status codes:</para>
        /// <para></para>
        /// <para>GSS_S_COMPLETE</para>
        /// <para>Successful completion.</para>
        /// <para></para>
        /// <para>GSS_S_NO_CONTEXT</para>
        /// <para>No valid context was supplied.</para>
        /// <para></para>
        /// <para>GSS_S_FAILURE</para>
        /// <para>The underlying mechanism detected an error for which no specific GSS status code is defined. The mechanism-specific status code reported by means of the minor_status parameter details the error condition.</para>
        /// </returns>
        [DllImport("libgssapi_krb5.so.2", EntryPoint = "gss_release_buffer")]
        internal static extern uint gss_delete_sec_context(
            ref uint minorStatus,
            ref IntPtr contextHandle,
            IntPtr outputToken);
        

        /// <summary>
        /// Discards an internal-form name
        /// <para>The gss_release_name() function frees GSS-API-allocated storage associated with an internal-form name. The name is set to GSS_C_NO_NAME on successful completion of this call.</para>
        /// </summary>
        /// <param name="minorStatus">A mechanism-specific status code.</param>
        /// <param name="inputName">The name to be deleted.</param>
        /// <returns>
        /// <para>The gss_release_name() function may return the following status codes:</para>
        /// <para></para>
        /// <para>GSS_S_COMPLETE</para>
        /// <para>Successful completion.</para>
        /// <para></para>
        /// <para>GSS_S_BAD_NAME</para>
        /// <para>The name parameter did not contain a valid name.</para>
        /// <para></para>
        /// <para>GSS_S_FAILURE</para>
        /// <para>The underlying mechanism detected an error for which no specific GSS status code is defined. The mechanism-specific status code reported by means of the minor_status parameter details the error condition.</para>
        /// </returns>
        [DllImport("libgssapi_krb5.so.2", EntryPoint = "gss_release_name")]
        internal static extern uint gss_release_name(
            ref uint minorStatus,
            ref IntPtr inputName);

        #endregion
    }
}
