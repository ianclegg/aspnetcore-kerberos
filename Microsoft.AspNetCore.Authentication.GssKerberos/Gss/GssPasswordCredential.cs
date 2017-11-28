using System;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Gss
{
    internal class GssPasswordCredential : GssCredential
    {
        private readonly IntPtr _credentials;

        public GssPasswordCredential(string principal, string password, CredentialUsage usage)
        {
            uint minorStatus = 0;
            uint majorStatus = 0;

            // copy the principal name to a gss_buffer
            using (var gssUsernameBuffer = GssBuffer.FromString(principal))
            using (var gssPasswordBuffer = GssBuffer.FromString(password))
            {
                // use the buffer to import the name into a gss_name
                majorStatus = NativeMethods.gss_import_name(
                    out minorStatus,
                    ref gssUsernameBuffer.Value,
                    ref NativeMethods.GssNtPrincipalName,
                    out var gssUsername
                );
                if (majorStatus != NativeMethods.GSS_S_COMPLETE)
                    throw new GssException("The GSS provider was unable to import the supplied principal name",
                        majorStatus, minorStatus, NativeMethods.GssNtHostBasedService);

                // attempt to obtain a TGT from the KDC using the supplied username and password
                var actualMechanims = default(NativeMethods.GssOidDesc);

                majorStatus = NativeMethods.gss_acquire_cred_with_password(
                    out minorStatus,
                    gssUsername,
                    ref gssPasswordBuffer.Value,
                    0xffffffff,
                    ref NativeMethods.GssSpnegoMechOidSet,
                    (int)usage,
                    ref _credentials,
                    ref actualMechanims,
                    out var actualExpiry);

                // release the gss_name allocated by gss, the gss_buffer we allocated is free'd by the using block
                NativeMethods.gss_release_name(out var _, ref gssUsername);

                if (majorStatus != NativeMethods.GSS_S_COMPLETE)
                    throw new GssException("The GSS Provider was unable aquire credentials for authentication",
                        majorStatus, minorStatus, NativeMethods.GssSpnegoMechOidDesc);
            }
        }

        protected internal override IntPtr Credentials => _credentials;
        public override void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}