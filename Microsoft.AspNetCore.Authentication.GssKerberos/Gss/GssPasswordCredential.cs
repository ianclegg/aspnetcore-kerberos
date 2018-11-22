using System;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using static Microsoft.AspNetCore.Authentication.GssKerberos.Native.Krb5Interop;

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Gss
{
    internal class GssPasswordCredential : GssCredential
    {
        private IntPtr _credentials;

        public GssPasswordCredential(string principal, string password, CredentialUsage usage)
        {
            uint minorStatus = 0;
            uint majorStatus = 0;

            // copy the principal name to a gss_buffer
            using (var gssUsernameBuffer = GssBuffer.FromString(principal))
            using (var gssPasswordBuffer = GssBuffer.FromString(password))
            {
                // use the buffer to import the name into a gss_name
                majorStatus = gss_import_name(
                    out minorStatus,
                    ref gssUsernameBuffer.Value,
                    ref GssNtPrincipalName,
                    out var gssUsername
                );
                if (majorStatus != GSS_S_COMPLETE)
                    throw new GssException("The GSS provider was unable to import the supplied principal name",
                        majorStatus, minorStatus, GssNtHostBasedService);

                // attempt to obtain a TGT from the KDC using the supplied username and password
                var actualMechanims = default(GssOidDesc);

                //krb5_get_init_creds_password
                majorStatus = gss_acquire_cred_with_password(
                    out minorStatus,
                    gssUsername,
                    ref gssPasswordBuffer.Value,
                    0,
                    ref GssSpnegoMechOidSet,
                    (int)usage,
                    ref _credentials,
                    ref actualMechanims,
                    out var actualExpiry);

                // release the gss_name allocated by gss, the gss_buffer we allocated is free'd by the using block
                gss_release_name(out var _, ref gssUsername);

                if (majorStatus != GSS_S_COMPLETE)
                    throw new GssException("The GSS Provider was unable aquire credentials for authentication",
                        majorStatus, minorStatus, GssSpnegoMechOidDesc);
            }
        }

        protected internal override IntPtr Credentials => _credentials;

        public override void Dispose()
        {
            var majorStatus = gss_release_cred(out var minorStatus, ref _credentials);
            if (majorStatus != GSS_S_COMPLETE)
            {
                throw new GssException("The GSS provider was unable to release the credential handle",
                    majorStatus, minorStatus, GssNtHostBasedService);
            }
        }
    }
}