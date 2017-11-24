using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssInitiator
    {
        private IntPtr initiatorCredentials;
        private IntPtr context;

        public GssInitiator(string TargetName)
        {
           //  gssTragetNameBuferr = GssBuffer.FromString()
        }

        public byte[] Initiate(Byte[] token)
        {
            //uint minorStatus = 0;
            //uint majorStatus = 0;


            //majorStatus = NativeMethods.gss_init_sec_context(
            //    out minorStatus,
            //    initiatorCredentials,
            //    ref context,
            //    IntPtr targetName, 

            return null;
        }
    }
}
