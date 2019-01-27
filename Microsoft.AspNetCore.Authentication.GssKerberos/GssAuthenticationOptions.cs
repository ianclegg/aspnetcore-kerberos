using System;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssAuthenticationOptions : AuthenticationSchemeOptions
    {
        public Func<IAcceptor> AcceptorFactory { get; set; }
    }
}