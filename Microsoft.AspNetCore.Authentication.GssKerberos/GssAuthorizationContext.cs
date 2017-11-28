using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssAuthorizationContext : ResultContext<GssAuthenticationOptions>
    {
        public GssAuthorizationContext(
            HttpContext context,
            AuthenticationScheme scheme,
            GssAuthenticationOptions options) : base(context, scheme, options)
        {
            this.Principal = new ClaimsPrincipal();
        }

        /// <summary>
        ///  The GSS Flags that were negociated during the GSS Context exchange
        /// </summary>
        public uint Flags { get; set; }
    }
}
