using System;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    internal class GssAuthenticationEvents
    {

        /// <summary>
        /// A delegate assigned to this property will be invoked when the credentials need validation.
        /// </summary>
        /// <remarks>
        /// You must provide a delegate for this property for authentication to occur.
        /// In your delegate you should construct an authentication principal from the user details,
        /// then create a new AuthenticationTicket using the principal, attach it to the
        /// context.AuthenticationTicket property and finally call context.HandleResponse();
        /// </remarks>
        public Func<GssAuthorizationContext, Task> OnAuthorise { get; set; } = context => Task.CompletedTask;


        public virtual Task Authorise(GssAuthorizationContext context) => OnAuthorise(context);
    }
}