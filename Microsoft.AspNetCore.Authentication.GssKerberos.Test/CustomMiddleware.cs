using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Test
{
    public class CustomMiddleware
    {
        public CustomMiddleware(RequestDelegate next)
        {
        }

        public async Task Invoke(HttpContext context)
        {
            var result = await context.AuthenticateAsync(GssAuthenticationDefaults.AuthenticationScheme);
            if (!result.Succeeded)
            {
                await context.ChallengeAsync(GssAuthenticationDefaults.AuthenticationScheme);
            }
            else
            {
                context.Response.StatusCode = 200;
                await context.Response.WriteAsync($"User: {context.User.Identity.Name}\n");
                await context.Response.WriteAsync($"Is Authenticated: {context.User.Identity.IsAuthenticated}\n");
                await context.Response.WriteAsync($"Group SID's: {string.Join(",", context.User.Claims.Select(claim => claim.Value))}\n");
            }
        }
    }
}
