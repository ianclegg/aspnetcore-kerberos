using System;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.GssKerberos.Gss;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    internal class GssAuthenticationHandler : AuthenticationHandler<GssAuthenticationOptions>
    {
        private const string SchemeName = "Negotiate";

        public GssAuthenticationHandler(
            IOptionsMonitor<GssAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        protected new GssAuthenticationEvents Events
        {
            get => (GssAuthenticationEvents)base.Events;
            set => base.Events = value;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string authorizationHeader = Request.Headers["Authorization"];
            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return Task.FromResult(AuthenticateResult.Fail("Authorization header missing"));
            }

            if (!authorizationHeader.StartsWith("Negotiate ", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(AuthenticateResult.Fail("not me"));
            }

            var base64Token = authorizationHeader.Substring(SchemeName.Length).Trim();

            if (string.IsNullOrEmpty(base64Token))
            {
                const string noCredentialsMessage = "No credentials";
                Logger.LogInformation(noCredentialsMessage);
                return Task.FromResult(AuthenticateResult.Fail(noCredentialsMessage));
            }

            try
            {
                var asn1ServiceTicket = Convert.FromBase64String(base64Token);
                using (var acceptor = new GssAcceptor(Options.Credential))
                {
                    acceptor.Accept(asn1ServiceTicket);
                    if (acceptor.IsEstablished)
                    {
                        var ticket = new AuthenticationTicket(
                            new GenericPrincipal(new GenericIdentity(acceptor.Principal), 
                                new[] { "User" }),
                            new AuthenticationProperties(),
                            GssAuthenticationDefaults.AuthenticationScheme);

                        return Task.FromResult(AuthenticateResult.Success(ticket));
                    }
                    return Task.FromResult(AuthenticateResult.Fail("Access Denied"));
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Authentication Failed", ex);
            }
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.StatusCode = 401;
            Response.Headers.Append(HeaderNames.WWWAuthenticate, "Negotiate");
            return Task.CompletedTask;
        }
    }
}
