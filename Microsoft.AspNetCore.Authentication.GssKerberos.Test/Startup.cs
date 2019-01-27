using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Test
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var servicePrincipal = "<spn>";

            // Aquire MIT Kerberos credentials from the systems configured Keytab
            var serverCredentials = GssCredentials.FromKeytab(servicePrincipal, CredentialUsage.Accept);

            // Uncomment to use Microsoft SSPI (Windows)
            // var serverCredentials = new SspiCredentials();

            services.AddAuthentication(options =>
                    {
                        options.DefaultChallengeScheme = GssAuthenticationDefaults.AuthenticationScheme;
                        options.DefaultAuthenticateScheme = GssAuthenticationDefaults.AuthenticationScheme;
                    })
                .AddKerberos(options =>
                {
                    // Use MIT Kerberos GSS (Linux / Windows)
                    options.AcceptorFactory = () => new GssAcceptor(serverCredentials); 

                    // Uncomment to use Microsoft SSPI (Windows)
                    // options.AcceptorFactory = () => new SspiAcceptor(serverCredentials); 
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseAuthentication();
            app.Map("/ws", ws =>
            {
                //  ws.UseWebSockets();
                ws.UseMiddleware<CustomMiddleware>();
            });
        }
    }
}
