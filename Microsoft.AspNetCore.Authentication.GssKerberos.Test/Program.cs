using Microsoft.AspNetCore.Hosting;

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Test
{
    public class Program
    {
        public static void Main(string[] args)
        {
            BuildWebHost(args).Run();
        }

        public static IWebHost BuildWebHost(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseUrls("http://*:8912")
                .UseStartup<Startup>()
                .Build();
    }
}
