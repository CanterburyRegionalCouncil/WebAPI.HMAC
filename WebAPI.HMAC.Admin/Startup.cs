using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(WebAPI.HMAC.Admin.Startup))]
namespace WebAPI.HMAC.Admin
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
