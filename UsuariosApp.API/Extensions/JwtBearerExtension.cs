using Microsoft.Extensions.Options;
using UsuariosApp.API.Services;
using UsuariosApp.API.Settings;

namespace UsuariosApp.API.Extensions
{
    public static class JwtBearerExtension
    {
        public static IServiceCollection AddJwtBearer
            (this IServiceCollection services, IConfiguration configuration)
        {
            //configurando os parametros do /appsettings
            var jwtTokenSettings = new JwtTokenSettings();
            new ConfigureFromConfigurationOptions<JwtTokenSettings>
                (configuration.GetSection("JwtTokenSettings"))
                .Configure(jwtTokenSettings);

            services.AddSingleton(jwtTokenSettings);
            services.AddTransient<JwtTokenService>();

            return services;
        }
    }
}
