using Microsoft.OpenApi.Models;
using System.Reflection;

namespace UsuariosApp.API.Extensions
{
    /// <summary>
    /// Classe de extensão para configuração do Swagger (OPEN API)
    /// </summary>
    public static class SwaggerDocExtension
    {
        /// <summary>
        /// Método de extensão para configurar as preferências do Swagger
        /// </summary>
        public static IServiceCollection AddSwaggerDoc(this IServiceCollection services)
        {
            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen(
                options =>
                {
                    //Informações exibidas na documentação do Swagger
                    options.SwaggerDoc("v1", new OpenApiInfo
                    {
                        Title = "UsuariosApp API - Treinamento C# Avançado Formação Arquiteto",
                        Description = "API para autenticação e controle de usuários.",
                        Version = "1.0",
                        Contact = new OpenApiContact
                        {
                            Name = "COTI Informática",
                            Email = "contato@cotiinformatica.com.br",
                            Url = new Uri("http://wwww.cotiinformatica.com.br")
                        }
                    });

                    //Configurações para testes de autenticação
                    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme 
                    { 
                        In = ParameterLocation.Header,
                        Description = "Entre com o TOKEN JWT",
                        Name = "Authorization",
                        Type = SecuritySchemeType.Http,
                        BearerFormat = "JWT",
                        Scheme = "Bearer"
                    });

                    //Informações adicionais para testes de autenticação
                    options.AddSecurityRequirement(new OpenApiSecurityRequirement
                    {
                        {
                            new OpenApiSecurityScheme
                            {
                                Reference = new OpenApiReference
                                {
                                    Type = ReferenceType.SecurityScheme,
                                    Id = "Bearer"
                                }
                            },
                            new string[]{ }
                        }
                    });
                });

            return services;
        }

        /// <summary>
        /// Método para configurar a execução do Swagger
        /// </summary>
        public static IApplicationBuilder UseSwaggerDoc(this IApplicationBuilder app)
        {
            app.UseSwagger();
            app.UseSwaggerUI(options => {
                options.SwaggerEndpoint("/swagger/v1/swagger.json", "UsuariosApp");
            });

            return app;
        }
    }

}
