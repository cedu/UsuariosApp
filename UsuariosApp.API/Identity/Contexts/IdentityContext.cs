using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using UsuariosApp.API.Identity.Entities;

namespace UsuariosApp.API.Identity.Contexts
{
    /// <summary>
    /// Classe de contexto para conexão com o banco de dados
    /// usando o modelo de entidades do AspNetCore.Identity
    /// </summary>
    public class IdentityContext : IdentityUserContext<Usuario>
    {
        //método construtor para injeção de dependência
        public IdentityContext(DbContextOptions<IdentityContext> options)
            : base(options)
        {

        }

        //método incluirmos os mapeamentos do banco de dados
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            #region Pré-cadastrar o usuário padrão no banco de dados

            //utilizar criptografia de dados para o usuário
            var hasher = new PasswordHasher<Usuario>();

            //ler os dados do usuário contido no /appsettings.json
            var adminEmail = new ConfigurationBuilder()
                .AddJsonFile("appsettings.Development.json").Build()
                .GetSection("IdentitySettings")["AdminEmail"];

            var adminPassword = new ConfigurationBuilder()
                .AddJsonFile("appsettings.Development.json").Build()
                .GetSection("IdentitySettings")["AdminPassword"];

            builder.Entity<Usuario>().HasData(new Usuario
            {
                Id = "BB1F498C-00C5-46E3-B869-0E8AC6029087",
                UserName = "Usuário Administrador",
                Email = adminEmail,
                NormalizedUserName = adminEmail.ToUpper(),
                NormalizedEmail = adminEmail.ToUpper(),
                PasswordHash = hasher.HashPassword(null, adminPassword)
            });

            #endregion
        }
    }
}



