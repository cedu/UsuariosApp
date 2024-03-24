using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using UsuariosApp.API.Identity.Entities;
using UsuariosApp.API.Settings;

namespace UsuariosApp.API.Identity.Contexts
{
    /// <summary>
    /// Classe de contexto para conexão com o banco de dados
    /// usando o modelo de entidades do AspNetCore.Identity
    /// </summary>
    public class IdentityContext : IdentityUserContext<Usuario>
    {
        private readonly IdentitySettings _identitySettings;

        //método construtor para injeção de dependência
        public IdentityContext(DbContextOptions<IdentityContext> options, IdentitySettings identitySettings)
            : base(options)
        {
            _identitySettings = identitySettings;
        }

        //método incluirmos os mapeamentos do banco de dados
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            #region Pré-cadastrar o usuário padrão no banco de dados

            //utilizar criptografia de dados para o usuário
            var hasher = new PasswordHasher<Usuario>();

            builder.Entity<Usuario>().HasData(new Usuario
            {
                Id = "BB1F498C-00C5-46E3-B869-0E8AC6029087",
                UserName = "Usuário Administrador",
                Email = _identitySettings.AdminEmail,
                NormalizedUserName = _identitySettings.AdminEmail.ToUpper(),
                NormalizedEmail = _identitySettings.AdminEmail.ToUpper(),
                PasswordHash = hasher.HashPassword(null, _identitySettings.AdminPassword)
            });

            #endregion
        }
    }
}



