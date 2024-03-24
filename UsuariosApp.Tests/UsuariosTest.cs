using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Newtonsoft.Json;
using System.Net;
using System.Text;
using UsuariosApp.API.Models;

namespace UsuariosApp.Tests
{
    public class UsuariosTest
    {
        [Fact]
        public async Task AutenticarUsuario_ReturnsOk()
        {
            #region Criar os dados da requisição

            var request = new AutenticarUsuarioRequestModel
            {
                Email = "administrador@test.com",
                Senha = "@Test123"
            };

            var jsonRequest = new StringContent
                (JsonConvert.SerializeObject(request), Encoding.UTF8, "application/json");

            #endregion

            #region Executando o serviço de autenticação e capturar a resposta

            var client = new WebApplicationFactory<Program>().CreateClient();
            var result = await client.PostAsync("/api/usuarios/autenticar", jsonRequest);

            #endregion

            #region Verificar a resposta do serviço

            result.StatusCode.Should().Be(HttpStatusCode.OK);

            #endregion
        }

        [Fact]
        public async Task AutenticarUsuario_ReturnsUnauthorized()
        {
            #region Criar os dados da requisição

            var request = new AutenticarUsuarioRequestModel
            {
                Email = "usuarionaoautorizado@test.com",
                Senha = "@NaoAutorizado123"
            };

            var jsonRequest = new StringContent
                (JsonConvert.SerializeObject(request), Encoding.UTF8, "application/json");

            #endregion

            #region Executando o serviço de autenticação e capturar a resposta

            var client = new WebApplicationFactory<Program>().CreateClient();
            var result = await client.PostAsync("/api/usuarios/autenticar", jsonRequest);

            #endregion

            #region Verificar a resposta do serviço

            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

            #endregion
        }
    }
}