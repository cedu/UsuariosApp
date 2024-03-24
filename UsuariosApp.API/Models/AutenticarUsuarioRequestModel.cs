using System.ComponentModel.DataAnnotations;

namespace UsuariosApp.API.Models
{
    /// <summary>
    /// Modelo de dados para a requisição de autenticação de usuário
    /// </summary>
    public class AutenticarUsuarioRequestModel
    {
        [EmailAddress(ErrorMessage = "Por favor, informe um endereço de email válido.")]
        [Required(ErrorMessage = "Por favor, informe o email de acesso.")]
        public string? Email { get; set; }

        [MinLength(8, ErrorMessage = "Por favor, informe no mínimo {1} caracteres.")]
        [Required(ErrorMessage = "Por favor, informe a senha de acesso.")]
        public string? Senha { get; set; }
    }
}
