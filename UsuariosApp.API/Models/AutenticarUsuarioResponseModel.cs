namespace UsuariosApp.API.Models
{
    /// <summary>
    /// Modelo de dados para a resposta da requisição de autenticação de usuários
    /// </summary>
    public class AutenticarUsuarioResponseModel
    {
        public int? UsuarioId { get; set; }
        public string? Nome { get; set; }
        public string? Email { get; set; }
        public DateTime? DataHoraAcesso { get; set; }
        public string? AccessToken { get; set; }
    }
}
