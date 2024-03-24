namespace UsuariosApp.API.Settings
{
    public class JwtTokenSettings
    {
        public string? Issuer { get; set; }
        public string? Audience { get; set; }
        public string? SecurityKey { get; set; }
        public string? JwtClaimNamesSub { get; set; }
        public string? ExpirationInHours { get; set; }


    }
}
