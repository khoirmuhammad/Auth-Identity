using System.Text.Json;

namespace IdentityAuth.Models.CustomModels
{
    public class ApiResponseModel
    {
        public ApiResponseModel()
        {

        }
        public ApiResponseModel(int code, string errorMessage, string? errorDetail = null)
        {
            Code = code;
            ErrorMessage = errorMessage;
            ErrorDetail = errorDetail;
        }

        public int Code { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
        public string? ErrorDetail { get; set; }

        public override string ToString()
        {
            var options = new JsonSerializerOptions()
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            return JsonSerializer.Serialize(this, options);
        }
    }
}
