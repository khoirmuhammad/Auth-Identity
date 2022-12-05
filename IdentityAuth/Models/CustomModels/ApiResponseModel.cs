using System.Text.Json;

namespace IdentityAuth.Models.CustomModels
{
    public class ApiResponseModel
    {
        public ApiResponseModel()
        {

        }
        public ApiResponseModel(int code, List<string> errorMessage, string? errorDetail = null)
        {
            Code = code;
            ErrorMessages = errorMessage;
            ErrorDetail = errorDetail;
        }

        public int Code { get; set; }
        public List<string> ErrorMessages { get; set; } = new List<string>();
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
