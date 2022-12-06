using System.Text.Json;

namespace IdentityAuth.Models.CustomModels
{
    public class ApiResponseModel<T>
    {
        public ApiResponseModel()
        {

        }
        public ApiResponseModel(int code, T data, List<string> errorMessage, string? errorDetail = null)
        {
            Code = code;
            Data = data;
            ErrorMessages = errorMessage;
            ErrorDetail = errorDetail;
        }

        public int Code { get; set; }
        public T Data { get; set; } = default!;
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
