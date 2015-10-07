namespace WebAPI.HMAC.Validator
{
    public interface IApiKeyValidator
    {
        bool Validate(string appId, string apiKey);
    }
}