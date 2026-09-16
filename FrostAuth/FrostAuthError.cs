namespace FrostAuth;

public class FrostAuthError : Exception
{
    public string Code { get; }
    public int Status { get; }
    public bool Retryable { get; }
    public int RetryAfterSeconds { get; init; }

    public FrostAuthError(string message, string code = "SERVER_ERROR", int status = 0, bool retryable = false)
        : base(message)
    {
        Code = code;
        Status = status;
        Retryable = retryable;
    }

    public bool NeedsActivation => Status == 404 && !Retryable;
    public bool Terminal => !Retryable && !NeedsActivation && Status is >= 400 and < 500;

    public static class Codes
    {
        public const string Config = "CONFIG";
        public const string Network = "NETWORK";
        public const string Timeout = "TIMEOUT";
        public const string NotInitialized = "NOT_INITIALIZED";
        public const string NotActivated = "NOT_ACTIVATED";
        public const string ServerError = "SERVER_ERROR";
        public const string Signature = "SIGNATURE";
        public const string RateLimited = "RATE_LIMITED";
    }
}
