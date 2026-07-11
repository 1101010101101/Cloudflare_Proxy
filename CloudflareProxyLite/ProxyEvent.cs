namespace CloudflareProxyApp;

public sealed record ProxyEvent(
    string Stage,
    string Status,
    string Message,
    int? Progress,
    string? Endpoint,
    string? AuthCode = null,
    string? AuthUrl = null);
