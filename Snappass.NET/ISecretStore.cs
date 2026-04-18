namespace Snappass;

public interface IDateTimeProvider
{
	DateTime Now { get; }
}

public sealed class CurrentDateTimeProvider : IDateTimeProvider
{
	public DateTime Now => DateTime.UtcNow;
}

public interface ISecretStore
{
	bool Exists(string id);
	void Store(string id, string ciphertext, TimeToLive ttl, int views);
	string? Consume(string id);
	int PurgeExpired();
}
