using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Moq;
using Snappass;
using Xunit;

namespace Snappass.NET.UnitTest;

public class SqliteStoreTests
{
	private static SqliteConnection CreateConnection()
	{
		var conn = new SqliteConnection("Data Source=:memory:");
		conn.Open();
		conn.Execute(@"
			CREATE TABLE Secret (
				Id              TEXT PRIMARY KEY,
				CreatedDt       TEXT NOT NULL,
				ExpireDt        TEXT NOT NULL,
				Ciphertext      TEXT NOT NULL,
				RemainingViews  INTEGER NOT NULL DEFAULT 1
			);
			CREATE INDEX idx_secret_expire ON Secret(ExpireDt);
		");
		return conn;
	}

	private static SqliteStore NewStore(SqliteConnection conn, IDateTimeProvider? clock = null) =>
		new(conn, Mock.Of<ILogger<SqliteStore>>(), clock ?? new CurrentDateTimeProvider());

	[Fact]
	public void Store_Then_Exists_ReturnsTrue()
	{
		using var conn = CreateConnection();
		var store = NewStore(conn);

		store.Store("abc123", "ciphertext-blob", TimeToLive.Day, views: 1);

		Assert.True(store.Exists("abc123"));
	}

	[Fact]
	public void Consume_Returns_StoredCiphertext()
	{
		using var conn = CreateConnection();
		var store = NewStore(conn);
		store.Store("abc123", "ciphertext-blob", TimeToLive.Day, views: 1);

		var result = store.Consume("abc123");

		Assert.Equal("ciphertext-blob", result);
	}

	[Fact]
	public void Consume_IsOneShot()
	{
		using var conn = CreateConnection();
		var store = NewStore(conn);
		store.Store("abc123", "ciphertext-blob", TimeToLive.Day, views: 1);

		store.Consume("abc123");

		Assert.Null(store.Consume("abc123"));
		Assert.False(store.Exists("abc123"));
	}

	[Fact]
	public void Consume_Expired_ReturnsNullAndDeletes()
	{
		using var conn = CreateConnection();
		var t0 = DateTime.UtcNow;
		var nowValue = t0;
		var clock = new Mock<IDateTimeProvider>();
		clock.Setup(c => c.Now).Returns(() => nowValue);
		var store = NewStore(conn, clock.Object);

		store.Store("abc123", "ciphertext-blob", TimeToLive.Hour, views: 1);

		nowValue = t0.AddHours(2);

		Assert.Null(store.Consume("abc123"));
		Assert.False(store.Exists("abc123"));
	}

	[Fact]
	public void Exists_Expired_ReturnsFalse()
	{
		using var conn = CreateConnection();
		var t0 = DateTime.UtcNow;
		var nowValue = t0;
		var clock = new Mock<IDateTimeProvider>();
		clock.Setup(c => c.Now).Returns(() => nowValue);
		var store = NewStore(conn, clock.Object);

		store.Store("abc123", "ciphertext-blob", TimeToLive.Hour, views: 1);

		nowValue = t0.AddHours(2);

		Assert.False(store.Exists("abc123"));
	}

	[Fact]
	public void Consume_UnknownId_ReturnsNull()
	{
		using var conn = CreateConnection();
		var store = NewStore(conn);

		Assert.Null(store.Consume("nonexistent"));
	}

	[Fact]
	public void PurgeExpired_RemovesOnlyExpired()
	{
		using var conn = CreateConnection();
		var t0 = DateTime.UtcNow;
		var nowValue = t0;
		var clock = new Mock<IDateTimeProvider>();
		clock.Setup(c => c.Now).Returns(() => nowValue);
		var store = NewStore(conn, clock.Object);

		store.Store("fresh", "ct-fresh", TimeToLive.Day, views: 1);
		store.Store("old", "ct-old", TimeToLive.Hour, views: 1);
		nowValue = t0.AddHours(2);

		var purged = store.PurgeExpired();

		Assert.Equal(1, purged);
		Assert.True(store.Exists("fresh"));
		Assert.False(store.Exists("old"));
		Assert.Null(store.Consume("old"));
	}

	[Fact]
	public void PurgeExpired_NothingToPurge_ReturnsZero()
	{
		using var conn = CreateConnection();
		var store = NewStore(conn);

		store.Store("fresh", "ct", TimeToLive.Day, views: 1);

		Assert.Equal(0, store.PurgeExpired());
		Assert.True(store.Exists("fresh"));
	}

	[Fact]
	public void Consume_MultiView_DecrementsUntilExhausted()
	{
		using var conn = CreateConnection();
		var store = NewStore(conn);

		store.Store("multi", "ct-multi", TimeToLive.Day, views: 3);

		// 3 successful reads, same ciphertext each time, row stays alive.
		Assert.Equal("ct-multi", store.Consume("multi"));
		Assert.True(store.Exists("multi"));

		Assert.Equal("ct-multi", store.Consume("multi"));
		Assert.True(store.Exists("multi"));

		// Third (last permitted) read — row deletes.
		Assert.Equal("ct-multi", store.Consume("multi"));
		Assert.False(store.Exists("multi"));

		// Fourth read — already gone.
		Assert.Null(store.Consume("multi"));
	}

	[Fact]
	public void Consume_MultiView_ExpiryBeatsRemainingCount()
	{
		using var conn = CreateConnection();
		var t0 = DateTime.UtcNow;
		var nowValue = t0;
		var clock = new Mock<IDateTimeProvider>();
		clock.Setup(c => c.Now).Returns(() => nowValue);
		var store = NewStore(conn, clock.Object);

		// Plenty of views left, but TTL is short.
		store.Store("expire-first", "ct", TimeToLive.Hour, views: 10);

		// Advance past TTL without consuming once.
		nowValue = t0.AddHours(2);

		Assert.Null(store.Consume("expire-first"));
		Assert.False(store.Exists("expire-first"));
	}
}
