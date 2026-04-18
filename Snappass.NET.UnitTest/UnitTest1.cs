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

	[Fact]
	public void Consume_UnlimitedViews_NeverDecrementsOrDeletes()
	{
		// views = 0 is the sentinel for "unlimited within TTL".
		// N consumes all return the same ciphertext; row stays alive.
		using var conn = CreateConnection();
		var store = NewStore(conn);

		store.Store("infinite", "ct-inf", TimeToLive.Day, views: 0);

		for (var i = 0; i < 25; i++)
		{
			Assert.Equal("ct-inf", store.Consume("infinite"));
			Assert.True(store.Exists("infinite"));
		}
	}

	[Fact]
	public void Consume_UnlimitedViews_StillExpiresOnTtl()
	{
		// Unlimited views does not exempt the row from TTL destruction.
		using var conn = CreateConnection();
		var t0 = DateTime.UtcNow;
		var nowValue = t0;
		var clock = new Mock<IDateTimeProvider>();
		clock.Setup(c => c.Now).Returns(() => nowValue);
		var store = NewStore(conn, clock.Object);

		store.Store("inf-but-ttl", "ct", TimeToLive.Hour, views: 0);

		// Before TTL: consume succeeds.
		Assert.Equal("ct", store.Consume("inf-but-ttl"));
		Assert.True(store.Exists("inf-but-ttl"));

		// After TTL: consume returns null and row is deleted.
		nowValue = t0.AddHours(2);
		Assert.Null(store.Consume("inf-but-ttl"));
		Assert.False(store.Exists("inf-but-ttl"));
	}

	[Fact]
	public void Store_ExtendedTtls_ComputeExpectedExpiry()
	{
		// Smoke-test the new TTL steps: TwoDays, ThreeDays, TwoWeeks, ThreeMonths.
		// Store at t0, check Exists at t0+offset ± 1 hour.
		using var conn = CreateConnection();
		var t0 = new DateTime(2026, 4, 18, 12, 0, 0, DateTimeKind.Utc);
		var nowValue = t0;
		var clock = new Mock<IDateTimeProvider>();
		clock.Setup(c => c.Now).Returns(() => nowValue);
		var store = NewStore(conn, clock.Object);

		store.Store("2d", "ct", TimeToLive.TwoDays, views: 1);
		store.Store("3d", "ct", TimeToLive.ThreeDays, views: 1);
		store.Store("2w", "ct", TimeToLive.TwoWeeks, views: 1);
		store.Store("3m", "ct", TimeToLive.ThreeMonths, views: 1);

		// All still exist right after creation.
		Assert.True(store.Exists("2d"));
		Assert.True(store.Exists("3d"));
		Assert.True(store.Exists("2w"));
		Assert.True(store.Exists("3m"));

		// 2d gone after 49 hours, 3d still alive.
		nowValue = t0.AddHours(49);
		Assert.False(store.Exists("2d"));
		Assert.True(store.Exists("3d"));

		// 3d and 2w gone after 15 days, 3m still alive.
		nowValue = t0.AddDays(15);
		Assert.False(store.Exists("3d"));
		Assert.False(store.Exists("2w"));
		Assert.True(store.Exists("3m"));

		// 3m gone after 94 days.
		nowValue = t0.AddDays(94);
		Assert.False(store.Exists("3m"));
	}
}
