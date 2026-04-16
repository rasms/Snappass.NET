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
				Id          TEXT PRIMARY KEY,
				CreatedDt   TEXT NOT NULL,
				ExpireDt    TEXT NOT NULL,
				Ciphertext  TEXT NOT NULL
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

		store.Store("abc123", "ciphertext-blob", TimeToLive.Day);

		Assert.True(store.Exists("abc123"));
	}

	[Fact]
	public void Consume_Returns_StoredCiphertext()
	{
		using var conn = CreateConnection();
		var store = NewStore(conn);
		store.Store("abc123", "ciphertext-blob", TimeToLive.Day);

		var result = store.Consume("abc123");

		Assert.Equal("ciphertext-blob", result);
	}

	[Fact]
	public void Consume_IsOneShot()
	{
		using var conn = CreateConnection();
		var store = NewStore(conn);
		store.Store("abc123", "ciphertext-blob", TimeToLive.Day);

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

		store.Store("abc123", "ciphertext-blob", TimeToLive.Hour);

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

		store.Store("abc123", "ciphertext-blob", TimeToLive.Hour);

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
}
