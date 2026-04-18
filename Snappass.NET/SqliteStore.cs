using System.Data;
using System.Globalization;
using Dapper;
using Microsoft.Data.Sqlite;

namespace Snappass;

public sealed class SqliteStore : ISecretStore, IDisposable
{
	private sealed class Secret
	{
		public string Id { get; set; } = string.Empty;
		public DateTime CreatedDt { get; set; }
		public DateTime ExpireDt { get; set; }
		public string Ciphertext { get; set; } = string.Empty;
	}

	private sealed class DateTimeHandler : SqlMapper.TypeHandler<DateTime>
	{
		internal const string FORMAT = "yyyy-MM-dd HH:mm:ss";

		public override DateTime Parse(object value)
		{
			if (value is null) return DateTime.MinValue;
			return DateTime.ParseExact(value.ToString()!, FORMAT, CultureInfo.InvariantCulture);
		}

		public override void SetValue(IDbDataParameter parameter, DateTime value)
		{
			parameter.Value = value.ToString(FORMAT, CultureInfo.InvariantCulture);
		}
	}

	private readonly SqliteConnection _connection;
	private readonly ILogger<SqliteStore> _logger;
	private readonly IDateTimeProvider _clock;
	private bool _disposed;

	public SqliteStore(SqliteConnection connection, ILogger<SqliteStore> logger, IDateTimeProvider clock)
	{
		_connection = connection;
		_logger = logger;
		_clock = clock;
		SqlMapper.AddTypeHandler(new DateTimeHandler());
	}

	private void EnsureOpen()
	{
		if (_connection.State != ConnectionState.Open)
		{
			_connection.Open();
		}
	}

	public bool Exists(string id)
	{
		EnsureOpen();
		using var cmd = _connection.CreateCommand();
		cmd.CommandText = @"
			SELECT EXISTS (
				SELECT 1 FROM Secret
				WHERE Id = @id AND ExpireDt > @now
			)";
		cmd.Parameters.AddWithValue("@id", id);
		cmd.Parameters.AddWithValue("@now", _clock.Now.ToString(DateTimeHandler.FORMAT, CultureInfo.InvariantCulture));
		return Convert.ToBoolean(cmd.ExecuteScalar());
	}

	public string? Consume(string id)
	{
		EnsureOpen();
		using var tx = _connection.BeginTransaction();

		using var select = _connection.CreateCommand();
		select.Transaction = tx;
		select.CommandText = @"
			SELECT Ciphertext, ExpireDt, RemainingViews
			FROM Secret
			WHERE Id = @id";
		select.Parameters.AddWithValue("@id", id);

		string? ciphertext = null;
		DateTime expire = DateTime.MinValue;
		long remaining = 0;
		using (var reader = select.ExecuteReader())
		{
			if (reader.Read())
			{
				ciphertext = reader.GetString(0);
				expire = DateTime.ParseExact(reader.GetString(1), DateTimeHandler.FORMAT, CultureInfo.InvariantCulture);
				remaining = reader.GetInt64(2);
			}
		}

		if (ciphertext is null)
		{
			tx.Rollback();
			_logger.LogWarning("Consume requested for unknown id");
			return null;
		}

		// Expired rows are always deleted regardless of remaining views.
		// Whichever limit (time or views) hits first wins.
		if (_clock.Now > expire)
		{
			using var delExpired = _connection.CreateCommand();
			delExpired.Transaction = tx;
			delExpired.CommandText = "DELETE FROM Secret WHERE Id = @id";
			delExpired.Parameters.AddWithValue("@id", id);
			delExpired.ExecuteNonQuery();
			tx.Commit();
			_logger.LogWarning("Consume requested for expired id (expired {Expire})", expire);
			return null;
		}

		if (remaining == 0)
		{
			// Sentinel 0 = unlimited views within TTL. No mutation; TTL is the
			// only destruction trigger. The row is eventually reaped by
			// ExpiredSecretCleaner or by a consume after ExpireDt.
			tx.Commit();
		}
		else if (remaining <= 1)
		{
			// Last (or only) permitted view — destroy the row.
			using var delLast = _connection.CreateCommand();
			delLast.Transaction = tx;
			delLast.CommandText = "DELETE FROM Secret WHERE Id = @id";
			delLast.Parameters.AddWithValue("@id", id);
			delLast.ExecuteNonQuery();
			tx.Commit();
		}
		else
		{
			// More views permitted — decrement atomically.
			using var dec = _connection.CreateCommand();
			dec.Transaction = tx;
			dec.CommandText = "UPDATE Secret SET RemainingViews = RemainingViews - 1 WHERE Id = @id";
			dec.Parameters.AddWithValue("@id", id);
			dec.ExecuteNonQuery();
			tx.Commit();
		}

		return ciphertext;
	}

	public int PurgeExpired()
	{
		EnsureOpen();
		using var cmd = _connection.CreateCommand();
		cmd.CommandText = "DELETE FROM Secret WHERE ExpireDt <= @now";
		cmd.Parameters.AddWithValue("@now", _clock.Now.ToString(DateTimeHandler.FORMAT, CultureInfo.InvariantCulture));
		return cmd.ExecuteNonQuery();
	}

	public void Store(string id, string ciphertext, TimeToLive ttl, int views)
	{
		// views == 0 is the sentinel for "unlimited" — everything else is a concrete count.
		if (views < 0) throw new ArgumentOutOfRangeException(nameof(views), "views must be >= 0");

		EnsureOpen();
		using var insert = _connection.CreateCommand();
		insert.CommandText = @"
			INSERT INTO Secret (Id, CreatedDt, ExpireDt, Ciphertext, RemainingViews)
			VALUES (@id, @createdDt, @expireDt, @ciphertext, @views)";

		var now = _clock.Now;
		var hours = TtlHours(ttl);
		insert.Parameters.AddWithValue("@id", id);
		insert.Parameters.AddWithValue("@createdDt", now.ToString(DateTimeHandler.FORMAT, CultureInfo.InvariantCulture));
		insert.Parameters.AddWithValue("@expireDt", now.AddHours(hours).ToString(DateTimeHandler.FORMAT, CultureInfo.InvariantCulture));
		insert.Parameters.AddWithValue("@ciphertext", ciphertext);
		insert.Parameters.AddWithValue("@views", views);
		insert.ExecuteNonQuery();
	}

	private static int TtlHours(TimeToLive ttl) => ttl switch
	{
		TimeToLive.Hour => 1,
		TimeToLive.Day => 24,
		TimeToLive.TwoDays => 24 * 2,
		TimeToLive.ThreeDays => 24 * 3,
		TimeToLive.Week => 24 * 7,
		TimeToLive.TwoWeeks => 24 * 14,
		TimeToLive.Month => 24 * 31,
		TimeToLive.ThreeMonths => 24 * 93,
		_ => throw new ArgumentOutOfRangeException(nameof(ttl)),
	};

	public void Dispose()
	{
		if (_disposed) return;
		_connection.Dispose();
		_disposed = true;
	}
}
