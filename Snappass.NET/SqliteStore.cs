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
			SELECT Ciphertext, ExpireDt
			FROM Secret
			WHERE Id = @id";
		select.Parameters.AddWithValue("@id", id);

		string? ciphertext = null;
		DateTime expire = DateTime.MinValue;
		using (var reader = select.ExecuteReader())
		{
			if (reader.Read())
			{
				ciphertext = reader.GetString(0);
				expire = DateTime.ParseExact(reader.GetString(1), DateTimeHandler.FORMAT, CultureInfo.InvariantCulture);
			}
		}

		using var delete = _connection.CreateCommand();
		delete.Transaction = tx;
		delete.CommandText = "DELETE FROM Secret WHERE Id = @id";
		delete.Parameters.AddWithValue("@id", id);
		delete.ExecuteNonQuery();

		tx.Commit();

		if (ciphertext is null)
		{
			_logger.LogWarning("Consume requested for unknown id");
			return null;
		}
		if (_clock.Now > expire)
		{
			_logger.LogWarning("Consume requested for expired id (expired {Expire})", expire);
			return null;
		}
		return ciphertext;
	}

	public void Store(string id, string ciphertext, TimeToLive ttl)
	{
		EnsureOpen();
		using var insert = _connection.CreateCommand();
		insert.CommandText = @"
			INSERT INTO Secret (Id, CreatedDt, ExpireDt, Ciphertext)
			VALUES (@id, @createdDt, @expireDt, @ciphertext)";

		var now = _clock.Now;
		var hours = TtlHours(ttl);
		insert.Parameters.AddWithValue("@id", id);
		insert.Parameters.AddWithValue("@createdDt", now.ToString(DateTimeHandler.FORMAT, CultureInfo.InvariantCulture));
		insert.Parameters.AddWithValue("@expireDt", now.AddHours(hours).ToString(DateTimeHandler.FORMAT, CultureInfo.InvariantCulture));
		insert.Parameters.AddWithValue("@ciphertext", ciphertext);
		insert.ExecuteNonQuery();
	}

	private static int TtlHours(TimeToLive ttl) => ttl switch
	{
		TimeToLive.Hour => 1,
		TimeToLive.Day => 24,
		TimeToLive.Week => 24 * 7,
		TimeToLive.Month => 24 * 31,
		_ => throw new ArgumentOutOfRangeException(nameof(ttl)),
	};

	public void Dispose()
	{
		if (_disposed) return;
		_connection.Dispose();
		_disposed = true;
	}
}
