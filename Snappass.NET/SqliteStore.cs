using Dapper;
using Microsoft.Extensions.Logging;
using System;
using System.Data;
using Microsoft.Data.Sqlite;
using System.Globalization;

namespace Snappass
{
	public sealed class SqliteStore : IMemoryStore, IDisposable
	{
		private class Secret 
		{
			public string Key { get; set; }
			public TimeToLive TimeToLive { get; set; }
			public string EncryptedPassword { get; set; }
			public DateTime StoredDateTime { get; set; }
		}
		private class DateTimeHandler : SqlMapper.TypeHandler<DateTime>
		{
			private static readonly DateTimeHandler Default = new DateTimeHandler();
			internal const string FORMAT = "yyyy-MM-dd HH:mm";

			public override DateTime Parse(object value)
			{
				if (value == null)
				{
					return DateTime.MinValue;
				}
				var parsed = DateTime.ParseExact(value.ToString(), FORMAT, CultureInfo.InvariantCulture);
				return parsed;
			}

			public override void SetValue(IDbDataParameter parameter, DateTime value)
			{
				parameter.Value = value.ToString(FORMAT, CultureInfo.InvariantCulture);
			}
		}
		private class TimeToLiveHandler : SqlMapper.TypeHandler<TimeToLive>
		{
			public override TimeToLive Parse(object value)
			{
				int.TryParse(value.ToString(), out int intValue);
				return intValue switch
				{
					0 => TimeToLive.Hour,
					1 => TimeToLive.Day,
					2 => TimeToLive.Week,
					3 => TimeToLive.Month,
					_ => TimeToLive.Hour,
				};
			}

			public override void SetValue(IDbDataParameter parameter, TimeToLive value)
			{
				parameter.Value = (int)value;
			}
		}
		private readonly SqliteConnection _sqliteConnection;
		private readonly ILogger<SqliteStore> _logger;
		private readonly IDateTimeProvider _dateTimeProvider;
		private bool _disposed;

		public SqliteStore(SqliteConnection sqliteConnection, ILogger<SqliteStore> logger, IDateTimeProvider dateTimeProvider)
		{
			_sqliteConnection = sqliteConnection;
			_logger = logger;
			_dateTimeProvider = dateTimeProvider;
			SqlMapper.AddTypeHandler(new TimeToLiveHandler());
			SqlMapper.AddTypeHandler(new DateTimeHandler());
		}
		public bool Has(string key)
		{
			SqliteCommand select = _sqliteConnection.CreateCommand();
			select.CommandText = $@"
				SELECT EXISTS (
					SELECT 1 
					FROM SECRET
					WHERE Key = @key
				)";
			select.Parameters.AddWithValue("@key", key);

			_sqliteConnection.Open();
			var result = select.ExecuteScalar();
			_sqliteConnection.Close();

			return Convert.ToBoolean(result);
		}

		public string Retrieve(string key)
		{
			if (key == null)
			{
				_logger.Log(LogLevel.Warning, $@"Tried to retrieve null key");
				return null;
			}
			if (!Has(key))
			{
				_logger.Log(LogLevel.Warning, $@"Tried to retrieve password for unknown key [{key}]");
				return null;
			}
            SqliteCommand select = _sqliteConnection.CreateCommand();
            select.CommandText = $@"
				SELECT Key, TimeToLive, EncryptedPassword, StoredDateTime
				FROM SECRET
				WHERE Key = @key
			";
            select.Parameters.AddWithValue("@key", key);
			_sqliteConnection.Open();
			var result = select.ExecuteReader();
			if (result.Read())
			{
				var secret = new Secret
				{
					Key = result.GetString(0),
					TimeToLive = result.GetInt32(1),
					EncryptedPassword = result.GetString(2),
					StoredDateTime = result.GetDateTime(3)
				};
			}
            //var secret = _sqliteConnection.QuerySingle<Secret>(query, new { Key = key });
			static DateTime GetAtTheLatest(TimeToLive ttl, DateTime dateTime) => ttl switch
			{
				TimeToLive.Day => dateTime.AddDays(1),
				TimeToLive.Week => dateTime.AddDays(7),
				TimeToLive.Hour => dateTime.AddHours(1),
				TimeToLive.Month => dateTime.AddDays(31),
				_ => dateTime.AddHours(1)
			};
			DateTime atTheLatest = GetAtTheLatest(secret.TimeToLive, secret.StoredDateTime);
			if (_dateTimeProvider.Now > atTheLatest)
			{
				static string ToString(TimeToLive ttl) => ttl switch
				{
					TimeToLive.Week => "1 week",
					TimeToLive.Day => "1 day",
					TimeToLive.Hour => "1 hour",
					TimeToLive.Month => "1 month",
					_ => "hour"
				};
				var ttlString = ToString(secret.TimeToLive);
				_logger.Log(LogLevel.Warning, $@"Tried to retrieve password for key [{key}] after date is expired. Key set at [{secret.StoredDateTime}] for [{ttlString}]");
				Remove(key);
				return null;
			}
			Remove(key);
			return secret.EncryptedPassword;
		}

		private void Remove(string key)
		{
			var query = $@"
					DELETE
					FROM SECRET
					WHERE Key = @key
				";
			_sqliteConnection.Execute(query, new { Key = key });
		}

		public void Store(string encryptedPassword, string key, TimeToLive timeToLive)
		{
			var insert = _sqliteConnection.CreateCommand();

            insert.CommandText = $@"
				INSERT INTO Secret (Key, TimeToLive, EncryptedPassword, StoredDateTime)
				VALUES (@key, @timeToLive, @encryptedPassword, @storedDateTime)
			";
			var storedDateTime = DateTime.Now.ToString(DateTimeHandler.FORMAT);
			var parameters = new
			{
				Key = key,
				TimeToLive = timeToLive,
				EncryptedPassword = encryptedPassword,
				StoredDateTime = storedDateTime
			};

			insert.Parameters.AddWithValue("@key", key);
			insert.Parameters.AddWithValue("@timeToLive", timeToLive);
			insert.Parameters.AddWithValue("@encryptedPassword", encryptedPassword);
			insert.Parameters.AddWithValue("@storedDateTime", storedDateTime);
			_sqliteConnection.Open();
			insert.ExecuteNonQuery();
			_sqliteConnection.Close();
			//_sqliteConnection.Execute(query);
		}

		public void Dispose()
		{
			if (!_disposed)
			{
				_sqliteConnection.Dispose();
				_disposed = true;
			}
		}
	}
}