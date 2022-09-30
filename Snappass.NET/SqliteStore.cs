using Dapper;
using Microsoft.Extensions.Logging;
using System;
using System.Data;
using Microsoft.Data.Sqlite;
using System.Globalization;
using System.Collections.Generic;

namespace Snappass
{
	public sealed class SqliteStore : IMemoryStore, IDisposable
	{
		private class Secret 
		{
			public string Key { get; set; }
			public DateTime CreatedDt { get; set; }
			public DateTime ExpireDt { get; set; }
			public string EncryptedPassword { get; set; }
		}
		private class DateTimeHandler : SqlMapper.TypeHandler<DateTime>
		{
			private static readonly DateTimeHandler Default = new DateTimeHandler();
			internal const string FORMAT = "yyyy-MM-dd HH:mm:ss";

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

		private readonly SqliteConnection _sqliteConnection;
		private readonly ILogger<SqliteStore> _logger;
		private readonly IDateTimeProvider _dateTimeProvider;
		private bool _disposed;

		public SqliteStore(SqliteConnection sqliteConnection, ILogger<SqliteStore> logger, IDateTimeProvider dateTimeProvider)
		{
			_sqliteConnection = sqliteConnection;
			_logger = logger;
			_dateTimeProvider = dateTimeProvider;
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
				SELECT Key, CreatedDt, ExpireDt, EncryptedPassword
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
					CreatedDt = result.GetDateTime(1),
					ExpireDt = result.GetDateTime(2),
					EncryptedPassword = result.GetString(3)
				};
			
            //var secret = _sqliteConnection.QuerySingle<Secret>(query, new { Key = key });

			if (_dateTimeProvider.Now > secret.ExpireDt)
			{	
				_logger.Log(LogLevel.Warning, $@"Tried to retrieve password for key [{key}] after date is expired. Key set at [{secret.CreatedDt}] and expired at [{secret.ExpireDt}]");
				Remove(key);
				return null;
			}
			Remove(key);
			return secret.EncryptedPassword;
            }
			return null;
        }

		private void Remove(string key)
		{
            SqliteCommand delete = _sqliteConnection.CreateCommand();
            delete.CommandText = $@"
					DELETE
					FROM SECRET
					WHERE Key = @key OR ExpireDt < Datetime(@now)
				";
            delete.Parameters.AddWithValue("@key", key);
            delete.Parameters.AddWithValue("@now", DateTime.Now);
			_sqliteConnection.Open();
            delete.ExecuteNonQuery();
            _sqliteConnection.Close();
        }

		public void Store(string encryptedPassword, string key, TimeToLive timeToLive)
		{
			var insert = _sqliteConnection.CreateCommand();

            insert.CommandText = $@"
				INSERT INTO Secret (Key, CreatedDt, ExpireDt, EncryptedPassword)
				VALUES (@key, @createdDt, @expireDt, @encryptedPassword)
			";

			int ttlHours = 0;
			switch (timeToLive.ToString().ToLower())
			{
				case "hour":
					ttlHours = 1;
					break;
				case "day":
					ttlHours = 24;
					break;
				case "week":
					ttlHours = 168;
					break;
				case "month":
					ttlHours = 5208;
                    break;
			}

			var createdDt = DateTime.Now.ToString(DateTimeHandler.FORMAT);
			var expireDt = DateTime.Now.AddHours(ttlHours).ToString(DateTimeHandler.FORMAT);

			insert.Parameters.AddWithValue("@key", key);
			insert.Parameters.AddWithValue("@createdDt", createdDt);
			insert.Parameters.AddWithValue("@expireDt", expireDt);
			insert.Parameters.AddWithValue("@encryptedPassword", encryptedPassword);
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