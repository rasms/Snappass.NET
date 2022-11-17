using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;

namespace Snappass
{
	public interface IDateTimeProvider
	{
		DateTime Now { get; }
	}
	public class CurrentDateTimeProvider : IDateTimeProvider
	{
		public DateTime Now => DateTime.Now;
	}

	public interface IMemoryStore
    {
        public bool Has(string key);
        public void Store(string encryptedPassword, string key, TimeToLive timeToLive);
        public string Retrieve(string key);
    }
    public sealed class MemoryStore : IMemoryStore
    {
        private class Item
        {
            public string Key { get; set; }
            public DateTime CreatedDt { get; set; }
            public DateTime ExpireDt { get; set; }
            public string EncryptedPassword { get; set; }
        }

        private readonly Dictionary<string, Item> _items = new Dictionary<string, Item>();
        private readonly ILogger<MemoryStore> _logger;
		private readonly IDateTimeProvider _dateTimeProvider;

		public MemoryStore(ILogger<MemoryStore> logger, IDateTimeProvider dateTimeProvider)
        {
            _logger = logger;
			_dateTimeProvider = dateTimeProvider;
		}

        public bool Has(string key) => _items.ContainsKey(key);

        public void Store(string encryptedPassword, string key, TimeToLive timeToLive) 
        {
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
            var item = new Item
            {
                Key = key,
                CreatedDt = DateTime.Now,
                ExpireDt = DateTime.Now.AddHours(ttlHours),
                EncryptedPassword = encryptedPassword
            };
            _items.Add(key, item);
        }

        public string Retrieve(string key) 
        {
            if (key == null)
            {
                _logger.Log(LogLevel.Warning, $@"Tried to retrieve null key");
                return null;
            }
            if (!_items.ContainsKey(key))
            {
                _logger.Log(LogLevel.Warning, $@"Tried to retrieve password for unknown key [{key}]");
                return null;
            }
            var item = _items[key];

            if (_dateTimeProvider.Now > item.ExpireDt)
            {
                _logger.Log(LogLevel.Warning, $@"Tried to retrieve password for key [{key}] after date is expired. Key set at [{item.CreatedDt}] and expired at [{item.ExpireDt}]");
                _items.Remove(key); // ensure "read-once" is implemented
                return null;
            }
            _items.Remove(key); // ensure "read-once" is implemented
            return item.EncryptedPassword;
        }
    }
}
