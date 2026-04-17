namespace Snappass;

public sealed class ExpiredSecretCleaner(
	IServiceScopeFactory scopeFactory,
	ILogger<ExpiredSecretCleaner> logger) : BackgroundService
{
	private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);
	private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(30);

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		try { await Task.Delay(InitialDelay, stoppingToken); }
		catch (OperationCanceledException) { return; }

		while (!stoppingToken.IsCancellationRequested)
		{
			try
			{
				await using var scope = scopeFactory.CreateAsyncScope();
				var store = scope.ServiceProvider.GetRequiredService<ISecretStore>();
				var deleted = store.PurgeExpired();
				if (deleted > 0)
				{
					logger.LogInformation("Purged {Count} expired secret(s)", deleted);
				}
			}
			catch (Exception ex)
			{
				logger.LogError(ex, "Expired-secret purge failed");
			}

			try { await Task.Delay(Interval, stoppingToken); }
			catch (OperationCanceledException) { break; }
		}
	}
}
