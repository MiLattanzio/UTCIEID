using Tmds.DBus.Protocol;

namespace UTCie.Linux;

public static class LomiriUrlLauncher
{
    public static async Task<bool> OpenAsync(Uri uri, CancellationToken token = default)
    {
        if (uri.Scheme != Uri.UriSchemeHttps) throw new ArgumentException("È richiesto un URL HTTPS.", nameof(uri));
        using var connection = new DBusConnection(DBusAddress.Session ?? throw new InvalidOperationException("Session bus non disponibile."));
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        await connection.ConnectAsync().AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
        MessageBuffer message;
        using (var writer = connection.GetMessageWriter())
        {
            writer.WriteMethodCallHeader(destination: "com.lomiri.URLDispatcher", path: "/com/lomiri/URLDispatcher",
                @interface: "com.lomiri.URLDispatcher", member: "DispatchURL", signature: "ss");
            writer.WriteString(uri.AbsoluteUri);
            writer.WriteString("");
            message = writer.CreateMessage();
        }
        var pending = connection.CallMethodAsync(message);
        try { await pending.WaitAsync(deadline.Token).ConfigureAwait(false); return true; }
        catch
        {
            _ = pending.ContinueWith(t => { _ = t.Exception; }, CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            throw;
        }
    }
}
