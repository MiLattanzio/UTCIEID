using Tmds.DBus.Protocol;

namespace UTCie.Linux;

public static class LomiriHaptics
{
    /// <summary>Brief card-detection cue. Missing feedback hardware must never interrupt NFC.</summary>
    public static async Task CardDetectedAsync()
    {
        try
        {
            using var connection = new DBusConnection(DBusAddress.System ?? "unix:path=/var/run/dbus/system_bus_socket");
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await connection.ConnectAsync().AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
            MessageBuffer message;
            using (var writer = connection.GetMessageWriter())
            {
                writer.WriteMethodCallHeader(destination: "com.lomiri.hfd", path: "/com/lomiri/hfd",
                    @interface: "com.lomiri.hfd.Vibrator", member: "vibrate", signature: "i");
                writer.WriteInt32(100);
                message = writer.CreateMessage();
            }
            var pending = connection.CallMethodAsync(message);
            try { await pending.WaitAsync(deadline.Token).ConfigureAwait(false); }
            catch
            {
                _ = pending.ContinueWith(t => { _ = t.Exception; }, CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
        catch { /* Optional feedback, including on desktop systems without hfd. */ }
    }
}
