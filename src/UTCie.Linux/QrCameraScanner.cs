using System.Diagnostics;
using UTCie.Sdk.Authentication;

namespace UTCie.Linux;

/// <summary>Live, memory-only QR scanning. The child inherits the app's confinement.</summary>
public sealed class QrCameraScanner(string? helperPath = null)
{
    private int _focusRequested;
    public void RequestFocus() => Interlocked.Exchange(ref _focusRequested, 1);

    public async Task<string> ScanAsync(Func<CameraFrame, CancellationToken, Task> preview, CancellationToken token)
    {
        string path = helperPath ?? Path.Combine(AppContext.BaseDirectory, "utcieid-camera");
        if (!OperatingSystem.IsLinux() || !File.Exists(path))
            throw new QrScanException("La fotocamera richiede la versione Ubuntu Touch di UTCIEID.");
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(path)
            {
                UseShellExecute = false, RedirectStandardInput = true,
                RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true
            }
        };
        try
        {
            if (!process.Start()) throw new QrScanException("Impossibile avviare la fotocamera.");
        }
        catch (System.ComponentModel.Win32Exception) { throw new QrScanException("Impossibile avviare la fotocamera."); }
        // Drain native library diagnostics without retaining or forwarding them.
        var drain = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
        try
        {
            bool first = true;
            while (true)
            {
                token.ThrowIfCancellationRequested();
                if (Interlocked.Exchange(ref _focusRequested, 0) != 0)
                {
                    await process.StandardInput.WriteAsync("f".AsMemory(), token).ConfigureAwait(false);
                    await process.StandardInput.FlushAsync(token).ConfigureAwait(false);
                }
                using var frameTimeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                frameTimeout.CancelAfter(TimeSpan.FromSeconds(first ? 60 : 6));
                CameraFrame frame;
                try { frame = await CameraFrame.ReadAsync(process.StandardOutput.BaseStream, frameTimeout.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (!token.IsCancellationRequested)
                { throw new QrScanException("La fotocamera non invia immagini. Chiudi le altre app che la usano e riprova."); }
                first = false;
                try
                {
                    await preview(frame, token).ConfigureAwait(false);
                    var link = CieQrDecoder.TryDecodeLuminance(frame.Luminance, frame.Width, frame.Height);
                    if (link is not null) return link;
                }
                finally { Array.Clear(frame.Luminance); }
            }
        }
        catch (EndOfStreamException)
        {
            token.ThrowIfCancellationRequested();
            throw new QrScanException("Fotocamera non disponibile. Consenti l'accesso alla fotocamera e chiudi eventuali altre app che la usano.");
        }
        catch (InvalidDataException) { throw new QrScanException("Il formato della fotocamera non è supportato su questo dispositivo."); }
        finally
        {
            process.StandardInput.Close();
            try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); }
            catch (TimeoutException)
            {
                // The worker does not spawn children. Traversing /proc to kill a
                // process tree is forbidden by Ubuntu Touch's app confinement.
                try { if (!process.HasExited) process.Kill(); }
                catch (InvalidOperationException) when (process.HasExited) { }
                await process.WaitForExitAsync().ConfigureAwait(false);
            }
            await drain.ConfigureAwait(false);
        }
    }
}
