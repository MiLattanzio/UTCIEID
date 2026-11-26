using System.Buffers.Binary;
using System.Diagnostics;
using NUnit.Framework;
using UTCIEID.App;
using UTCie.Linux;
using UTCie.Sdk.Authentication;
using ZXing;
using ZXing.QrCode;

namespace UTCie.Tests;

public class CameraTests
{
    private static byte[] Header(int width, int height, int angle, int length, int magic = 0x314D4143)
    {
        byte[] bytes = new byte[20];
        int[] values = [magic, width, height, angle, length];
        for (int i = 0; i < values.Length; i++) BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(i * 4), values[i]);
        return bytes;
    }

    [Test] public async Task ReadsOneFrameWithoutConsumingTheNext()
    {
        using var stream = new MemoryStream([..Header(2, 2, 90, 4), 1, 2, 3, 4, ..Header(2, 2, 90, 4), 5, 6, 7, 8]);
        var first = await CameraFrame.ReadAsync(stream, default);
        var second = await CameraFrame.ReadAsync(stream, default);
        Assert.That(first.Luminance, Is.EqualTo(new byte[] { 1, 2, 3, 4 }));
        Assert.That(second.Luminance, Is.EqualTo(new byte[] { 5, 6, 7, 8 }));
    }

    [TestCase(0, 2, 0, 0)] [TestCase(4096, 960, 0, 3932160)]
    [TestCase(2, 2, 45, 4)] [TestCase(2, 2, 0, int.MaxValue)] [TestCase(2, 2, 0, -1)]
    public void BadCameraHeadersAreRejectedBeforeAllocation(int w, int h, int angle, int length)
    {
        using var stream = new MemoryStream(Header(w, h, angle, length));
        Assert.ThrowsAsync<InvalidDataException>(async () => await CameraFrame.ReadAsync(stream, default));
    }

    [Test] public void TruncatedCameraDataAndBadMagicAreRejected()
    {
        using var truncated = new MemoryStream([..Header(2, 2, 0, 4), 1]);
        Assert.ThrowsAsync<EndOfStreamException>(async () => await CameraFrame.ReadAsync(truncated, default));
        using var wrong = new MemoryStream(Header(2, 2, 0, 4, 0));
        Assert.ThrowsAsync<InvalidDataException>(async () => await CameraFrame.ReadAsync(wrong, default));
    }

    [TestCase(0, new byte[] { 1, 2, 3, 4, 5, 6 })]
    [TestCase(90, new byte[] { 5, 3, 1, 6, 4, 2 })]
    [TestCase(180, new byte[] { 6, 5, 4, 3, 2, 1 })]
    [TestCase(270, new byte[] { 2, 4, 6, 1, 3, 5 })]
    public void PreviewUsesSensorOrientation(int angle, byte[] expected)
    {
        var image = new CameraFrame(2, 3, angle, [1, 2, 3, 4, 5, 6]).ToBgra();
        Assert.That(image.Width, Is.EqualTo(angle % 180 == 0 ? 2 : 3));
        Assert.That(image.Height, Is.EqualTo(angle % 180 == 0 ? 3 : 2));
        Assert.That(image.Pixels.Where((_, i) => i % 4 == 0), Is.EqualTo(expected));
        Assert.That(image.Pixels.Where((_, i) => i % 4 == 3), Is.All.EqualTo(255));
    }

    [TestCase(0)] [TestCase(90)] [TestCase(180)] [TestCase(270)]
    public void DecodesLiveLuminanceQrAtEveryCameraOrientation(int rotation)
    {
        string qr = QrAuthenticationTests.Qr.Replace("Accedi%20a+INPS", "Accesso al servizio INPS");
        var source = new BarcodeWriterPixelData { Format = BarcodeFormat.QR_CODE,
            Options = new QrCodeEncodingOptions { Width = 500, Height = 500, Margin = 4 } }.Write(qr);
        byte[] luminance = source.Pixels.Where((_, i) => i % 4 == 0).ToArray();
        var rotated = new CameraFrame(500, 500, rotation, luminance).ToBgra();
        var rotatedLuma = rotated.Pixels.Where((_, i) => i % 4 == 0).ToArray();
        Assert.That(CieQrDecoder.TryDecodeLuminance(rotatedLuma, rotated.Width, rotated.Height), Is.EqualTo(qr));
        Assert.That(CieQrDecoder.TryDecodeLuminance(new byte[400], 20, 20), Is.Null);
    }

    [Test] public async Task CameraScanLoadsRequestWithoutStartingNfcOrReadingPin()
    {
        var simulator = new SimulatedCie();
        var reader = new FakeReader(simulator);
        var model = new MainViewModel(reader) { ReadCameraQrAsync = _ => Task.FromResult<string?>(QrAuthenticationTests.Qr) };
        model.ScanQrCommand.Execute(null);
        await WaitForIdle(model);
        Assert.That(model.RequestLink, Is.EqualTo(QrAuthenticationTests.Qr));
        Assert.That(model.SelectedTab, Is.EqualTo(1));
        Assert.That(model.Status, Is.EqualTo("QR riconosciuto"));
        Assert.That(model.HasOtp, Is.False);
        Assert.That(model.Pin, Is.Empty);
        Assert.That(simulator.PinVerifications, Is.Zero);
        Assert.That(model.ScanningQr, Is.False);
    }

    [Test] public async Task BackgroundingCancelsCameraAndDiscardsLateResult()
    {
        var ready = new TaskCompletionSource<string?>();
        CancellationToken scanToken = default;
        var model = new MainViewModel(new FakeReader(new SimulatedCie()))
        {
            ReadCameraQrAsync = token => { scanToken = token; return ready.Task; }
        };
        model.ScanQrCommand.Execute(null);
        Assert.That(model.ScanningQr, Is.True);
        Assert.That(model.Busy, Is.True);
        model.OnDeactivated();
        Assert.That(scanToken.IsCancellationRequested, Is.True);
        ready.SetResult(QrAuthenticationTests.Qr);
        await WaitForIdle(model);
        Assert.That(model.RequestLink, Is.Empty);
        Assert.That(model.ScanningQr, Is.False);
    }

    [Test] public async Task CameraDoesNotAcceptForeignQrAsAnAuthenticationRequest()
    {
        var model = new MainViewModel(new FakeReader(new SimulatedCie()))
            { ReadCameraQrAsync = _ => Task.FromResult<string?>("https://example.org/not-a-cie") };
        model.ScanQrCommand.Execute(null);
        await WaitForIdle(model);
        Assert.That(model.Error, Is.True);
        Assert.That(model.RequestService, Is.Empty);
        Assert.That(model.HasOtp, Is.False);
    }

    [TestCase(false)] [TestCase(true)]
    public async Task CancelledScannerClosesItsCaptureProcess(bool stalledDriver)
    {
        if (!OperatingSystem.IsLinux()) { Assert.Ignore("Linux process lifecycle test"); return; }
        string directory = Path.Combine(Path.GetTempPath(), "utcieid-camera-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string script = Path.Combine(directory, "camera"), pidFile = Path.Combine(directory, "pid");
        await File.WriteAllTextAsync(script, "#!/usr/bin/python3\nimport os,sys,struct\n" +
            "open(os.path.join(os.path.dirname(__file__),'pid'),'w').write(str(os.getpid()))\n" +
            "sys.stdout.buffer.write(struct.pack('<5I',0x314D4143,20,20,0,400)+bytes(400))\nsys.stdout.buffer.flush()\n" +
            (stalledDriver ? "import time\ntime.sleep(30)\n" : "sys.stdin.buffer.read()\n"));
        File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            Assert.ThrowsAsync<OperationCanceledException>(async () => await new QrCameraScanner(script).ScanAsync((_, _) =>
                { cancel.Cancel(); return Task.CompletedTask; }, cancel.Token));
            int pid = int.Parse(await File.ReadAllTextAsync(pidFile));
            Assert.Throws<ArgumentException>(() => Process.GetProcessById(pid));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Test] public async Task RefocusSendsControlWithoutClosingCapture()
    {
        if (!OperatingSystem.IsLinux()) { Assert.Ignore("Linux process lifecycle test"); return; }
        string directory = Path.Combine(Path.GetTempPath(), "utcieid-camera-focus-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string script = Path.Combine(directory, "camera");
        await File.WriteAllTextAsync(script, "#!/usr/bin/python3\nimport sys,struct\n" +
            "frame=struct.pack('<5I',0x314D4143,20,20,0,400)+bytes(400)\n" +
            "sys.stdout.buffer.write(frame)\nsys.stdout.buffer.flush()\n" +
            "assert sys.stdin.buffer.read(1)==b'f'\n" +
            "sys.stdout.buffer.write(frame)\nsys.stdout.buffer.flush()\nsys.stdin.buffer.read()\n");
        File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var scanner = new QrCameraScanner(script);
        int frames = 0;
        try
        {
            Assert.ThrowsAsync<OperationCanceledException>(async () => await scanner.ScanAsync((_, _) =>
            {
                if (++frames == 1) scanner.RequestFocus();
                else cancel.Cancel();
                return Task.CompletedTask;
            }, cancel.Token));
            Assert.That(frames, Is.EqualTo(2), "The worker received refocus and continued streaming.");
        }
        finally { Directory.Delete(directory, true); }
    }

    private static async Task WaitForIdle(MainViewModel model)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (model.Busy) await Task.Delay(5, timeout.Token);
    }
}
