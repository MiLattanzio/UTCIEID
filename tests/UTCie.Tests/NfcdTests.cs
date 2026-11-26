using System.Diagnostics;
using NUnit.Framework;
using Tmds.DBus.Protocol;
using UTCie.Linux;
using UTCie.Sdk.Card;

namespace UTCie.Tests;

public class NfcdTests
{
    [Test] public async Task RealDbusDiscoveryAcquireAndApduWireFormat()
    {
        using var daemon = Process.Start(new ProcessStartInfo("dbus-daemon")
        {
            ArgumentList = { "--session", "--nofork", "--print-address=1", "--address=unix:tmpdir=/tmp" },
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false
        })!;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var address = await daemon.StandardOutput.ReadLineAsync(deadline.Token);
            Assert.That(address, Is.Not.Null);
            using var service = new DBusConnection(address!);
            await service.ConnectAsync();
            var handler = new FakeNfcd();
            service.AddMethodHandler(handler);
            await service.RequestNameAsync("org.neard");
            var reader = new NfcdReader(address!, "org.neard");
            Assert.That((await reader.GetStatusAsync(deadline.Token)).Enabled, Is.True);
            await using (var card = await reader.WaitForCardAsync(deadline.Token))
            {
                var response = await card.TransceiveAsync(Convert.FromHexString("00A4020402100100"), deadline.Token);
                Assert.That(response, Is.EqualTo(new byte[] { 1, 2, 0x90, 0 }));
                Assert.That(handler.Acquired, Is.True);
                Assert.That(handler.LastLe, Is.EqualTo(256));
                Assert.That(handler.Data, Is.EqualTo(new byte[] { 0x10, 1 }));
                Assert.That(handler.Mode, Is.EqualTo(2));
                Assert.That(handler.SkipNdef, Is.True);
                await card.TransceiveAsync(Convert.FromHexString("00A40400"), deadline.Token);
                Assert.That(handler.LastLe, Is.Zero, "No Le is distinct from wire 00 (256)");
                byte[] extendedData = Enumerable.Range(0, 264).Select(i => (byte)i).ToArray();
                await card.TransceiveAsync(new ApduCommand(0, 0xa4, 0, 0, extendedData, 256).Encode(), deadline.Token);
                Assert.That(handler.Data, Is.EqualTo(extendedData));
                Assert.That(handler.LastLe, Is.EqualTo(256));
            }
        }
        finally { if (!daemon.HasExited) daemon.Kill(); await daemon.WaitForExitAsync(); }
    }

    private sealed class FakeNfcd : IPathMethodHandler
    {
        public string Path => "/";
        public bool HandlesChildPaths => true;
        public bool Acquired { get; private set; }
        public uint LastLe { get; private set; }
        public uint Mode { get; private set; }
        public bool SkipNdef { get; private set; }
        public byte[] Data { get; private set; } = [];
        public ValueTask HandleMethodAsync(MethodContext context)
        {
            var reader = context.Request.GetBodyReader();
            string member = context.Request.MemberAsString!;
            switch (member)
            {
                case "GetAdapters": case "GetTags":
                    using (var w = context.CreateReplyWriter("ao"))
                    { w.WriteArray(new ObjectPath[] { new(member == "GetAdapters" ? "/nfc0" : "/nfc0/tag0") }); context.Reply(w.CreateMessage()); }
                    break;
                case "GetEnabled": case "GetPowered":
                    using (var w = context.CreateReplyWriter("b")) { w.WriteBool(true); context.Reply(w.CreateMessage()); }
                    break;
                case "GetInterfaces":
                    using (var w = context.CreateReplyWriter("as")) { w.WriteArray(new[] { "org.sailfishos.nfc.IsoDep" }); context.Reply(w.CreateMessage()); }
                    break;
                case "RequestMode":
                    Mode = reader.ReadUInt32(); Assert.That(reader.ReadUInt32(), Is.Zero);
                    using (var w = context.CreateReplyWriter("u")) { w.WriteUInt32(1); context.Reply(w.CreateMessage()); }
                    break;
                case "RequestParams":
                    Assert.That(context.Request.SignatureAsString, Is.EqualTo("a{sv}b"));
                    var parameters = reader.ReadDictionaryOfStringToVariantValue();
                    Assert.That(parameters.Count, Is.EqualTo(1));
                    Assert.That(parameters["T4_NDEF"].GetBool(), Is.False);
                    Assert.That(reader.ReadBool(), Is.False);
                    SkipNdef = true;
                    using (var w = context.CreateReplyWriter("u")) { w.WriteUInt32(2); context.Reply(w.CreateMessage()); }
                    break;
                case "Acquire":
                    Assert.That(reader.ReadBool(), Is.True); Acquired = true;
                    using (var w = context.CreateReplyWriter(null)) context.Reply(w.CreateMessage());
                    break;
                case "Transmit":
                    Assert.That(context.Request.SignatureAsString, Is.EqualTo("yyyyayu"));
                    Assert.That(reader.ReadByte(), Is.Zero); Assert.That(reader.ReadByte(), Is.EqualTo(0xa4));
                    reader.ReadByte(); reader.ReadByte(); Data = reader.ReadArrayOfByte(); LastLe = reader.ReadUInt32();
                    using (var w = context.CreateReplyWriter("ayyy")) { w.WriteArray(new byte[] { 1, 2 }); w.WriteByte(0x90); w.WriteByte(0); context.Reply(w.CreateMessage()); }
                    break;
                default: throw new InvalidOperationException(member);
            }
            return ValueTask.CompletedTask;
        }
    }
}
