using NUnit.Framework;
using UTCIEID.App;
using UTCie.Sdk.Card;

namespace UTCie.Tests;

public class RegistrationTests
{
    [TestCase("/idp/login/livello2QR", "livello 2")]
    public async Task UnsupportedQrSurvivesStartupRefreshAndNeverReadsPin(string path, string message)
    {
        var store = new FakeCredentials { Card = new(new string('1', 64)), SavedPin = "12345678" };
        var simulator = new SimulatedCie();
        var model = new MainViewModel(new FakeReader(simulator),
            "https://idserver.servizicie.interno.gov.it" + path + "?opId=synthetic&opType=login", store);
        await model.RefreshAsync();
        Assert.That(model.SelectedTab, Is.EqualTo(1));
        Assert.That(model.Error, Is.True);
        Assert.That(model.Status, Does.Contain(message));
        model.ContinueCommand.Execute(null);
        await Finished(model);
        Assert.That(model.Status, Does.Contain(message));
        Assert.That(store.PinReads, Is.Zero);
        Assert.That(simulator.PinVerifications, Is.Zero);
        Assert.That(model.HasCompletion, Is.False);
    }

    [Test] public async Task LocateCardSignalsDetectionWithoutPinAndKeepsEnteredPin()
    {
        var transport = new TranscriptTransport(
            ("00A4040C0DA0000000308000000009816001", "6A82"),
            ("00A4040406A00000000039", "9000"),
            ("00A40204021001", "9000"),
            ("00B000000C", "0102030405060708090A0B0C9000"));
        var model = new MainViewModel(new FakeReader(transport));
        int signals = 0;
        model.CardDetected += () => { signals++; Assert.That(model.NfcGuideTitle, Does.Contain("tienila ferma")); };
        await model.RefreshAsync(); model.Pin = "12345678";
        model.LocateCardCommand.Execute(null); await Finished(model);
        Assert.That(signals, Is.EqualTo(1));
        Assert.That(model.Error, Is.False);
        Assert.That(model.Status, Is.EqualTo("CIE riconosciuta senza PIN"));
        Assert.That(model.Pin, Is.EqualTo("12345678"));
        Assert.That(model.HasRegistration, Is.False);
        Assert.That(model.NfcGuideTitle, Does.Contain("allontanare"));
    }

    [Test] public async Task SuccessfulReadStoresFullPinAndClearsTransientCopy()
    {
        var store = new FakeCredentials();
        var model = new MainViewModel(new FakeReader(new SimulatedCie()), credentials: store);
        await model.RefreshAsync();
        model.Pin = "12345678";
        model.ContinueCommand.Execute(null);
        await Finished(model);
        Assert.That(model.Error, Is.False, model.Detail);
        Assert.That(model.HasRegistration, Is.True);
        Assert.That(model.EnterPin, Is.False);
        Assert.That(model.Pin, Is.Empty);
        Assert.That(store.SavedPin, Is.EqualTo("12345678"));
        Assert.That(store.PinBuffer.ToArray(), Is.All.EqualTo('\0'));
        model.ForgetCardCommand.Execute(null);
        await Finished(model);
        Assert.That(model.HasRegistration, Is.False);
        Assert.That(store.SavedPin, Is.Null);
    }
    [Test] public async Task WrongPinDoesNotRegisterOrStoreAnything()
    {
        var store = new FakeCredentials();
        var simulator = new SimulatedCie();
        var model = new MainViewModel(new FakeReader(simulator), credentials: store);
        await model.RefreshAsync();
        model.Pin = "00000000";
        model.ContinueCommand.Execute(null);
        await Finished(model);
        Assert.That(store.SavedPin, Is.Null);
        Assert.That(model.HasRegistration, Is.False);
        Assert.That(simulator.PinVerifications, Is.EqualTo(1));
        Assert.That(model.Pin, Is.Empty);
    }
    [Test] public async Task InterruptedReadRetainsPinForManualRetryOnly()
    {
        var transport = new TranscriptTransport(("00A4040C0DA0000000308000000009816001", "6F00"));
        var model = new MainViewModel(new FakeReader(transport));
        await model.RefreshAsync(); model.Pin = "12345678";
        model.ContinueCommand.Execute(null); await Finished(model);
        Assert.That(model.Pin, Is.EqualTo("12345678"));
        Assert.That(model.CanContinue, Is.True);
        model.OnDeactivated();
        Assert.That(model.Pin, Is.Empty);
    }
    [Test] public async Task KeyringFailureDoesNotClaimRegistration()
    {
        var store = new FakeCredentials { FailSave = true };
        var model = new MainViewModel(new FakeReader(new SimulatedCie()), credentials: store);
        await model.RefreshAsync(); model.Pin = "12345678";
        model.ContinueCommand.Execute(null);
        await Finished(model);
        Assert.That(model.HasRegistration, Is.False);
        Assert.That(model.Error, Is.True);
        Assert.That(model.Pin, Is.EqualTo("12345678"));
    }
    [Test] public async Task SavedPinIsNotSentToAnotherCard()
    {
        var store = new FakeCredentials { Card = new(new string('1', 64)), SavedPin = "12345678" };
        var simulator = new SimulatedCie();
        var model = new MainViewModel(new FakeReader(simulator), credentials: store);
        await model.RefreshAsync();
        Assert.That(model.CanContinue, Is.True);
        model.ContinueCommand.Execute(null);
        await Finished(model);
        Assert.That(simulator.PinVerifications, Is.Zero);
        Assert.That(model.Error, Is.True);
    }
    [Test] public async Task FailedForgetPreservesRegistration()
    {
        var store = new FakeCredentials { Card = new(new string('1', 64)), SavedPin = "12345678", FailForget = true };
        var model = new MainViewModel(new FakeReader(new TranscriptTransport()), credentials: store);
        await model.RefreshAsync();
        model.ForgetCardCommand.Execute(null); await Finished(model);
        Assert.That(model.HasRegistration, Is.True);
        Assert.That(store.SavedPin, Is.EqualTo("12345678"));
        Assert.That(model.Error, Is.True);
    }
    private static async Task Finished(MainViewModel model)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        while (model.Busy) await Task.Delay(5, timeout.Token);
    }
    private sealed class FakeCredentials : ICardCredentialStore
    {
        public RegisteredCard? Card { get; set; }
        public string? SavedPin { get; set; }
        public ReadOnlyMemory<char> PinBuffer { get; private set; }
        public bool FailSave { get; init; }
        public bool FailForget { get; init; }
        public int PinReads { get; private set; }
        public Task<RegisteredCard?> GetRegistrationAsync(CancellationToken token = default) => Task.FromResult(Card);
        public Task SaveAsync(RegisteredCard card, ReadOnlyMemory<char> pin, CancellationToken token = default)
        {
            if (FailSave) throw new CredentialStoreException("Test keyring locked");
            Card = card; SavedPin = pin.ToString(); PinBuffer = pin;
            return Task.CompletedTask;
        }
        public Task<char[]> GetPinAsync(RegisteredCard card, CancellationToken token = default)
        {
            PinReads++;
            return Task.FromResult(SavedPin!.ToCharArray());
        }
        public Task ForgetAsync(RegisteredCard card, CancellationToken token = default)
        {
            if (FailForget) throw new CredentialStoreException("Test deletion failed");
            Card = null; SavedPin = null; return Task.CompletedTask;
        }
    }
}
