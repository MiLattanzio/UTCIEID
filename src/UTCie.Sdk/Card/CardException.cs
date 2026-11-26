namespace UTCie.Sdk.Card;

public class CardException(string message) : Exception(message);
public sealed class CardProtocolException(string message) : CardException(message);
public sealed class NotCieException() : CardException("La carta rilevata non è una CIE compatibile.");
public sealed class PinException(int remainingAttempts)
    : CardException(remainingAttempts == 0 ? "PIN bloccato. È necessario il PUK tramite un servizio abilitato." : $"PIN errato. Tentativi rimasti: {remainingAttempts}.")
{
    public int RemainingAttempts { get; } = remainingAttempts;
}
public sealed class CardStatusException(ushort status)
    : CardException($"La carta ha rifiutato il comando (SW {status:X4}).")
{
    public ushort Status { get; } = status;
}

public static class CiePin
{
    public static bool IsValid(ReadOnlySpan<char> pin)
    {
        if (pin.Length != 8) return false;
        foreach (var c in pin) if (c is < '0' or > '9') return false;
        return true;
    }
}
