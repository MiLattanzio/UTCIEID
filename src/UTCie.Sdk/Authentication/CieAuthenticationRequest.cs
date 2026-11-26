namespace UTCie.Sdk.Authentication;

public enum CieEnvironment { Production, Preproduction, Collaudo }

public sealed class CieUnsupportedFlowException(string message, string guidance) : ArgumentException(message)
{
    public string Guidance { get; } = guidance;
}

public sealed record CieEndpoint(CieEnvironment Environment, Uri BaseUri)
{
    public static CieEndpoint For(CieEnvironment environment) => new(environment, new Uri(environment switch
    {
        CieEnvironment.Production => "https://idserver.servizicie.interno.gov.it/idp/",
        CieEnvironment.Preproduction => "https://preproduzione.idserver.servizicie.interno.gov.it/idp/",
        CieEnvironment.Collaudo => "https://collaudo.idserver.servizicie.interno.gov.it/idp/",
        _ => throw new ArgumentOutOfRangeException(nameof(environment))
    }));
}

/// <summary>Validated OpenApp request. The untrusted link never selects the network endpoint.</summary>
public sealed record CieAuthenticationRequest
{
    public required CieEnvironment Environment { get; init; }
    public required string AuthnRequest { get; init; }
    public required string Name { get; init; }
    public required string Value { get; init; }
    public string Operation { get; init; } = "Accesso con CIE";

    public static CieAuthenticationRequest Parse(string link, CieEnvironment environment)
    {
        ValidateEscapes(link);
        var endpoint = CieEndpoint.For(environment);
        if (link.Length > 65536 || !Uri.TryCreate(link, UriKind.Absolute, out var uri) ||
            uri.Scheme != "https" || !uri.IsDefaultPort || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 ||
            !uri.IdnHost.Equals(endpoint.BaseUri.IdnHost, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Inserisci un link HTTPS /idp/OpenApp dell'ambiente CIE selezionato.");
        // These are genuine CieID QR formats, but they use different protocols.
        // Never reinterpret their operation IDs as OpenApp authentication requests.
        if (uri.AbsolutePath == "/idp/erroreQr.jsp")
            throw new CieUnsupportedFlowException("Questa richiesta usa il flusso QR con OTP",
                "La richiesta deve essere elaborata come QR con OTP, non come collegamento OpenApp.");
        if (uri.AbsolutePath == "/idp/login/livello2QR")
            throw new CieUnsupportedFlowException("Accesso QR di livello 2 non supportato",
                "Questo flusso richiede la certificazione del dispositivo CieID, non implementata in UTCIEID. Generare un nuovo QR non risolve questa limitazione.");
        if (uri.AbsolutePath != "/idp/OpenApp")
            throw new ArgumentException("Inserisci un link HTTPS /idp/OpenApp dell'ambiente CIE selezionato.");
        var query = ReadQuery(uri);
        string Required(string name) => query.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value : throw new ArgumentException($"Parametro {name} assente nel link CIE.");
        var result = new CieAuthenticationRequest
        {
            Environment = environment, AuthnRequest = Required("authnRequestString"), Name = Required("name"), Value = Required("value"),
            Operation = query.GetValueOrDefault("OpText", "Accesso con CIE")
        };
        if (result.Name.Length > 64 || result.Name.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '_') || result.Name.Equals("challenge", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Nome parametro di continuazione non valido.");
        return result;
    }

    internal static Dictionary<string, string> ReadQuery(Uri uri)
    {
        var query = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var pair = part.Split('=', 2);
            string key = Decode(pair[0]), value = pair.Length == 2 ? Decode(pair[1]) : "";
            if (!query.TryAdd(key, value)) throw new ArgumentException("Il link contiene parametri duplicati.");
        }
        return query;
    }

    private static string Decode(string value)
    {
        ValidateEscapes(value);
        var decoded = Uri.UnescapeDataString(value.Replace('+', ' '));
        if (decoded.Any(char.IsControl)) throw new ArgumentException("Caratteri di controllo nel link.");
        return decoded;
    }

    internal static void ValidateEscapes(string value)
    {
        for (int i = 0; i < value.Length; i++)
            if (value[i] == '%' && (i + 2 >= value.Length || !Uri.IsHexDigit(value[i + 1]) || !Uri.IsHexDigit(value[i + 2])))
                throw new ArgumentException("Escape URL non valido.");
        if (value.Any(char.IsControl)) throw new ArgumentException("Caratteri di controllo nel link.");
    }
}
