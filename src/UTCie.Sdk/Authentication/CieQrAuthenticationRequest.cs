namespace UTCie.Sdk.Authentication;

/// <summary>Desktop + NFC smartphone request. OriginalUrl is signed byte-for-byte, never normalized.</summary>
public sealed class CieQrAuthenticationRequest
{
    public CieEnvironment Environment { get; }
    public string OriginalUrl { get; }
    public string OperationId { get; }
    public string DocumentNumber { get; }
    public string ServiceName { get; }

    private CieQrAuthenticationRequest(CieEnvironment environment, string url, string operationId, string documentNumber, string serviceName)
        => (Environment, OriginalUrl, OperationId, DocumentNumber, ServiceName) = (environment, url, operationId, documentNumber, serviceName);

    public static CieQrAuthenticationRequest Parse(string link, CieEnvironment environment)
    {
        CieAuthenticationRequest.ValidateEscapes(link);
        var root = CieEndpoint.For(environment).BaseUri;
        // The official desktop QR contains literal ASCII spaces in opText.
        // Preserve those bytes for the signature; only the URI prefix must be space-free.
        int queryStart = link.IndexOf('?');
        if (link.Length > 8192 || link != link.Trim() || queryStart < 0 ||
            link[..queryStart].Contains(' ') || link.Any(c => char.IsWhiteSpace(c) && c != ' ') ||
            !Uri.TryCreate(link, UriKind.Absolute, out var uri) ||
            uri.Scheme != "https" || !uri.IsDefaultPort || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 ||
            !uri.IdnHost.Equals(root.IdnHost, StringComparison.OrdinalIgnoreCase) || uri.AbsolutePath != "/idp/erroreQr.jsp")
            throw new ArgumentException("Il QR non è una richiesta CIE con OTP dell'ambiente selezionato.");
        var query = CieAuthenticationRequest.ReadQuery(uri);
        string Required(string key) => query.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value : throw new ArgumentException($"Parametro {key} assente nel QR CIE.");
        if (Required("opType") != "login" || Required("IdPName") != root.AbsoluteUri)
            throw new ArgumentException("Operazione o servizio del QR CIE non valido.");
        string op = Required("opId"), document = Required("userId"), service = Required("SPName");
        if (op.Length > 256 || op.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '_' and not '-'))
            throw new ArgumentException("Identificativo della richiesta QR non valido.");
        if (document.Length != 9 || !document.All(char.IsAsciiLetterOrDigit))
            throw new ArgumentException("Numero del documento nel QR non valido.");
        if (service.Length > 512 || !Uri.TryCreate(service, UriKind.Absolute, out var sp) ||
            sp.Scheme is not ("https" or "http") || sp.UserInfo.Length != 0)
            throw new ArgumentException("Servizio destinatario nel QR non valido.");
        return new(environment, link, op, document, sp.IdnHost);
    }

    // Prevent accidental logging of the URL, operation ID and document number.
    public override string ToString() => "Richiesta CIE QR con OTP";
}
