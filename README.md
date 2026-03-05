## Purpose
A lightweight device-facing proxy that delivers secrets (e.g., storage account keys) to Windows endpoints over HTTPS with mutual TLS. Secrets live in Function App settings; Azure Key Vault is removed for this iteration.

## Architecture
- Windows endpoints call an Azure Function.
- The platform enforces client certificates; the function validates the presented certificate’s thumbprint and its chain.
- Only certificates that (1) match `ALLOWED_CLIENT_CERTS` and (2) build a chain to a configured intermediate/root (`ALLOWED_ISSUER_CERTS`) are accepted.
- Authorized calls return the requested secret from app settings; administrators manage secrets by updating app settings.

Diagram: [docs/architecture-diagram.drawio](/docs/architecture-diagram.drawio)

## Function behavior
- Trigger: HTTP GET/POST at `/api/azfunctioncertificatesecretproxy`.
- Authentication: mutual TLS; client certificate is forwarded in header `X-ARR-ClientCert`.
- Authorization:
  - Client cert thumbprint must be in `ALLOWED_CLIENT_CERTS` (semicolon-separated).
  - Certificate chain must anchor to one of the uploaded issuer certs listed in `ALLOWED_ISSUER_CERTS`.
- Input: `SecretName` via query string or JSON body `{ "SecretName": "<name>" }`.
- Output:
  - `200` with JSON `{ SecretName, SecretValue, CertThumb }`
  - `401` if cert missing/unauthorized/chain not trusted
  - `400` for bad input
  - `404` if the secret app setting is absent

## Required app settings
- `ALLOWED_CLIENT_CERTS` = `THUMB1;THUMB2` (uppercase recommended).
- `ALLOWED_ISSUER_CERTS` = thumbprints of uploaded intermediate/root CAs that you trust for clients.
- One app setting per secret, e.g., `MyStorageAccountKey=<value>`.
- `WEBSITE_LOAD_CERTIFICATES` = `*` (or include the specific issuer thumbprints) so the Function runtime loads the uploaded CA certs into `Cert:\CurrentUser\My`.
- Standard Functions settings: `FUNCTIONS_WORKER_RUNTIME=powershell`, `AzureWebJobsStorage=...`.

## Deployment checklist
1. Deploy the function code.
2. Enable “Client certificate mode: Require” on the Function App.
3. Upload your intermediate/root CA certificates under TLS/SSL settings → Private Certificates (PFX) or Public Certificates (CER). Add their thumbprints to `ALLOWED_ISSUER_CERTS`. Ensure `WEBSITE_LOAD_CERTIFICATES` contains those thumbprints (or `*`).
4. Configure app settings above, including one setting per secret.
5. Ensure your ingress (Front Door/APIM/App Gateway) is configured to require client certificates and forward them (`X-ARR-ClientCert`) to the Function App.

## Client usage (PowerShell)
Prereqs: client certificate installed in `Cert:\CurrentUser\My` on the calling machine.

```powershell
.\client\requestSecret.ps1 `
  -FunctionUrl "https://<func>.azurewebsites.net/api/azfunctioncertificatesecretproxy" `
  -SecretName "MyStorageAccountKey" `
  -Thumbprint "<THUMBPRINT>" `
  -SkipCertCheck   # optional for non-production testing
```

## Local testing (optional)
- Add a `local.settings.json` with your secrets, `ALLOWED_CLIENT_CERTS`, and `ALLOWED_ISSUER_CERTS`.
- Start with `func start` (or `func start --cert <pfx> --key <key>` if you want mTLS locally).
- When not using mTLS locally, you can inject `X-ARR-ClientCert` for ad-hoc tests, but do not do this in production.

## Security notes
- Trust is two-layered: explicit client thumbprints plus CA chain validation to uploaded issuers.
- Limit access to the Function App and its app settings; rotate client certificates and secrets regularly.
- Prefer short-lived secrets; consider reintroducing Key Vault + managed identity later for stronger governance.


