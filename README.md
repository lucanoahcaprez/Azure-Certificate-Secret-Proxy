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
- Authorization rule (thumbprint): client cert must be in `ALLOWED_CLIENT_CERTS`. If you skip issuer validation, keep this allowlist populated.
- Authorization rule (issuer) **optional**: if `ALLOWED_ISSUER_CERTS` is set, the certificate chain must anchor to a listed CA that you uploaded and loaded. If unset/empty, issuer validation is skipped and trust relies on the thumbprint allowlist only.
- Input: `SecretName` via query string or JSON body `{ "SecretName": "<name>" }`.
- Output 200: JSON `{ SecretName, SecretValue, CertThumb, Workload }`.
- Output 401: cert missing, unauthorized thumbprint, or (when enabled) chain not trusted.
- Output 400: bad input.
- Output 404: secret not found for the selected workload.

## Workloads (select via `WORKLOAD`)
- `AppSettings`: reads the secret directly from app settings (default if `WORKLOAD` not set).
- `KeyVault`: uses managed identity to call Key Vault REST (`https://vault.azure.net`) and return the secret value. Set `KEYVAULT_NAME` or `KEYVAULT_URI` and grant the Function App identity `get` permission on secrets.
- `Table`: fetches a row from Azure Table Storage via SAS. Requires `TABLE_ENDPOINT` (e.g., `https://account.table.core.windows.net/Secrets`) and `TABLE_SAS_TOKEN` (starting with `?sv=`). Expects `PartitionKey='secret'` and `RowKey=<SecretName>`. Uses column `Value` by default; override with `TABLE_VALUE_FIELD`.
- Expandable: add new cases to the workload switch in `run.ps1` to support other backends (e.g., Cosmos DB, API call).

## Required app settings
- `ALLOWED_CLIENT_CERTS` = `THUMB1;THUMB2` (uppercase recommended). Mandatory when issuer validation is disabled.
- `ALLOWED_ISSUER_CERTS` = thumbprints of uploaded intermediate/root CAs that you trust for clients **(optional; leave empty to skip issuer validation)**.
- `WORKLOAD` = `AppSettings` or `KeyVault` or `Table`.
- For `AppSettings`: one app setting per secret, e.g., `MyStorageAccountKey=<value>`.
- For `KeyVault`: `KEYVAULT_NAME` (or `KEYVAULT_URI`) and managed identity with Secret Get permission.
- For `Table`: `TABLE_ENDPOINT`, `TABLE_SAS_TOKEN`, optional `TABLE_VALUE_FIELD`.
- `WEBSITE_LOAD_CERTIFICATES` = `*` (or include the specific issuer thumbprints) **only needed when `ALLOWED_ISSUER_CERTS` is set** so the Function runtime loads the uploaded CA certs into `Cert:\CurrentUser\My`.
- Standard Functions settings: `FUNCTIONS_WORKER_RUNTIME=powershell`, `AzureWebJobsStorage=...`.

## Deployment checklist
1. Deploy the function code.
2. Enable “Client certificate mode: Require” on the Function App.
3. Upload your intermediate/root CA certificates under TLS/SSL settings → Private Certificates (PFX) or Public Certificates (CER). Add their thumbprints to `ALLOWED_ISSUER_CERTS`. Ensure `WEBSITE_LOAD_CERTIFICATES` contains those thumbprints (or `*`).
4. Configure app settings above, including one setting per secret.
5. Ensure your ingress (Front Door/APIM/App Gateway) is configured to require client certificates and forward them (`X-ARR-ClientCert`) to the Function App.

## Client usage (PowerShell)
Prereqs: client certificate installed in `Cert:\CurrentUser\My` (or `LocalMachine\My`) on the calling machine. The script will automatically pick a certificate whose CN or SAN matches the device hostname (or FQDN). Override by passing `-Thumbprint`.

```powershell
.\client\requestSecret.ps1 `
  -FunctionUrl "https://<func>.azurewebsites.net/api/azfunctioncertificatesecretproxy" `
  -SecretName "MyStorageAccountKey" `
  -SkipCertCheck   # optional for non-production testing
```

## Local testing (optional)
- Add a `local.settings.json` with your secrets, `ALLOWED_CLIENT_CERTS`, and `ALLOWED_ISSUER_CERTS`.
- Start with `func start` (or `func start --cert <pfx> --key <key>` if you want mTLS locally).
- When not using mTLS locally, you can inject `X-ARR-ClientCert` for ad-hoc tests, but do not do this in production.

## Security notes
- Trust is two-layered when `ALLOWED_ISSUER_CERTS` is set: explicit client thumbprints plus CA chain validation to uploaded issuers. If you leave `ALLOWED_ISSUER_CERTS` empty, trust relies solely on the thumbprint allowlist—keep it populated.
- Limit access to the Function App and its app settings; rotate client certificates and secrets regularly.
- Prefer short-lived secrets; consider reintroducing Key Vault + managed identity later for stronger governance.


