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

### Using a Certificate from the Windows Store

The script auto-discovers a certificate whose CN or SAN matches the local hostname:

```powershell
.\client\requestSecret.ps1 `
  -FunctionUrl "https://<func>.azurewebsites.net/api/azfunctioncertificatesecretproxy" `
  -SecretName "MyStorageAccountKey"
```

Or specify a certificate by thumbprint:

```powershell
.\client\requestSecret.ps1 `
  -FunctionUrl "https://<func>.azurewebsites.net/api/azfunctioncertificatesecretproxy" `
  -SecretName "MyStorageAccountKey" `
  -Thumbprint "A1B2C3D4..."
```

### Using a Certificate from a PFX File

Load a PFX file (helpful for automation or non-Store scenarios):

```powershell
.\client\requestSecret.ps1 `
  -FunctionUrl "https://<func>.azurewebsites.net/api/azfunctioncertificatesecretproxy" `
  -SecretName "MyStorageAccountKey" `
  -CertificatePath "C:\path\to\cert.pfx" `
  -CertificatePassword "pfx-password"
```

If the PFX has no password, omit `-CertificatePassword`.

### Debugging

Enable verbose logging to see additional details:

```powershell
.\client\requestSecret.ps1 `
  -FunctionUrl "https://..." `
  -SecretName "..." `
  -VerboseLogging
```

## Local testing (optional)
- Add a `local.settings.json` with your secrets, `ALLOWED_CLIENT_CERTS`, and `ALLOWED_ISSUER_CERTS`.
- Start with `func start` (or `func start --cert <pfx> --key <key>` if you want mTLS locally).
- When not using mTLS locally, you can inject `X-ARR-ClientCert` for ad-hoc tests, but do not do this in production.

## Security notes
- Trust is two-layered when `ALLOWED_ISSUER_CERTS` is set: explicit client thumbprints plus CA chain validation to uploaded issuers. If you leave `ALLOWED_ISSUER_CERTS` empty, trust relies solely on the thumbprint allowlist—keep it populated.
- Limit access to the Function App and its app settings; rotate client certificates and secrets regularly.
- Prefer short-lived secrets; consider reintroducing Key Vault + managed identity later for stronger governance.

## Certificate Validation Details

### Backend Validation Steps

The Azure Function backend validates client certificates in the following order:

1. **Extract from Header**: Read Base64-encoded certificate from `X-ARR-ClientCert` header (set by Azure App Service after TLS termination).
2. **Parse**: Convert Base64 to X509Certificate2 object.
3. **Check Validity Period**: Verify `NotBefore` ≤ now ≤ `NotAfter`.
4. **Check Enhanced Key Usage (EKU)**: Verify certificate has OID `1.3.6.1.5.5.7.3.2` (Client Authentication) unless disabled via `CERT_REQUIRE_EKU=false`.
5. **Check Thumbprint Allowlist** (if `ALLOWED_CLIENT_CERTS` is configured): Verify cert thumbprint is in allowlist.
6. **Check Chain Trust** (if `ALLOWED_ISSUER_CERTS` is configured): Build certificate chain and verify it anchors to one of the configured issuer certificates using custom root trust.
7. **Check Revocation** (configurable): If `CERT_REVOCATION_MODE=Online` or `Offline`, validate against CRL (default is `NoCheck` for performance).

If any step fails, return HTTP 401 with diagnostic details.

### Configuration for Certificate Validation

Create app settings on the Function App:

```
ALLOWED_CLIENT_CERTS=<THUMB1>;<THUMB2>;<THUMB3>          # Semicolon-separated client cert thumbprints (uppercase)
ALLOWED_ISSUER_CERTS=<ISSUER_THUMB1>;<ISSUER_THUMB2>     # Semicolon-separated CA cert thumbprints (optional)
CERT_REQUIRE_EKU=true                                     # Require Client Authentication EKU (default: true)
CERT_REVOCATION_MODE=NoCheck|Online|Offline               # CRL check mode (default: NoCheck)
WEBSITE_LOAD_CERTIFICATES=*                               # Load all uploaded certs into Cert:\CurrentUser\My (needed for issuer validation)
```

### Example: Issuer-Based Trust (Recommended)

If you want to trust any client cert signed by your CA (not just specific thumbprints):

1. Export your intermediate/root CA certificate as `.cer` (DER-encoded, no private key).
2. Upload it to Function App: **TLS/SSL settings** → **Public Certificates** → **Upload PEM/DER-encoded file**.
3. Note the certificate **thumbprint** from the upload dialog.
4. Set app settings:
   ```
   ALLOWED_ISSUER_CERTS=<CA_THUMBPRINT>
   CERT_REQUIRE_EKU=true
   WEBSITE_LOAD_CERTIFICATES=*
   ```
5. (Optional) Leave `ALLOWED_CLIENT_CERTS` empty; trust is now based on chain validation alone.
6. When a client connects, the backend validates that its certificate chain anchors to the CA you uploaded.

### Example: Thumbprint-Based Trust (Simpler, but Less Scalable)

If you want to explicitly list which client certificates are allowed:

1. Obtain the thumbprint of each client certificate (uppercase hex).
2. Set app setting:
   ```
   ALLOWED_CLIENT_CERTS=<THUMB1>;<THUMB2>;<THUMB3>
   ```
3. Leave `ALLOWED_ISSUER_CERTS` empty.
4. When a client connects, the backend checks if its thumbprint matches the allowlist. EKU and validity period are still validated.

## Verification Steps

### 1. Create a Test Client Certificate

Generate a self-signed certificate with Client Authentication EKU:

```powershell
# Create a client certificate valid for 1 year with Client Authentication EKU
$cert = New-SelfSignedCertificate `
  -Type Custom `
  -KeyUsage DigitalSignature `
  -Subject "CN=TestClient" `
  -KeyAlgorithm RSA `
  -KeyLength 2048 `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -NotAfter (Get-Date).AddYears(1) `
  -TextExtension "2.5.29.37={text}1.3.6.1.5.5.7.3.2"

Write-Host "Thumbprint: $($cert.Thumbprint)"
```

### 2. Get the Thumbprint

```powershell
Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=TestClient" } | Select-Object Thumbprint
```

### 3. Configure the Function App

```powershell
$thumbprint = "<cert-thumbprint>"
$resourceGroup = "your-rg"
$functionAppName = "your-func-app"

# Set allowed client cert thumbprint
az functionapp config appsettings set `
  -g $resourceGroup `
  -n $functionAppName `
  --settings ALLOWED_CLIENT_CERTS=$thumbprint

# Add a test secret (using AppSettings workload)
az functionapp config appsettings set `
  -g $resourceGroup `
  -n $functionAppName `
  --settings TestSecret="my-secret-value"
```

### 4. Enable Client Certificates and HTTPS

```powershell
$resourceGroup = "your-rg"
$functionAppName = "your-func-app"

# Enable client certificate negotiation and require it
az functionapp update --set clientCertEnabled=true `
  -g $resourceGroup -n $functionAppName

az functionapp config appsettings set `
  -g $resourceGroup -n $functionAppName `
  --settings WEBSITE_CLIENT_CERT_MODE=Required

# Enforce HTTPS-only
az functionapp update --set https_only=true `
  -g $resourceGroup -n $functionAppName

# Restart
az functionapp restart -g $resourceGroup -n $functionAppName
```

### 5. Test with the PowerShell Client

```powershell
.\client\requestSecret.ps1 `
  -FunctionUrl "https://<your-func>.azurewebsites.net/api/azfunctioncertificatesecretproxy" `
  -SecretName "TestSecret"
```

Expected output:
```
SecretName : TestSecret
SecretValue: my-secret-value
CertThumb  : <THUMBPRINT>
```

### 6. Test Failure Cases

#### Missing Client Certificate
```powershell
# Use Invoke-RestMethod without -Certificate
Invoke-RestMethod `
  -Uri "https://<func>.azurewebsites.net/api/azfunctioncertificatesecretproxy?SecretName=TestSecret" `
  -Method Get
```
Expected: **HTTP 401** — "Client certificate missing or unreadable"

#### Unauthorized Thumbprint
```powershell
# Use a different certificate
.\client\requestSecret.ps1 `
  -FunctionUrl "https://<func>.azurewebsites.net/api/azfunctioncertificatesecretproxy" `
  -SecretName "TestSecret" `
  -Thumbprint "DIFFERENT_THUMBPRINT"
```
Expected: **HTTP 401** — "Unauthorized certificate: <thumbprint>"

#### Missing Client Authentication EKU
Create a cert without Client Authentication EKU and test:
```powershell
$badCert = New-SelfSignedCertificate `
  -Type Custom `
  -KeyUsage DigitalSignature `
  -Subject "CN=BadClient" `
  -CertStoreLocation "Cert:\CurrentUser\My"
```
Expected: **HTTP 401** — "Certificate validation failed: Certificate does not have Client Authentication EKU"

## Troubleshooting

### "Certificate chain not trusted. Status: PartialChain:..."

**Cause**: The certificate's issuer is not in the `ALLOWED_ISSUER_CERTS` list or not loaded.

**Fix**:
1. Export your CA certificate (`.cer` file).
2. Upload to Function App: **TLS/SSL settings** → **Public Certificates**.
3. Copy the thumbprint.
4. Set `ALLOWED_ISSUER_CERTS=<CA_THUMBPRINT>`.
5. Ensure `WEBSITE_LOAD_CERTIFICATES=*`.
6. Restart the Function App.

### "Certificate does not have Client Authentication EKU"

**Cause**: The certificate was not issued with Client Authentication EKU, or EKU validation is required.

**Fix**:
- Regenerate the certificate with EKU `1.3.6.1.5.5.7.3.2` (Client Authentication).
- Or disable EKU requirement (not recommended): `CERT_REQUIRE_EKU=false`.

### "Certificate not yet valid" or "Certificate expired"

**Cause**: The certificate's `NotBefore` or `NotAfter` dates are outside the current time.

**Fix**:
- Ensure system clocks are synchronized.
- Regenerate the certificate with correct validity dates.
- Check certificate properties: `Get-ChildItem Cert:\CurrentUser\My\<thumb> | Select-Object NotBefore, NotAfter`.

### "Configured issuer certificates not found in Cert:\CurrentUser\My"

**Cause**: The CA cert is not loaded in the Function runtime's store.

**Fix**:
1. Check the CA cert is uploaded in **TLS/SSL settings** → **Public Certificates**.
2. Set `WEBSITE_LOAD_CERTIFICATES=*` (or specific thumbprints).
3. Wait a few minutes for the runtime to load.
4. Restart: `az functionapp restart -g <rg> -n <name>`.

### PowerShell Client: "No client certificate found..."

**Cause**: Auto-discovery failed; no cert with matching CN/SAN found.

**Fix**:
- Add `CN=<hostname>` to a certificate's subject or SAN.
- Or use `-Thumbprint "<thumb>"` explicitly.
- Or use `-CertificatePath "C:\cert.pfx"`.

### PowerShell Client: "Session using TLS 1.0 cipher suites"

**Cause**: Client is negotiating an old TLS version.

**Fix**:
```powershell
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
```

## Local Testing

For development without setting up mTLS on Azure:

1. Run `func start` (HTTP on localhost:7071).
2. Manually inject the `X-ARR-ClientCert` header (Base64-encoded cert):
   ```powershell
   $cert = Get-ChildItem Cert:\CurrentUser\My\<thumbprint>
   $certBase64 = [Convert]::ToBase64String($cert.RawData)
   
   Invoke-RestMethod `
     -Uri "http://localhost:7071/api/azfunctioncertificatesecretproxy?SecretName=TestSecret" `
     -Headers @{ "X-ARR-ClientCert" = $certBase64 }
   ```

**Warning**: Do NOT manually set `X-ARR-ClientCert` in production. Azure App Service sets it automatically after validating the real TLS client certificate.


