# Azure Certificate Secret Proxy

A lightweight Azure Function that delivers secrets to Windows endpoints over HTTPS with mutual TLS (mTLS). Client machines authenticate using their machine certificate; the Function validates the certificate before returning the requested secret.

## What problem does this solve?

Managed Windows endpoints often need to retrieve secrets at runtime (e.g. a storage account key, a connection string) without storing those secrets locally. This proxy lets a device prove its identity using its machine certificate — issued by your corporate CA — and receive the secret it needs in return. No secrets are stored on disk on the device.

## How it works (high level)

1. The client runs `requestSecret.ps1`, which locates the machine certificate in the Windows certificate store and calls the Azure Function over HTTPS with the cert attached.
2. Azure App Service is configured to **require** a client certificate. It terminates TLS and forwards the certificate in the `X-ARR-ClientCert` request header.
3. The Azure Function (`run.ps1`) decodes and validates the certificate:
   - **Chain validation** (if `CERT_ROOT_THUMBPRINT` is set): the cert must chain up to the uploaded Root CA.
   - **Thumbprint allowlist** (if `ALLOWED_CLIENT_CERTS` is set): the cert thumbprint must be in the list.
   - Both can be active simultaneously; the cert must then pass **both** checks.
   - At least one must be configured; otherwise the function returns HTTP 500.
4. If validation passes, the function retrieves the requested secret from the configured backend (App Settings, Key Vault, or Azure Table Storage) and returns it.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a detailed technical walkthrough.

## Repository structure

```
certificatesecretproxy/
  function.json          # Azure Function trigger (HTTP GET+POST, anonymous authLevel)
  run.ps1                # Function logic — cert validation + secret retrieval
client/
  requestSecret.ps1      # PowerShell client script for Windows endpoints
deployment/
  configs.azcli          # az CLI commands to configure the Function App
docs/
  ARCHITECTURE.md        # Technical deep-dive: full request flow, validation logic, response format
  DEPLOY.md              # Step-by-step deployment and configuration guide
  TEST.md                # Test matrix and test commands
  architecture-diagram.drawio
```

## Quick start

### Prerequisites
- Azure Function App (PowerShell worker runtime, Windows hosting plan)
- Machine certificates enrolled in `Cert:\LocalMachine\My` on each endpoint, issued by your corporate CA

### 1 — Deploy the function code

```powershell
func azure functionapp publish <your-function-app-name>
```

### 2 — Enable mTLS and HTTPS on the Function App

```bash
az functionapp update --set clientCertEnabled=true \
  -g <resource-group> -n <function-app-name>

az functionapp config appsettings set \
  -g <resource-group> -n <function-app-name> \
  --settings WEBSITE_CLIENT_CERT_MODE=Required

az functionapp update --set https_only=true \
  -g <resource-group> -n <function-app-name>
```

### 3 — Configure certificate validation

**Option A – Root CA chain validation (recommended for device fleets)**

Upload your Root CA certificate (`.cer`, no private key) in the Azure Portal:
**Function App → Certificates → Public key certificates → Upload certificate**

Then set:
```bash
az functionapp config appsettings set \
  -g <resource-group> -n <function-app-name> \
  --settings CERT_ROOT_THUMBPRINT="<ROOT_CA_THUMBPRINT>" \
             WEBSITE_LOAD_CERTIFICATES="*"
```

With this option, any device certificate signed by your CA is trusted automatically — no per-device configuration needed.

**Option B – Thumbprint allowlist (simpler, suitable for a small number of devices)**

```bash
az functionapp config appsettings set \
  -g <resource-group> -n <function-app-name> \
  --settings ALLOWED_CLIENT_CERTS="THUMB1;THUMB2;THUMB3"
```

Thumbprints must be uppercase hex strings with no spaces.

**Option C – Both (chain validation + explicit allowlist)**

Set both `CERT_ROOT_THUMBPRINT` and `ALLOWED_CLIENT_CERTS`. The certificate must pass the chain check **and** have its thumbprint in the list. This is the most restrictive mode.

### 4 — Add secrets

Secrets are stored as Function App application settings (default `APPSETTINGS` workload):

```bash
az functionapp config appsettings set \
  -g <resource-group> -n <function-app-name> \
  --settings MyStorageAccountKey="<value>" OtherSecret="<value>"
```

The setting name is the `SecretName` the client will request.

### 5 — Call from a Windows endpoint

```powershell
# Auto-discover machine certificate by hostname (COMPUTERNAME / FQDN)
.\client\requestSecret.ps1 `
  -FunctionUrl "https://<func>.azurewebsites.net/api/certificatesecretproxy" `
  -SecretName "MyStorageAccountKey"

# Specify a thumbprint explicitly
.\client\requestSecret.ps1 `
  -FunctionUrl "https://<func>.azurewebsites.net/api/certificatesecretproxy" `
  -SecretName "MyStorageAccountKey" `
  -Thumbprint "22E4D9050A50F3AC0A6588C641BD4BE869F788CD"
```

Expected output:
```
Auto-selected certificate: CN=MYDEVICE [22E4D9050A50F3AC0A6588C641BD4BE869F788CD]
Success
SecretName : MyStorageAccountKey
SecretValue: <the-secret>
CertThumb  : 22E4D9050A50F3AC0A6588C641BD4BE869F788CD
Workload   : APPSETTINGS
```

## Client script parameters

| Parameter | Required | Description |
|---|---|---|
| `-FunctionUrl` | Yes | Full URL of the Azure Function endpoint |
| `-SecretName` | Yes | Name of the secret to retrieve |
| `-Thumbprint` | No | Explicit certificate thumbprint; skips auto-discovery |
| `-CertificatePath` | No | Path to a `.pfx` file; bypasses the Windows cert store entirely |
| `-CertificatePassword` | No | Password for the PFX file (plain text; use only for non-interactive automation) |
| `-VerboseLogging` | No | Prints certificate subject, thumbprint, and full endpoint URL before the request |

## App settings reference

| Setting | Required? | Description |
|---|---|---|
| `CERT_ROOT_THUMBPRINT` | At least one of the two must be set | Thumbprint of the Root CA uploaded to the Function App. Enables chain validation. |
| `ALLOWED_CLIENT_CERTS` | At least one of the two must be set | Semicolon-separated list of allowed client cert thumbprints (uppercase). |
| `WEBSITE_LOAD_CERTIFICATES` | Required when `CERT_ROOT_THUMBPRINT` is used | Set to `*` so the runtime loads uploaded CA certs into the Function process cert stores. |
| `WORKLOAD` | No (default: `APPSETTINGS`) | Secret backend: `APPSETTINGS`, `KEYVAULT`, or `TABLE`. |
| `KEYVAULT_NAME` or `KEYVAULT_URI` | Required for `KEYVAULT` workload | Key Vault name or full URI. The Function App must have a managed identity with Secret `get` permission. |
| `TABLE_ENDPOINT` | Required for `TABLE` workload | Azure Table Storage URL including table name, e.g. `https://acct.table.core.windows.net/Secrets`. |
| `TABLE_SAS_TOKEN` | Required for `TABLE` workload | SAS token string (starts with `?sv=`). Table rows must have `PartitionKey=secret`, `RowKey=<SecretName>`, `Value=<secret>`. |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `SecretValue` is empty in response | Secret name does not match an app setting (or Key Vault secret / Table row) | Verify the exact setting name matches what the client passes as `SecretName` |
| HTTP 401 – "Client certificate header not found" | App Service is not forwarding the cert, or client did not send one | Confirm `clientCertEnabled=true` and `WEBSITE_CLIENT_CERT_MODE=Required`; ensure the client uses `-Certificate` |
| HTTP 401 – "Certificate chain validation failed: Root certificate … not found" | Root CA cert not loaded in Function process stores | Upload CA cert; set `WEBSITE_LOAD_CERTIFICATES=*`; restart Function App |
| HTTP 401 – "Certificate thumbprint not in whitelist" | Cert not in `ALLOWED_CLIENT_CERTS` | Add thumbprint (uppercase, no spaces) to the setting |
| HTTP 401 – "Certificate expired or not yet valid" | Machine cert outside validity window | Renew or re-enroll the machine certificate |
| HTTP 500 – "No validation method configured" | Neither `CERT_ROOT_THUMBPRINT` nor `ALLOWED_CLIENT_CERTS` is set | Configure at least one validation method |

For a full deployment walkthrough see [docs/DEPLOY.md](docs/DEPLOY.md).
For the technical request flow see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
