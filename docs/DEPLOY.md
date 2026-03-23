# Deployment Guide

This guide walks through deploying the Azure Certificate Secret Proxy from zero to a working installation.

## Option A — Deploy to Azure (recommended)

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Flucanoahcaprez%2FAzure-Certificate-Secret-Proxy%2Fmain%2Fdeployment%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Flucanoahcaprez%2FAzure-Certificate-Secret-Proxy%2Fmain%2Fdeployment%2FcreateUiDefinition.json)

Click the button to open the deployment wizard in the Azure Portal. The ARM template (`deployment/azuredeploy.json`) provisions all required Azure resources and configures every mandatory setting. After the deployment completes, run:

```powershell
func azure functionapp publish <your-function-app-name>
```

to publish the function code, then continue from [Step 4 — Configure certificate validation](#step-4--configure-certificate-validation) below.

---

## Option B — Manual ARM deployment (CLI)

```bash
az deployment group create \
  --resource-group <resource-group> \
  --template-file deployment/azuredeploy.json \
  --parameters deployment/azuredeploy.parameters.json \
               functionAppName="<your-function-app-name>"
```

Edit `deployment/azuredeploy.parameters.json` first to set your desired values. After the deployment completes, publish the function code and continue from [Step 4](#step-4--configure-certificate-validation).

---

## Option C — Fully manual setup

Follow the steps below to provision and configure everything using the Azure CLI.

## Prerequisites

- **Azure CLI** installed and logged in (`az login`)
- **Azure Functions Core Tools** installed (`func` command available)
- A **Function App** already provisioned (Windows hosting plan, PowerShell runtime, app settings storage configured)
- Your corporate **Root CA certificate** exported as a `.cer` file (DER or PEM encoded, containing only the public key — no private key)

> Replace `<resource-group>` and `<your-function-app-name>` in all commands below with your own values.

---

## Step 1 — Deploy the function code

From the repository root:

```bash
func azure functionapp publish <your-function-app-name>
```

This publishes `certificatesecretproxy/run.ps1` and `certificatesecretproxy/function.json`.

---

## Step 2 — Enable mTLS client certificate enforcement

Azure App Service must be configured to **require** a client certificate and forward it to the function. Without this, the function will never see a certificate.

```bash
# Enable client certificate negotiation
az functionapp update --set clientCertEnabled=true --name <your-function-app-name> --resource-group <resource-group>

# Require the client cert (not just request it optionally)
az functionapp config appsettings set --settings WEBSITE_CLIENT_CERT_MODE=Required --name <your-function-app-name> --resource-group <resource-group>
```

---

## Step 3 — Enforce HTTPS

```bash
az functionapp update --set https_only=true  --name <your-function-app-name> --resource-group <resource-group>
```

---

## Step 4 — Configure certificate validation

You must configure **at least one** authentication method via the `AUTH_METHODS` app setting. Multiple methods can be combined — when more than one is listed, **all must pass** (AND logic).

| Method value | Trust basis | Best for |
|---|---|---|
| `EntraDeviceCert` | Microsoft Entra ID device record (via Graph API) | Entra-joined / Hybrid-joined device fleets |
| `CertChainValidation` | Certificate chains to uploaded Root CA | Devices with certificates from a corporate PKI |
| `TrustedThumbprints` | Certificate thumbprint is in the allowlist | Small, static set of known devices |

Set `AUTH_METHODS` as a semicolon-separated list, e.g. `AUTH_METHODS=EntraDeviceCert` or `AUTH_METHODS=CertChainValidation;TrustedThumbprints`.

> **Backward compatibility:** If `AUTH_METHODS` is not set, the function derives the method from the legacy `CERT_ROOT_THUMBPRINT` / `ALLOWED_CLIENT_CERTS` settings automatically.

---

### Option A — Entra Device Certificate (recommended for Entra-managed fleets)

Trusts any device whose certificate is registered in Microsoft Entra ID. The function calls Microsoft Graph to verify the device record, thumbprint, and public key hash from `alternativeSecurityIds`. Private key ownership is proven by the mTLS handshake.

**Requirements:** The device must be Entra-joined or Hybrid Entra-joined. The Entra device certificate (`CN=<DeviceId>`) must be in `Cert:\LocalMachine\My`.

**Enable the managed identity** (skip if already done)

```bash
az functionapp identity assign --name <your-function-app-name> --resource-group <resource-group>
```

Note the `principalId` in the output.

**Grant the managed identity the `Device.Read.All` application role on Microsoft Graph**

```powershell
# Get the Microsoft Graph service principal ID in your tenant
$graphSpId = az ad sp list --filter "appId eq '00000003-0000-0000-c000-000000000000'" --query '[0].id' -o tsv

# Get the Device.Read.All app role ID from Graph
$roleId = az ad sp show --id $graphSpId --query "appRoles[?value=='Device.Read.All'].id" -o tsv

# Get the managed identity's object (service principal) ID
$miSpId = az ad sp list --filter "displayName eq '<your-function-app-name>'" --query '[0].id' -o tsv
# Or look it up directly:
$miSpId = az functionapp identity show --query principalId -o tsv --name <your-function-app-name> --resource-group <resource-group>

# Assign the app role (this is an app role assignment, not an Azure RBAC role)
$body = @{ principalId = $miSpId; resourceId = $graphSpId; appRoleId = $roleId } | ConvertTo-Json -Compress
$body > body.json
az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$miSpId/appRoleAssignments" --body "@body.json"
Remove-Item body.json
```

**Set app settings**

```bash
az functionapp config appsettings set --settings AUTH_METHODS=EntraDeviceCert  --name <your-function-app-name> --resource-group <resource-group>
```

---

### Option B — Root CA chain validation (recommended for corporate PKI device fleets)

This trusts any device certificate issued by your corporate CA. No per-device configuration is needed when a new machine is enrolled.

**Upload the Root CA certificate**

In the **Azure Portal**:
1. Navigate to your Function App.
2. Go to **Certificates** → **Public key certificates** → **Upload certificate**.
3. Upload your `.cer` file.
4. Note the **Thumbprint** shown after upload (uppercase hex, no spaces).

**Set app settings**

```bash
az functionapp config appsettings set \
  -g <resource-group> \
  -n <your-function-app-name> \
  --settings \
    AUTH_METHODS=CertChainValidation \
    CERT_ROOT_THUMBPRINT="<ROOT_CA_THUMBPRINT>" \
    WEBSITE_LOAD_CERTIFICATES="*"
```

`WEBSITE_LOAD_CERTIFICATES=*` tells the App Service runtime to load all uploaded certificates into the process certificate stores, which is required for chain validation to find the CA cert at runtime.

---

### Option C — Thumbprint allowlist (suitable for a small number of devices)

Explicitly lists which client certificate thumbprints are trusted. Requires re-configuration every time a device is added or a certificate is renewed.

**Get the client certificate thumbprint** (run on the device):

```powershell
Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object Subject, Thumbprint, NotAfter
```

**Set the allowlist:**

```bash
az functionapp config appsettings set \
  -g <resource-group> \
  -n <your-function-app-name> \
  --settings \
    AUTH_METHODS=TrustedThumbprints \
    ALLOWED_CLIENT_CERTS="THUMB1;THUMB2;THUMB3"
```

Thumbprints must be **uppercase** hex strings with **no spaces**. Separate multiple thumbprints with `;`.

---

### Option D — Combined methods

Set `AUTH_METHODS` to a semicolon-separated list. All methods must pass. For example, to require both an Entra device certificate **and** a Root CA chain:

```bash
az functionapp config appsettings set \
  -g <resource-group> \
  -n <your-function-app-name> \
  --settings \
    AUTH_METHODS="EntraDeviceCert;CertChainValidation" \
    CERT_ROOT_THUMBPRINT="<ROOT_CA_THUMBPRINT>" \
    WEBSITE_LOAD_CERTIFICATES="*"
```

---

## Step 5 — Configure the secret backend

The `WORKLOAD` setting controls **which backend is active**. Only one backend is used per request — set `WORKLOAD` to the value that matches where your secrets live. You can switch backends at any time by updating `WORKLOAD` and restarting the Function App.

| `WORKLOAD` value | Secret source | Extra settings required |
|---|---|---|
| `APPSETTINGS` (default) | Function App application settings | None |
| `KEYVAULT` | Azure Key Vault (via managed identity) | `KEYVAULT_NAME` or `KEYVAULT_URI` |
| `TABLE` | Azure Table Storage (via managed identity) | `TABLE_ENDPOINT` |

---

### APPSETTINGS (default)

Each secret is a Function App application setting prefixed with `VAR_`. The client sends `SecretName=MyKey` and the function looks up the environment variable `VAR_MyKey`. This prefix prevents accidental exposure of system or runtime settings.

```bash
az functionapp config appsettings set \
  -g <resource-group> \
  -n <your-function-app-name> \
  --settings \
    VAR_MyStorageAccountKey="<value>" \
    VAR_AnotherSecret="<value>"
```

No `WORKLOAD` setting needed; `APPSETTINGS` is the default.

---

### KEYVAULT

The function acquires a token via the Function App's **system-assigned managed identity** and calls the Key Vault REST API. No credentials are stored anywhere in the function code or app settings.

**5a. Enable the managed identity**

```bash
az functionapp identity assign \
  -g <resource-group> \
  -n <your-function-app-name>
```

Note the `principalId` in the output — you need it for the next step.

**5b. Grant the identity permission to read secrets**

Key Vault supports two permission models. Check yours under **Key Vault → Settings → Access configuration**.

> **RBAC permission model** (recommended — the default for new vaults):

```bash
# Get the Key Vault resource ID
KV_ID=$(az keyvault show --name <your-keyvault-name> --query id -o tsv)

# Assign Key Vault Secrets User role (allows reading secret values)
az role assignment create \
  --assignee "<PRINCIPAL_ID>" \
  --role "Key Vault Secrets User" \
  --scope "$KV_ID"
```

> **Access policy permission model** (legacy):

```bash
az keyvault set-policy \
  --name <your-keyvault-name> \
  --object-id <PRINCIPAL_ID> \
  --secret-permissions get
```

> **Important**: Do not confuse the **Reader** Azure role (ARM plane — grants access to vault *metadata* only) with the **Key Vault Secrets User** role (data plane — grants access to secret *values*). The function needs the data-plane role. Assigning only `Reader` results in a `403 ForbiddenByRbac` error when reading secrets.

**5c. Set app settings**

```bash
az functionapp config appsettings set \
  -g <resource-group> \
  -n <your-function-app-name> \
  --settings \
    WORKLOAD=KEYVAULT \
    KEYVAULT_NAME="<your-keyvault-name>"
```

Alternatively use `KEYVAULT_URI` instead of `KEYVAULT_NAME` if you prefer the full URI (e.g. `https://myvault.vault.azure.net`).

The client passes the Key Vault secret name as `SecretName`. Key Vault secret names may only contain alphanumerics and hyphens — underscores are not allowed.

---

### STORAGE TABLE

Secrets are stored as rows in an Azure Table Storage table with `PartitionKey=secret`, `RowKey=<SecretName>`, and a `Value` column. The function acquires a token via the Function App's **system-assigned managed identity** — no credentials are stored anywhere.

**5d. Enable the managed identity** (skip if already done for KEYVAULT)

```bash
az functionapp identity assign \
  -g <resource-group> \
  -n <your-function-app-name>
```

Note the `principalId` in the output.

**5e. Grant the identity permission to read table data**

The required role is **Storage Table Data Reader** (data plane — grants read access to table entities).

```bash
# Get the Storage Account resource ID
SA_ID=$(az storage account show --name <your-storage-account-name> --query id -o tsv)

# Assign Storage Table Data Reader role
az role assignment create \
  --assignee "<PRINCIPAL_ID>" \
  --role "Storage Table Data Reader" \
  --scope "$SA_ID"
```

**5f. Set app settings**

```bash
az functionapp config appsettings set \
  -g <resource-group> \
  -n <your-function-app-name> \
  --settings \
    WORKLOAD=TABLE \
    TABLE_ENDPOINT="https://<account>.table.core.windows.net/Secrets"
```

---

## Step 6 — Restart the Function App

Always restart after changing app settings to ensure the new values are loaded:

```bash
az functionapp restart \
  -g <resource-group> \
  -n <your-function-app-name>
```

---

## Step 7 — Verify the deployment

Run the client script from a device that has a valid machine certificate:

```powershell
.\client\requestSecret.ps1 `
  -FunctionUrl "https://<your-function-app-name>.azurewebsites.net/api/certificatesecretproxy" `
  -SecretName "MyStorageAccountKey" `
  -VerboseLogging
```

Expected output:
```
Auto-selected certificate: CN=MYDEVICE [22E4D9050A50F3ACAA6583C641BD4BE869F788CD]
Certificate: CN=MYDEVICE
Thumbprint: 22E4D9050A50F3ACAA6583C641BD4BE869F788CD
Endpoint: https://...
Success
SecretName : MyStorageAccountKey
SecretValue: <the-secret>
CertThumb  : 22E4D9050A50F3ACAA6583C641BD4BE869F788CD
Workload   : APPSETTINGS
```

---

## App settings reference

| Setting | Required? | Default | Description |
|---|---|---|---|
| `AUTH_METHODS` | Yes (or set legacy vars) | derived | Semicolon-separated list of auth methods. All must pass. Values: `EntraDeviceCert`, `CertChainValidation`, `TrustedThumbprints`. |
| `CERT_ROOT_THUMBPRINT` | Required when `CertChainValidation` is active | — | Thumbprint of the Root CA uploaded to the Function App. |
| `ALLOWED_CLIENT_CERTS` | Required when `TrustedThumbprints` is active | — | Semicolon-separated client cert thumbprints (uppercase). |
| `WEBSITE_LOAD_CERTIFICATES` | Required when `CertChainValidation` is active | — | Set to `*` to load all uploaded certs into the Function process cert stores. |
| `WORKLOAD` | No | `APPSETTINGS` | Secret backend: `APPSETTINGS`, `KEYVAULT`, or `TABLE`. |
| `KEYVAULT_NAME` | Required for `KEYVAULT` | — | Key Vault name. Alternatively set `KEYVAULT_URI` for the full URI. |
| `TABLE_ENDPOINT` | Required for `TABLE` | — | Table Storage URL including table name (e.g. `https://{account}.table.core.windows.net/{tableName}`). |

---

## Troubleshooting

### HTTP 401 — "Client certificate header not found"

The function did not receive the `X-ARR-ClientCert` header.

- Verify `clientCertEnabled=true` is set on the Function App.
- Verify `WEBSITE_CLIENT_CERT_MODE=Required` is set.
- Verify the client script is calling with `-Certificate $cert` (or `-Thumbprint` / auto-discovery mode).
- If accessing through a reverse proxy (Front Door, API Management, App Gateway), confirm the proxy is configured to pass client certificates through and forward the `X-ARR-ClientCert` header.

### HTTP 401 — "Certificate chain validation failed: Root certificate … not found"

The function could not find the Root CA in any of its process-side cert stores.

1. Confirm the Root CA cert is uploaded: Azure Portal → Function App → **Certificates** → **Public key certificates**.
2. Confirm `WEBSITE_LOAD_CERTIFICATES=*` is set as an app setting.
3. After changing either, **restart** the Function App.

### HTTP 401 — "Certificate thumbprint not in allowlist"

The presented certificate's thumbprint is not in `ALLOWED_CLIENT_CERTS`.

- Get the thumbprint: `$cert.Thumbprint` (on the client) or check the `Diagnostics.CertThumbprint` field in the 401 response body.
- Update `ALLOWED_CLIENT_CERTS` to include it (uppercase, no spaces, semicolon-separated).

### HTTP 401 — "Certificate expired or not yet valid"

The machine certificate's `NotBefore`/`NotAfter` window does not include the current time.

- Renew the certificate via your CA or re-enroll the device.

### HTTP 500 — "No authentication method configured"

Neither `AUTH_METHODS` nor the legacy `CERT_ROOT_THUMBPRINT`/`ALLOWED_CLIENT_CERTS` settings are set.

- Set `AUTH_METHODS` to one of: `EntraDeviceCert`, `CertChainValidation`, `TrustedThumbprints`. See Step 4.

### HTTP 401 — "EntraDeviceCert validation failed: No Entra device record found"

The certificate's Subject CN is a valid GUID but no matching device was found in Entra.

- Verify the device is Entra-joined or Hybrid-joined: run `dsregcmd /status` on the device and check `AzureAdJoined: YES`.
- Verify the managed identity has the `Device.Read.All` **application role** on Microsoft Graph (not an Azure RBAC role).
- Check the `Diagnostics.CertThumbprint` in the response — does it match the Entra device certificate in `Cert:\LocalMachine\My` on the device?

### HTTP 401 — "EntraDeviceCert validation failed: Certificate CN '...' is not a GUID"

The client is presenting a non-Entra certificate (e.g. a corporate PKI cert with `CN=<hostname>`). Entra device certificates must have `CN=<DeviceId>` where DeviceId is the Entra device ID GUID.

- If you want to use corporate PKI certificates, use `CertChainValidation` instead of (or in addition to) `EntraDeviceCert`.
- On the device, the Entra device cert is typically in `Cert:\LocalMachine\My` with `CN=<GUID>`. The `requestSecret.ps1` client script may be auto-selecting a different certificate.

### HTTP 401 — "EntraDeviceCert validation failed: Certificate thumbprint ... does not match"

The certificate presented over mTLS has a different thumbprint than what Entra has on record for that device.

- The device certificate may have been renewed/rotated. Force an Entra re-registration: `dsregcmd /forcerecovery` or re-join the device.
- Alternatively, the device may be presenting the wrong certificate. Inspect `Cert:\LocalMachine\My` for all certs with `CN=<DeviceId>`.

### `SecretValue` is empty / HTTP 404

The `SecretName` requested does not exist in the configured backend.

- For `APPSETTINGS`: verify there is an app setting named `VAR_<SecretName>` (case-sensitive on Linux; case-insensitive on Windows).
- For `KEYVAULT`: verify the secret exists in the vault and the managed identity has `get` permission.
- For `TABLE`: verify a row exists with `PartitionKey=secret` and `RowKey=<SecretName>`.
