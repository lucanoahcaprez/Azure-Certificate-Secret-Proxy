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

> The resource group and Function App name used in `deployment/configs.azcli` are:
> - Resource group: `rg-lnc-lab-CertificateSecretProxy-test-01`
> - Function App: `func-lnc-lab-certificatesecretproxy-test-01`
>
> Replace these with your own values in all commands below.

---

## Step 1 — Deploy the function code

From the repository root:

```bash
func azure functionapp publish func-lnc-lab-certificatesecretproxy-test-01
```

This publishes `certificatesecretproxy/run.ps1` and `certificatesecretproxy/function.json`.

---

## Step 2 — Enable mTLS client certificate enforcement

Azure App Service must be configured to **require** a client certificate and forward it to the function. Without this, the function will never see a certificate.

```bash
# Enable client certificate negotiation
az functionapp update \
  --set clientCertEnabled=true \
  --name func-lnc-lab-certificatesecretproxy-test-01 \
  --resource-group rg-lnc-lab-CertificateSecretProxy-test-01

# Require the client cert (not just request it optionally)
az functionapp config appsettings set \
  -g rg-lnc-lab-CertificateSecretProxy-test-01 \
  -n func-lnc-lab-certificatesecretproxy-test-01 \
  --settings WEBSITE_CLIENT_CERT_MODE=Required
```

---

## Step 3 — Enforce HTTPS

```bash
az functionapp update \
  --set https_only=true \
  --name func-lnc-lab-certificatesecretproxy-test-01 \
  --resource-group rg-lnc-lab-CertificateSecretProxy-test-01
```

---

## Step 4 — Configure certificate validation

You must configure **at least one** of the two validation methods. They can both be active simultaneously (the certificate must then satisfy both checks).

### Option A — Root CA chain validation (recommended for device fleets)

This trusts any device certificate issued by your corporate CA. No per-device configuration is needed when a new machine is enrolled.

**4a. Upload the Root CA certificate**

In the **Azure Portal**:
1. Navigate to your Function App.
2. Go to **Certificates** → **Public key certificates** → **Upload certificate**.
3. Upload your `.cer` file.
4. Note the **Thumbprint** shown after upload (uppercase hex, no spaces).

**4b. Set app settings**

```bash
az functionapp config appsettings set \
  -g rg-lnc-lab-CertificateSecretProxy-test-01 \
  -n func-lnc-lab-certificatesecretproxy-test-01 \
  --settings \
    CERT_ROOT_THUMBPRINT="<ROOT_CA_THUMBPRINT>" \
    WEBSITE_LOAD_CERTIFICATES="*"
```

`WEBSITE_LOAD_CERTIFICATES=*` tells the App Service runtime to load all uploaded certificates into the process certificate stores (`Cert:\CurrentUser\My`, etc.), which is required for the chain validation to find the CA cert at runtime.

---

### Option B — Thumbprint allowlist (suitable for a small number of devices)

Explicitly lists which client certificate thumbprints are trusted. Requires re-configuration every time a device is added or a certificate is renewed.

**Get the client certificate thumbprint** (run on the device):

```powershell
Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object Subject, Thumbprint, NotAfter
```

**Set the allowlist:**

```bash
az functionapp config appsettings set \
  -g rg-lnc-lab-CertificateSecretProxy-test-01 \
  -n func-lnc-lab-certificatesecretproxy-test-01 \
  --settings ALLOWED_CLIENT_CERTS="THUMB1;THUMB2;THUMB3"
```

Thumbprints must be **uppercase** hex strings with **no spaces**. Separate multiple thumbprints with `;`.

---

### Option C — Both methods (chain + allowlist)

Set both `CERT_ROOT_THUMBPRINT` and `ALLOWED_CLIENT_CERTS`. The certificate must pass the chain check **and** have its thumbprint in the list. This is the strictest mode.

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

Each secret is a Function App application setting. The setting name is exactly what the client passes as `SecretName`.

```bash
az functionapp config appsettings set \
  -g rg-lnc-lab-CertificateSecretProxy-test-01 \
  -n func-lnc-lab-certificatesecretproxy-test-01 \
  --settings \
    MyStorageAccountKey="<value>" \
    AnotherSecret="<value>"
```

No `WORKLOAD` setting needed; `APPSETTINGS` is the default.

---

### KEYVAULT

The function acquires a token via the Function App's **system-assigned managed identity** and calls the Key Vault REST API. No credentials are stored anywhere in the function code or app settings.

**5a. Enable the managed identity**

```bash
az functionapp identity assign \
  -g rg-lnc-lab-CertificateSecretProxy-test-01 \
  -n func-lnc-lab-certificatesecretproxy-test-01
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
  -g rg-lnc-lab-CertificateSecretProxy-test-01 \
  -n func-lnc-lab-certificatesecretproxy-test-01 \
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
  -g rg-lnc-lab-CertificateSecretProxy-test-01 \
  -n func-lnc-lab-certificatesecretproxy-test-01
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
  -g rg-lnc-lab-CertificateSecretProxy-test-01 \
  -n func-lnc-lab-certificatesecretproxy-test-01 \
  --settings \
    WORKLOAD=TABLE \
    TABLE_ENDPOINT="https://<account>.table.core.windows.net/Secrets"
```

---

## Step 6 — Restart the Function App

Always restart after changing app settings to ensure the new values are loaded:

```bash
az functionapp restart \
  -g rg-lnc-lab-CertificateSecretProxy-test-01 \
  -n func-lnc-lab-certificatesecretproxy-test-01
```

---

## Step 7 — Verify the deployment

Run the client script from a device that has a valid machine certificate:

```powershell
.\client\requestSecret.ps1 `
  -FunctionUrl "https://func-lnc-lab-certificatesecretproxy-test-01.azurewebsites.net/api/certificatesecretproxy" `
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
| `CERT_ROOT_THUMBPRINT` | At least one of the two must be set | — | Thumbprint of the Root CA uploaded to the Function App. Enables chain-based trust. |
| `ALLOWED_CLIENT_CERTS` | At least one of the two must be set | — | Semicolon-separated client cert thumbprints (uppercase). |
| `WEBSITE_LOAD_CERTIFICATES` | Required when `CERT_ROOT_THUMBPRINT` is set | — | Set to `*` to load all uploaded certs into the Function process cert stores. |
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

### HTTP 401 — "Certificate thumbprint not in whitelist"

The presented certificate's thumbprint is not in `ALLOWED_CLIENT_CERTS`.

- Get the thumbprint: `$cert.Thumbprint` (on the client) or check the `Diagnostics.CertThumbprint` field in the 401 response body.
- Update `ALLOWED_CLIENT_CERTS` to include it (uppercase, no spaces, semicolon-separated).

### HTTP 401 — "Certificate expired or not yet valid"

The machine certificate's `NotBefore`/`NotAfter` window does not include the current time.

- Renew the certificate via your CA or re-enroll the device.

### HTTP 500 — "No validation method configured"

Neither `CERT_ROOT_THUMBPRINT` nor `ALLOWED_CLIENT_CERTS` is set.

- Configure at least one. See Step 4.

### `SecretValue` is empty / HTTP 404

The `SecretName` requested does not exist in the configured backend.

- For `APPSETTINGS`: verify there is an app setting with exactly that name (case-sensitive on Linux; case-insensitive on Windows).
- For `KEYVAULT`: verify the secret exists in the vault and the managed identity has `get` permission.
- For `TABLE`: verify a row exists with `PartitionKey=secret` and `RowKey=<SecretName>`.
