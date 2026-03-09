# Architecture

## Overview

The Azure Certificate Secret Proxy is an Azure Function App that acts as a secure secret-delivery endpoint for managed Windows devices. It uses mutual TLS (mTLS) to authenticate callers: every request must carry a valid client certificate, and the function validates that certificate before returning any secret.

```
 Windows Device                  Azure                        Secret Backend
 ─────────────                  ───────                        ──────────────
 requestSecret.ps1              App Service                    App Settings
   │                               │                           Key Vault
   │  HTTPS + client cert TLS ──►  │  X-ARR-ClientCert         Table Storage
   │                               │  header forwarded
   │                               ▼
   │                           run.ps1 (Azure Function)
   │                             1. Extract cert from header
   │                             2. Check validity window
   │                             3. Chain validation (optional)
   │                             4. Thumbprint allowlist (optional)
   │                             5. Retrieve secret
   │  ◄── JSON response ──────────│
```

## Components

### `certificatesecretproxy/run.ps1` — the Azure Function

PowerShell HTTP-triggered Azure Function. All authentication and secret retrieval logic lives here.

**Trigger**: HTTP GET or POST, `authLevel` is `anonymous` (App Service enforces client certs at the platform level before the function is invoked).

**Key data flow inside the function:**

1. Read configuration from environment variables (`ALLOWED_CLIENT_CERTS`, `CERT_ROOT_THUMBPRINT`, `WORKLOAD`, …).
2. Extract the client certificate from the `X-ARR-ClientCert` header (Base64-encoded DER, set by App Service after TLS termination).
3. Parse it into an `X509Certificate2` object.
4. Check the certificate's `NotBefore` / `NotAfter` validity window.
5. Run one or both validation steps (see "Certificate validation" below).
6. On success, retrieve the secret from the configured backend and return it.

A `$diagnostics` ordered hashtable is built throughout execution and included in every response body. This makes failures self-explanatory without requiring log access.

### `client/requestSecret.ps1` — client script

PowerShell script that runs on the endpoint. Responsible for:

1. **Locating the client certificate** — three modes, evaluated in priority order:
   - **PFX file** (`-CertificatePath`): loads the cert directly from a `.pfx` file. Suitable for automation or service accounts.
   - **By thumbprint** (`-Thumbprint`): looks up `Cert:\LocalMachine\My\<thumb>` then `Cert:\CurrentUser\My\<thumb>`.
   - **Auto-discovery** (no `-Thumbprint`, no `-CertificatePath`): enumerates `LocalMachine\My` and `CurrentUser\My`, filters by CN/SAN matching the machine hostname (`COMPUTERNAME` env var and DNS FQDN), requires `HasPrivateKey = true` and Client Authentication EKU (`1.3.6.1.5.5.7.3.2`). Picks the most recently expiring matching certificate.

2. **Building the request URL** — appends `SecretName` as a query parameter to `FunctionUrl`.

3. **Calling the function** — `Invoke-RestMethod -Uri $uri -Method Get -Certificate $cert`. PowerShell/WinHTTP sends the certificate in the TLS ClientCertificate extension of the handshake.

4. **Printing the result** — reads `$response.SecretName`, `$response.SecretValue`, `$response.CertThumb`, `$response.Workload` from the JSON response body.

## Certificate validation pipeline

At least one of the two methods below must be configured. Both can be active simultaneously, in which case the certificate must pass **both** checks.

### Step 1 — Extract and parse

App Service decodes the client certificate from the TLS handshake and writes it as a Base64 string into the `X-ARR-ClientCert` HTTP header. The function reads this header case-insensitively, base64-decodes it, and constructs an `X509Certificate2`.

If the header is absent, the function returns **HTTP 401**. This can happen if:
- `clientCertEnabled` is not set on the Function App, or
- the client did not present a certificate.

### Step 2 — Validity window

```powershell
if ($clientCert.NotBefore -gt (Get-Date) -or $clientCert.NotAfter -lt (Get-Date))
```

Returns **HTTP 401** if the certificate is outside its validity window.

### Step 3 — Root CA chain validation (`CERT_ROOT_THUMBPRINT`)

When `CERT_ROOT_THUMBPRINT` is set, the function:

1. Searches for the root CA certificate across four stores in order:
   - `Cert:\CurrentUser\My`
   - `Cert:\CurrentUser\Root`
   - `Cert:\LocalMachine\My`
   - `Cert:\LocalMachine\Root`

   The cert must have been uploaded to the Function App (Portal → Certificates → Public key certificates) and `WEBSITE_LOAD_CERTIFICATES=*` must be set so the runtime loads it into the process stores.

2. Builds an `X509Chain` with:
   - `RevocationMode = NoCheck` (CRL checks are skipped for performance; enable `Online`/`Offline` if your PKI publishes CRLs reachable from Azure)
   - `TrustMode = CustomRootTrust` — the uploaded CA cert is the sole trusted anchor; the system's Windows trust store is not consulted

3. Calls `$chain.Build($clientCert)`. Returns **HTTP 401** if the chain cannot be built to the configured root.

This is the recommended mode for device fleets: any device certificate issued by the corporate CA is accepted without per-device configuration.

### Step 4 — Thumbprint allowlist (`ALLOWED_CLIENT_CERTS`)

When `ALLOWED_CLIENT_CERTS` is set, the function checks whether the certificate's thumbprint (uppercase) is in the semicolon-separated list.

Returns **HTTP 401** if the thumbprint is not found.

This step is **additive**: if both `CERT_ROOT_THUMBPRINT` and `ALLOWED_CLIENT_CERTS` are set, the certificate must pass the chain check first, and then the thumbprint check.

### Validation modes summary

| `CERT_ROOT_THUMBPRINT` | `ALLOWED_CLIENT_CERTS` | Behaviour |
|---|---|---|
| Set | Not set | Accept any cert that chains to the Root CA |
| Not set | Set | Accept only certs whose thumbprint is in the list |
| Set | Set | Cert must chain to Root CA **and** be in the list |
| Not set | Not set | HTTP 500 — misconfiguration |

## Secret retrieval workloads

The `WORKLOAD` app setting selects **one active backend** per deployment. The function reads from exactly one source per request. To switch backends, update `WORKLOAD` and restart the Function App.

### `APPSETTINGS` (default)

```powershell
$secretValue = [Environment]::GetEnvironmentVariable($secretName)
```

The secret is stored as a Function App application setting whose name equals `SecretName`. Simple and requires no additional Azure services. Manage secrets by updating app settings.

### `KEYVAULT`

Uses the Function App's **system-assigned managed identity** to call the Key Vault data-plane REST API:

```
GET https://<vault>.vault.azure.net/secrets/<SecretName>?api-version=7.4
```

The token is acquired via the App Service managed identity endpoint — **not** the VM Instance Metadata Service (IMDS). Azure Functions exposes two environment variables for this:

- `IDENTITY_ENDPOINT` — the local MSI token service URL (injected automatically when managed identity is enabled)
- `IDENTITY_HEADER` — a secret value passed as `X-IDENTITY-HEADER` to prevent SSRF

If either variable is absent the function returns HTTP 500 with a clear error. This means managed identity is not enabled on the Function App.

The managed identity must hold the **Key Vault Secrets User** role (RBAC model) or a `get` access policy (access policy model) on the vault. The `Reader` Azure role grants ARM-plane access only and is **not** sufficient to read secret values — assigning only `Reader` results in `403 ForbiddenByRbac`.

Required settings: `KEYVAULT_NAME` (or `KEYVAULT_URI`). Secret names in Key Vault may only contain alphanumerics and hyphens.

### `TABLE`

Fetches a row from Azure Table Storage using a SAS token:

```
GET <TABLE_ENDPOINT>(PartitionKey='secret',RowKey='<SecretName>')<TABLE_SAS_TOKEN>
```

The table row is expected to have a `Value` column containing the secret.

Required settings: `TABLE_ENDPOINT`, `TABLE_SAS_TOKEN`.

## Response format

All responses are JSON and include a `Message` and a `Diagnostics` object. Success responses (HTTP 200) additionally include the secret fields at the top level:

```jsonc
// HTTP 200 — success
{
  "Message": "Success",
  "SecretName": "MyStorageAccountKey",
  "SecretValue": "<the-secret>",
  "CertThumb": "22E4D9050A50F3AC0A6588C641BD4BE869F788CD",
  "Workload": "APPSETTINGS",
  "Diagnostics": {
    "Timestamp": "2026-03-09T10:00:00.000Z",
    "Phase": "success",
    "ValidationMethod": "Chain validation",
    "CertThumbprint": "22E4D9050A50F3AC0A6588C641BD4BE869F788CD",
    "ChainValidationStatus": "Validated",
    ...
  }
}

// HTTP 401 — chain validation failed
{
  "Message": "Certificate chain validation failed: PartialChain: ...",
  "Diagnostics": {
    "Phase": "validation",
    "ValidationMethod": "Chain validation",
    "ChainValidationStatus": "PartialChain: ...",
    ...
  }
}
```

## HTTP status codes

| Code | Meaning |
|---|---|
| 200 | Certificate valid, secret found and returned |
| 400 | `SecretName` query parameter missing |
| 401 | Certificate missing, expired, chain invalid, or not in allowlist |
| 404 | Certificate valid but no secret found for the given name in the configured backend |
| 500 | No validation method configured, or backend retrieval threw an unexpected exception |

## Security model

- **Platform-level enforcement**: App Service requires a client certificate at the TLS layer (`clientCertEnabled=true`, `WEBSITE_CLIENT_CERT_MODE=Required`) before the function code runs. Requests without a certificate are rejected by the platform, never reaching the function.
- **Function-level validation**: the function performs additional checks (validity window, chain, allowlist) so that even if the platform setting were misconfigured, the function would not return a secret.
- **Custom trust anchor**: chain validation uses `X509ChainTrustMode::CustomRootTrust`. The system Windows certificate store is not used as a trust source. Only the explicitly uploaded Root CA is trusted.
- **No secret in logs**: the `$diagnostics` block never includes the secret value. Only `SecretName` appears in diagnostics.
- **HTTPS only**: `https_only=true` prevents plaintext connections.
