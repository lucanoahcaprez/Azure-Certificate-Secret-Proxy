# Usage

## Call the function directly (two lines)

```powershell
$cert = Get-Item Cert:\LocalMachine\My\<THUMBPRINT>
Invoke-RestMethod -Uri "https://<func>.azurewebsites.net/api/certificatesecretproxy?SecretName=<name>" -Method Get -Certificate $cert -ErrorAction Stop
```

Replace `<THUMBPRINT>` with the machine certificate thumbprint (uppercase, no spaces), `<func>` with the Function App name, and `<name>` with the secret to retrieve.

The response object contains:

| Field | Description |
|---|---|
| `SecretName` | The name that was requested |
| `SecretValue` | The secret value |
| `CertThumb` | Thumbprint of the certificate that was accepted |
| `Workload` | Backend that served the secret (`APPSETTINGS`, `KEYVAULT`, or `TABLE`) |

## Use the wrapper script

The `client/requestSecret.ps1` script wraps those two lines with auto-discovery and error handling:

```powershell
# Auto-select the machine certificate (matches hostname CN/SAN)
.\client\requestSecret.ps1 -FunctionUrl "https://<func>.azurewebsites.net/api/certificatesecretproxy" -SecretName "<name>"

# Specify the thumbprint explicitly
.\client\requestSecret.ps1 -FunctionUrl "https://..." -SecretName "<name>" -Thumbprint "<THUMBPRINT>"

# Load from a PFX file instead of the cert store
.\client\requestSecret.ps1 -FunctionUrl "https://..." -SecretName "<name>" -CertificatePath "C:\path\to\cert.pfx"
```

Add `-VerboseLogging` to any call to print the certificate subject, thumbprint, and full endpoint URL before the request is sent.
