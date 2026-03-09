# Deployment Guide

## Prerequisites
- Azure Function App deployed
- Root CA certificate imported in Azure Portal (Function App → Certificates)

## Configuration

### Method 1: Thumbprint Whitelist
1. Get client certificate thumbprint:
   ```powershell
   $cert = Get-ChildItem -Path "Cert:\LocalMachine\My\*" | Where-Object { $_.Subject -match "your-cert-name" }
   Write-Host $cert.Thumbprint
   ```
2. Set environment variable:
   ```bash
   az functionapp config appsettings set \
     -g <resource-group> \
     -n <function-app-name> \
     --settings ALLOWED_CLIENT_CERTS="THUMB1;THUMB2"
   ```

### Method 2: Root CA Chain Validation
1. Import Root CA certificate in Azure Portal
2. Copy thumbprint from Certificates tab
3. Set environment variable:
   ```bash
   az functionapp config appsettings set \
     -g <resource-group> \
     -n <function-app-name> \
     --settings CERT_ROOT_THUMBPRINT="<ROOT_CA_THUMBPRINT>"
   ```

### Restart Function App
```bash
az functionapp restart -g <resource-group> -n <function-app-name>
```

## Workload Configuration
- `WORKLOAD=APPSETTINGS` (default)
- `WORKLOAD=KEYVAULT` or `WORKLOAD=TABLE` for advanced secret sources

---

## Hybrid Mode
- Both methods can be enabled; certificate is accepted if it matches either.
