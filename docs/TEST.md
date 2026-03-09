# Testing Guide

## Test Matrix

| Method | Test | Expected |
|--------|------|---------|
| Thumbprint | Cert in whitelist | 200 OK, secret returned |
| Thumbprint | Cert not in whitelist | 401 Unauthorized |
| Root CA | Cert chains to Root CA | 200 OK, secret returned |
| Root CA | Cert does not chain | 401 Unauthorized |
| Both | Cert matches either | 200 OK |
| None | No validation configured | 500 Error |

---

## Thumbprint Whitelist Test

1. Set `ALLOWED_CLIENT_CERTS` to your cert thumbprint
2. Run:
   ```powershell
   .\client\requestSecret.ps1 -FunctionUrl <url> -SecretName "Secret12345" -Thumbprint <your-thumbprint>
   ```
3. Expected: Success if thumbprint matches

## Root CA Chain Validation Test

1. Set `CERT_ROOT_THUMBPRINT` to your Root CA thumbprint
2. Run:
   ```powershell
   .\client\requestSecret.ps1 -FunctionUrl <url> -SecretName "Secret12345" -Thumbprint <your-thumbprint>
   ```
3. Expected: Success if certificate chains to Root CA

## Hybrid Mode Test

1. Set both `ALLOWED_CLIENT_CERTS` and `CERT_ROOT_THUMBPRINT`
2. Run with:
   - Cert in whitelist: Success
   - Cert chains to Root CA: Success
   - Cert not in either: Unauthorized

---

## Troubleshooting
- Restart function app after changing settings
- Use verbose logging in client script for diagnostics
- Check Azure Portal → Certificates for correct Root CA
- Ensure thumbprints are uppercase, no spaces
