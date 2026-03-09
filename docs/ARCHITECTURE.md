# Certificate Secret Proxy Architecture

## Overview

This Azure Function enables secure secret retrieval using mTLS client certificate authentication. Two validation modes are supported:

- **Thumbprint Whitelist**: Only certificates with thumbprints listed in `ALLOWED_CLIENT_CERTS` are accepted.
- **Root CA Chain Validation**: Any certificate that chains to the Root CA imported in Azure (thumbprint set via `CERT_ROOT_THUMBPRINT`) is accepted.

## Flow Diagram

1. Client sends HTTPS request with client certificate
2. Azure App Service terminates TLS, forwards certificate in `X-ARR-ClientCert` header
3. Function extracts certificate, checks validity
4. Function validates:
   - Thumbprint whitelist (if configured)
   - Chain validation to Root CA (if configured)
5. If validation passes, secret is returned

## Security Notes
- Only one or both validation methods need to be configured
- Chain validation uses the Root CA imported in Azure Portal
- No certificate is accepted if neither method is configured

---

## Diagram

See `docs/architecture-diagram.drawio` for a visual overview.
