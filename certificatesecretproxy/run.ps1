using namespace System.Security.Cryptography.X509Certificates

param($Request, $TriggerMetadata)

# ========== CONFIGURATION ==========
# AUTH_METHODS: semicolon-separated list of auth methods; ALL listed must pass (AND logic).
# Supported values: EntraDeviceCert, CertChainValidation, TrustedThumbprints
# If not set, derived automatically from the legacy CERT_ROOT_THUMBPRINT / ALLOWED_CLIENT_CERTS env vars.
$allowedThumbprints = ($env:ALLOWED_CLIENT_CERTS -split ';' | Where-Object { $_ }) | ForEach-Object { $_.Trim().ToUpper() }
$rootCertThumbprint = if ($env:CERT_ROOT_THUMBPRINT) { $env:CERT_ROOT_THUMBPRINT.Trim().ToUpper() } else { $null }

if ([string]::IsNullOrWhiteSpace($env:AUTH_METHODS)) {
    # Backward compatibility: derive from legacy env vars
    $authMethods = @()
    if ($rootCertThumbprint)             { $authMethods += 'CertChainValidation' }
    if ($allowedThumbprints.Count -gt 0) { $authMethods += 'TrustedThumbprints'  }
} else {
    $authMethods = ($env:AUTH_METHODS -split ';' | Where-Object { $_ }) | ForEach-Object { $_.Trim() }
}

# Diagnostics
$diagnostics = [ordered]@{
    Timestamp              = (Get-Date).ToString('o')
    Method                 = $Request.Method
    Url                    = $Request.Url
    SecretName             = $null
    Workload               = $null
    Phase                  = 'init'
    ValidationMethod       = $null
    CertThumbprint         = $null
    ChainValidationStatus  = $null
    Message                = $null
}

# Capture all request headers for troubleshooting (including cert-related ones)
$diagnostics.Headers = @{}
foreach ($hk in $Request.Headers.Keys) {
    $diagnostics.Headers[$hk] = $Request.Headers[$hk]
}

function Send-Response([int]$code, [string]$message, [hashtable]$extra = @{}) {
    if ($extra.ContainsKey('Phase')) {
        $diagnostics.Phase = $extra['Phase']
        $extra.Remove('Phase') | Out-Null
    }
    if ($extra.Count -gt 0) {
        foreach ($k in $extra.Keys) { $diagnostics[$k] = $extra[$k] }
    }
    $diagnostics.LastMessage = $message

    $body = [ordered]@{ Message = $message; Diagnostics = $diagnostics }
    foreach ($k in $extra.Keys) { $body[$k] = $extra[$k] }

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $code
        Body       = [pscustomobject]$body
    })
}


# ========== RESPONSE HELPER ==========


# ========== EXTRACT CLIENT CERTIFICATE ==========
function Get-ClientCertificate {
    $raw = $null
    
    # Find X-ARR-ClientCert header (case-insensitive)
    foreach ($key in $Request.Headers.Keys) {
        if ($key -ieq 'x-arr-clientcert') {
            $raw = $Request.Headers[$key]
            break
        }
    }
    
    if (-not $raw) {
        $diagnostics.Message = "Client certificate header not found"
        return $null
    }

    try {
        $bytes = [Convert]::FromBase64String($raw)
        $cert = [X509Certificate2]::new($bytes)
        return $cert
    }
    catch {
        $diagnostics.Message = "Failed to parse certificate: $($_.Exception.Message)"
        return $null
    }
}

# ========== VALIDATE CHAIN ==========
function Find-TrustedRootCertificate([string]$thumbprint) {
    $stores = @(
        "Cert:\CurrentUser\My",
        "Cert:\CurrentUser\Root",
        "Cert:\LocalMachine\My",
        "Cert:\LocalMachine\Root"
    )

    foreach ($store in $stores) {
        try {
            $cert = Get-ChildItem -Path "$store\$thumbprint" -ErrorAction Stop
            if ($cert) { return $cert }
        }
        catch {
            # Ignore missing store access/errors and continue searching.
        }
    }

    return $null
}

function Test-CertificateChain([X509Certificate2]$clientCert, [string]$rootThumbprint) {
    try {
        $rootCertificate = Find-TrustedRootCertificate -thumbprint $rootThumbprint
        if (-not $rootCertificate) {
            return @{ Valid = $false; Error = "Root certificate $rootThumbprint not found in CurrentUser/LocalMachine My/Root stores" }
        }
        
        $chain = [X509Chain]::new()
        $chain.ChainPolicy.RevocationMode = [X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [X509VerificationFlags]::NoFlag
        
        [void]$chain.ChainPolicy.CustomTrustStore.Add($rootCertificate)
        $chain.ChainPolicy.TrustMode = [X509ChainTrustMode]::CustomRootTrust
        
        $isValid = $chain.Build($clientCert)
        
        if (-not $isValid) {
            $details = ($chain.ChainStatus | ForEach-Object { "$($_.Status): $($_.StatusInformation)" }) -join "; "
            return @{ Valid = $false; Error = $details }
        }
        
        return @{ Valid = $true }
    }
    catch {
        return @{ Valid = $false; Error = $_.Exception.Message }
    }
}

# ========== VALIDATE ENTRA DEVICE CERTIFICATE ==========
# Validates that the client certificate is a genuine Entra (Azure AD) device certificate by:
#   1. Confirming the Subject CN is a valid Entra device ID GUID
#   2. Looking up the device record in Microsoft Graph
#   3. Comparing the cert thumbprint and public key hash against alternativeSecurityIds
#   4. Confirming the device is enabled
# Private key ownership is proven by the mTLS handshake, so no separate signature step is needed.
function Test-EntraDeviceCertificate([X509Certificate2]$cert) {
    # 1. Extract CN — Entra device certs have CN=<DeviceId GUID>
    $cn = if ($cert.Subject -match '(?i)^CN=([^,]+)') { $Matches[1].Trim() } else { $null }
    if (-not $cn) {
        return @{ Valid = $false; Error = "Cannot extract CN from certificate subject '$($cert.Subject)'." }
    }
    # 2. CN must parse as a GUID (the Entra device ID)
    try   { $deviceId = [guid]::Parse($cn).ToString() }
    catch { return @{ Valid = $false; Error = "Certificate CN '$cn' is not a GUID. Entra device certificates must have CN=<DeviceId>. This certificate does not appear to be an Entra device certificate." } }

    # 3. Acquire Microsoft Graph token via managed identity
    if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
        return @{ Valid = $false; Error = "Managed identity is not available (IDENTITY_ENDPOINT/IDENTITY_HEADER missing). Enable a system-assigned managed identity on the Function App." }
    }
    try {
        $tokenUri   = "$($env:IDENTITY_ENDPOINT)?resource=https://graph.microsoft.com&api-version=2019-08-01"
        $graphToken = (Invoke-RestMethod -Method Get -Uri $tokenUri `
            -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER } `
            -ErrorAction Stop).access_token
    }
    catch {
        return @{ Valid = $false; Error = "Failed to acquire Microsoft Graph token via managed identity: $($_.Exception.Message). Ensure the Function App managed identity has the 'Device.Read.All' application role on Microsoft Graph." }
    }

    # 4. Look up the device record in Entra via Microsoft Graph
    try {
        $encodedId = [Uri]::EscapeDataString($deviceId)
        $graphUri  = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$encodedId'&`$select=id,deviceId,displayName,accountEnabled,alternativeSecurityIds"
        $devices   = (Invoke-RestMethod -Method Get -Uri $graphUri `
            -Headers @{ Authorization = "Bearer $graphToken" } `
            -ErrorAction Stop).value
    }
    catch {
        return @{ Valid = $false; Error = "Graph API call failed: $($_.Exception.Message). Ensure the Function App managed identity has the 'Device.Read.All' application role on Microsoft Graph." }
    }

    if (-not $devices -or $devices.Count -eq 0) {
        return @{ Valid = $false; Error = "No Entra device record found with deviceId '$deviceId'. The device may not be Entra-joined, or Device.Read.All is missing on the managed identity." }
    }
    $device = $devices[0]

    # 5. Verify the device is enabled in Entra
    if (-not $device.accountEnabled) {
        return @{ Valid = $false; Error = "Entra device '$($device.displayName)' ($deviceId) is disabled (accountEnabled=false)." }
    }
    if (-not $device.alternativeSecurityIds -or $device.alternativeSecurityIds.Count -eq 0) {
        return @{ Valid = $false; Error = "Entra device '$($device.displayName)' ($deviceId) has no alternativeSecurityIds — cannot verify the certificate." }
    }

    # 6. Decode alternativeSecurityIds.key
    # The key is a Base64-encoded Unicode string: <21-char prefix incl. '>'><40-char thumbprint><base64 public key hash>
    try {
        $decoded          = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($device.alternativeSecurityIds[0].key))
        $afterFirstAngle  = $decoded.Split(">")[1]
        $storedThumbprint = $afterFirstAngle.Substring(0, 40).ToUpper()
        $storedPubKeyHash = $afterFirstAngle.Substring(40)
    }
    catch {
        return @{ Valid = $false; Error = "Failed to decode alternativeSecurityIds.key: $($_.Exception.Message)" }
    }

    # 7. Validate the certificate thumbprint against the Entra record
    if ($cert.Thumbprint.ToUpper() -ne $storedThumbprint) {
        return @{ Valid = $false; Error = "Certificate thumbprint '$($cert.Thumbprint.ToUpper())' does not match the thumbprint in the Entra device record ('$storedThumbprint'). The device certificate may have been rotated without re-syncing to Entra." }
    }

    # 8. Validate the certificate public key hash against the Entra record
    # Hash = Base64(SHA256(cert.GetPublicKey())) where GetPublicKey() returns SubjectPublicKeyInfo DER bytes
    try {
        $sha256          = [System.Security.Cryptography.SHA256]::Create()
        $computedPubHash = [System.Convert]::ToBase64String($sha256.ComputeHash($cert.GetPublicKey()))
    }
    catch {
        return @{ Valid = $false; Error = "Failed to compute certificate public key hash: $($_.Exception.Message)" }
    }
    if ($computedPubHash -ne $storedPubKeyHash) {
        return @{ Valid = $false; Error = "Certificate public key hash does not match the Entra device record. The certificate may have been replaced without re-registering the device." }
    }

    return @{ Valid = $true; DeviceId = $deviceId; DeviceName = $device.displayName }
}

# ========== MAIN LOGIC ==========

# Parse request
$secretName = $Request.Query.SecretName
if (-not $secretName) {
    Send-Response 400 "SecretName parameter required" @{ Phase = 'request-validation' }
    return
}

$workload = $env:WORKLOAD
if (-not $workload) { $workload = 'APPSETTINGS' }

$diagnostics.SecretName = $secretName
$diagnostics.Workload = $workload

# Extract client certificate
$clientCert = Get-ClientCertificate
if (-not $clientCert) {
    $diagnostics.Phase = 'cert-extraction'
    Send-Response 401 $diagnostics.Message @{ Phase = 'cert-extraction' }
    return
}

$thumbprint = $clientCert.Thumbprint.ToUpper()
$diagnostics.CertThumbprint = $thumbprint
$diagnostics.Phase = 'cert-extraction-success'

# Check certificate validity
if ($clientCert.NotBefore -gt (Get-Date) -or $clientCert.NotAfter -lt (Get-Date)) {
    $diagnostics.Phase = 'validation'
    $diagnostics.Message = "Certificate expired or not yet valid"
    Send-Response 401 $diagnostics.Message @{ Phase = 'validation' }
    return
}

if ($authMethods.Count -eq 0) {
    $diagnostics.Phase = 'unauthorized'
    $diagnostics.Message = "No authentication method configured. Set AUTH_METHODS to one or more of: EntraDeviceCert, CertChainValidation, TrustedThumbprints (or set the legacy CERT_ROOT_THUMBPRINT / ALLOWED_CLIENT_CERTS settings)."
    Send-Response 500 $diagnostics.Message @{ Phase = 'unauthorized' }
    return
}

# Run each required authentication method — ALL listed methods must pass (AND logic).
foreach ($authMethod in $authMethods) {
    switch ($authMethod) {
        'EntraDeviceCert' {
            $entraResult = Test-EntraDeviceCertificate -cert $clientCert
            if (-not $entraResult.Valid) {
                $diagnostics.Phase = 'validation'
                $diagnostics.Message = "EntraDeviceCert validation failed: $($entraResult.Error)"
                Send-Response 401 $diagnostics.Message @{ Phase = 'validation' }
                return
            }
            $diagnostics.EntraDeviceId   = $entraResult.DeviceId
            $diagnostics.EntraDeviceName = $entraResult.DeviceName
        }
        'CertChainValidation' {
            if ([string]::IsNullOrWhiteSpace($rootCertThumbprint)) {
                $diagnostics.Phase = 'unauthorized'
                $diagnostics.Message = "AUTH_METHODS includes 'CertChainValidation' but CERT_ROOT_THUMBPRINT is not set."
                Send-Response 500 $diagnostics.Message @{ Phase = 'unauthorized' }
                return
            }
            $chainTest = Test-CertificateChain -clientCert $clientCert -rootThumbprint $rootCertThumbprint
            if (-not $chainTest.Valid) {
                $diagnostics.Phase = 'validation'
                $diagnostics.ChainValidationStatus = $chainTest.Error
                $diagnostics.Message = "Certificate chain validation failed: $($chainTest.Error)"
                Send-Response 401 $diagnostics.Message @{ Phase = 'validation' }
                return
            }
            $diagnostics.ChainValidationStatus = "Validated"
        }
        'TrustedThumbprints' {
            if ($allowedThumbprints.Count -eq 0) {
                $diagnostics.Phase = 'unauthorized'
                $diagnostics.Message = "AUTH_METHODS includes 'TrustedThumbprints' but ALLOWED_CLIENT_CERTS is not set."
                Send-Response 500 $diagnostics.Message @{ Phase = 'unauthorized' }
                return
            }
            if ($thumbprint -notin $allowedThumbprints) {
                $diagnostics.Phase = 'validation'
                $diagnostics.Message = "Certificate thumbprint '$thumbprint' is not in the ALLOWED_CLIENT_CERTS allowlist."
                Send-Response 401 $diagnostics.Message @{ Phase = 'validation' }
                return
            }
        }
        default {
            $diagnostics.Phase = 'unauthorized'
            $diagnostics.Message = "Unknown authentication method '$authMethod' in AUTH_METHODS. Supported values: EntraDeviceCert, CertChainValidation, TrustedThumbprints."
            Send-Response 500 $diagnostics.Message @{ Phase = 'unauthorized' }
            return
        }
    }
}

$diagnostics.ValidationMethod = $authMethods -join '+'
$diagnostics.Phase = 'authorized'

# ========== RETRIEVE SECRET ==========
try {
    $secretValue = $null

    switch ($workload) {
        'APPSETTINGS' {
            $envVarName = "VAR_$secretName"
            $secretValue = [Environment]::GetEnvironmentVariable($envVarName)
        }
        'KEYVAULT' {
            # Resolve vault URI from KEYVAULT_URI or KEYVAULT_NAME.
            $vaultUri = $env:KEYVAULT_URI
            if (-not $vaultUri) {
                $vaultName = $env:KEYVAULT_NAME
                if (-not $vaultName) { throw "KEYVAULT workload requires KEYVAULT_NAME or KEYVAULT_URI to be set." }
                $vaultUri = "https://$vaultName.vault.azure.net"
            }

            # Acquire a token via the App Service managed identity endpoint.
            # IDENTITY_ENDPOINT and IDENTITY_HEADER are injected automatically when a
            # system-assigned (or user-assigned) managed identity is enabled on the Function App.
            if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
                throw "Managed identity is not available (IDENTITY_ENDPOINT/IDENTITY_HEADER missing). Enable a system-assigned managed identity on the Function App."
            }
            $tokenUri = "$($env:IDENTITY_ENDPOINT)?resource=https://vault.azure.net&api-version=2019-08-01"
            $token = (Invoke-RestMethod -Method Get -Uri $tokenUri `
                -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER } `
                -ErrorAction Stop).access_token

            # Retrieve the secret by name. Key Vault secret names support alphanumerics and hyphens only;
            # map underscores to hyphens if your naming convention requires it.
            $secret = Invoke-RestMethod -Method Get `
                -Uri "$vaultUri/secrets/$secretName`?api-version=7.4" `
                -Headers @{ Authorization = "Bearer $token" } `
                -ErrorAction Stop
            $secretValue = $secret.value
        }
        'TABLE' {
            $tableEndpoint = $env:TABLE_ENDPOINT
            if (-not $tableEndpoint) { throw "TABLE_ENDPOINT required (e.g. https://{account}.table.core.windows.net/{tableName})" }

            # Acquire a token via the App Service managed identity endpoint.
            if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
                throw "Managed identity is not available (IDENTITY_ENDPOINT/IDENTITY_HEADER missing). Enable a system-assigned managed identity on the Function App."
            }
            $tokenUri = "$($env:IDENTITY_ENDPOINT)?resource=https://storage.azure.com/&api-version=2019-08-01"
            $token = (Invoke-RestMethod -Method Get -Uri $tokenUri `
                -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER } `
                -ErrorAction Stop).access_token

            $encodedRowKey = [Uri]::EscapeDataString($secretName)
            $uri = "$tableEndpoint(PartitionKey='secret',RowKey='$encodedRowKey')"
            $resp = Invoke-RestMethod -Method Get -Uri $uri `
                -Headers @{
                    Authorization  = "Bearer $token"
                    Accept         = 'application/json;odata=nometadata'
                    'x-ms-version' = '2019-02-02'
                } `
                -ErrorAction Stop

            # Collect all non-system properties from the row
            $rowData = [ordered]@{}
            foreach ($prop in $resp.PSObject.Properties) {
                if ($prop.Name -notin @('PartitionKey', 'RowKey', 'Timestamp', 'odata.etag')) {
                    $rowData[$prop.Name] = $prop.Value
                }
            }
            $secretValue = if ($rowData.Count -gt 0) { [pscustomobject]$rowData } else { $null }
        }
        default {
            throw "Unknown workload: $workload"
        }
    }
    
    if (-not $secretValue) {
        $notFoundHint = switch ($workload) {
            'APPSETTINGS' { "No Function App application setting named 'VAR_$secretName' was found. Only settings prefixed with 'VAR_' are exposed. Add it under Configuration > Application settings in the Azure Portal, or via: az functionapp config appsettings set --settings VAR_$secretName=<value>. Names are case-sensitive on Linux and case-insensitive on Windows." }
            'KEYVAULT'    {
                $vaultDisplay = if ($env:KEYVAULT_URI) { $env:KEYVAULT_URI } elseif ($env:KEYVAULT_NAME) { "https://$($env:KEYVAULT_NAME).vault.azure.net" } else { '(unknown vault)' }
                "No secret named '$secretName' was found in Key Vault '$vaultDisplay'. Verify: (1) the secret exists and is enabled, (2) the Function App managed identity has the 'Key Vault Secrets User' role on the vault, (3) secret names may only contain alphanumerics and hyphens."
            }
            'TABLE'       { "No row with PartitionKey='secret' and RowKey='$secretName' was found in table endpoint '$($env:TABLE_ENDPOINT)'. Verify: (1) the row exists with exactly PartitionKey='secret' and RowKey='$secretName', (2) the Function App managed identity has the 'Storage Table Data Reader' role on the storage account. See docs: https://github.com/lucanoahcaprez/Azure-Certificate-Secret-Proxy/blob/main/docs/DEPLOY.md#storage-table" }
            default       { "Secret '$secretName' not found in workload '$workload'." }
        }
        $diagnostics.Phase = 'secret-retrieval'
        $diagnostics.Message = "Secret not found: $secretName"
        $diagnostics.Hint = $notFoundHint
        Send-Response 404 $diagnostics.Message @{ Phase = 'secret-retrieval'; Hint = $notFoundHint }
        return
    }

    $diagnostics.Phase = 'success'
    Send-Response 200 "Success" @{
        SecretName  = $secretName
        SecretValue = $secretValue
        CertThumb   = $thumbprint
        Workload    = $workload
    }
}
catch {
    $diagnostics.Phase = 'secret-retrieval'
    $diagnostics.Message = $_.Exception.Message

    # If the upstream service (Key Vault, Table Storage) returned 404, surface that as a 404.
    $upstreamStatus = $null
    if ($_.Exception -is [Microsoft.PowerShell.Commands.HttpResponseException]) {
        $upstreamStatus = [int]$_.Exception.Response.StatusCode
    }

    if ($upstreamStatus -eq 404) {
        $notFoundHint = switch ($workload) {
            'KEYVAULT' {
                $vaultDisplay = if ($env:KEYVAULT_URI) { $env:KEYVAULT_URI } elseif ($env:KEYVAULT_NAME) { "https://$($env:KEYVAULT_NAME).vault.azure.net" } else { '(unknown vault)' }
                "No secret named '$secretName' was found in Key Vault '$vaultDisplay'. Verify: (1) the secret exists and is enabled, (2) the Function App managed identity has the 'Key Vault Secrets User' role on the vault, (3) secret names may only contain alphanumerics and hyphens."
            }
            'TABLE'    { "No row with PartitionKey='secret' and RowKey='$secretName' was found in table endpoint '$($env:TABLE_ENDPOINT)'. Verify: (1) the row exists with exactly PartitionKey='secret' and RowKey='$secretName', (2) the Function App managed identity has the 'Storage Table Data Reader' role on the storage account. See docs: https://github.com/lucanoahcaprez/Azure-Certificate-Secret-Proxy/blob/main/docs/DEPLOY.md#storage-table" }
            default    { "Secret '$secretName' not found." }
        }
        $diagnostics.Message = "Secret not found: $secretName"
        $diagnostics.Hint = $notFoundHint
        Send-Response 404 $diagnostics.Message @{ Phase = 'secret-retrieval'; Hint = $notFoundHint }
    } else {
        Send-Response 500 $diagnostics.Message @{ Phase = 'secret-retrieval' }
    }
}

