using namespace System.Security.Cryptography.X509Certificates

param($Request, $TriggerMetadata)

# ========== CONFIGURATION ==========
# Method 1: Whitelist specific client certificate thumbprints (semicolon-separated)
$allowedThumbprints = ($env:ALLOWED_CLIENT_CERTS -split ';' | Where-Object { $_ }) | ForEach-Object { $_.Trim().ToUpper() }

# Method 2: Validate client certificate chain against Root CA imported in Azure (by thumbprint)
$rootCertThumbprint = if ($env:CERT_ROOT_THUMBPRINT) { $env:CERT_ROOT_THUMBPRINT.Trim().ToUpper() } else { $null }

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

 $hasThumbprintAllowlist = $allowedThumbprints.Count -gt 0
 $hasRootChainValidation = -not [string]::IsNullOrWhiteSpace($rootCertThumbprint)

if (-not ($hasThumbprintAllowlist -or $hasRootChainValidation)) {
    # No validation method configured
    $diagnostics.Phase = 'unauthorized'
    $diagnostics.Message = "No validation method configured (set ALLOWED_CLIENT_CERTS or CERT_ROOT_THUMBPRINT)"
    Send-Response 500 $diagnostics.Message @{ Phase = 'unauthorized' }
    return
}

# Always validate certificate chain when a trusted root is configured.
if ($hasRootChainValidation) {
    $chainTest = Test-CertificateChain -clientCert $clientCert -rootThumbprint $rootCertThumbprint
    if (-not $chainTest.Valid) {
        $diagnostics.Phase = 'validation'
        $diagnostics.ValidationMethod = if ($hasThumbprintAllowlist) { "Chain + thumbprint" } else { "Chain validation" }
        $diagnostics.ChainValidationStatus = $chainTest.Error
        $diagnostics.Message = "Certificate chain validation failed: $($chainTest.Error)"
        Send-Response 401 $diagnostics.Message @{ Phase = 'validation' }
        return
    }
    $diagnostics.ChainValidationStatus = "Validated"
}

# If allowlist is configured, it is an additional requirement.
if ($hasThumbprintAllowlist) {
    if ($thumbprint -notin $allowedThumbprints) {
        $diagnostics.Phase = 'validation'
        $diagnostics.ValidationMethod = if ($hasRootChainValidation) { "Chain + thumbprint" } else { "Thumbprint whitelist" }
        $diagnostics.Message = "Certificate thumbprint not in whitelist"
        Send-Response 401 $diagnostics.Message @{ Phase = 'validation' }
        return
    }
}

$diagnostics.ValidationMethod = if ($hasRootChainValidation -and $hasThumbprintAllowlist) { "Chain + thumbprint" } elseif ($hasRootChainValidation) { "Chain validation" } else { "Thumbprint whitelist" }
$diagnostics.Phase = 'authorized'

# ========== RETRIEVE SECRET ==========
try {
    $secretValue = $null
    
    switch ($workload) {
        'APPSETTINGS' {
            $secretValue = [Environment]::GetEnvironmentVariable($secretName)
        }
        'KEYVAULT' {
            $vaultName = $env:KEYVAULT_NAME
            $vaultUri = $env:KEYVAULT_URI
            if (-not $vaultUri) {
                if (-not $vaultName) { throw "KEYVAULT_NAME or KEYVAULT_URI required" }
                $vaultUri = "https://$vaultName.vault.azure.net"
            }
            $token = (Invoke-RestMethod -Method Get -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://vault.azure.net" -Headers @{ Metadata = 'true' } -ErrorAction Stop).access_token
            $secret = Invoke-RestMethod -Method Get -Uri "$vaultUri/secrets/$secretName?api-version=7.3" -Headers @{ Authorization = "Bearer $token" } -ErrorAction Stop
            $secretValue = $secret.value
        }
        'TABLE' {
            $tableEndpoint = $env:TABLE_ENDPOINT
            $sasToken = $env:TABLE_SAS_TOKEN
            if (-not $tableEndpoint -or -not $sasToken) { throw "TABLE_ENDPOINT and TABLE_SAS_TOKEN required" }
            $uri = "$tableEndpoint(PartitionKey='secret',RowKey='$secretName')$sasToken"
            $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ Accept = 'application/json;odata=nometadata' } -ErrorAction Stop
            $secretValue = $resp.Value
        }
        default {
            throw "Unknown workload: $workload"
        }
    }
    
    if (-not $secretValue) {
        $diagnostics.Phase = 'secret-retrieval'
        $diagnostics.Message = "Secret not found: $secretName"
        Send-Response 404 $diagnostics.Message @{ Phase = 'secret-retrieval' }
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
    Send-Response 500 $diagnostics.Message @{ Phase = 'secret-retrieval' }
}

