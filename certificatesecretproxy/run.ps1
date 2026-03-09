using namespace System.Security.Cryptography.X509Certificates

param($Request, $TriggerMetadata)

# Expected client certificate thumbprints (semicolon-separated) from app setting ALLOWED_CLIENT_CERTS
$allowed = ($env:ALLOWED_CLIENT_CERTS -split ';' | Where-Object { $_ }) | ForEach-Object { $_.Trim().ToUpper() }

# Expected issuer/root certificates (thumbprints) uploaded to the Function App and loaded via WEBSITE_LOAD_CERTIFICATES (optional)
$issuerThumbs = ($env:ALLOWED_ISSUER_CERTS -split ';' | Where-Object { $_ }) | ForEach-Object { $_.Trim().ToUpper() }
$issuerValidationRequired = $issuerThumbs.Count -gt 0

# Collect lightweight execution diagnostics so callers can see how the request was interpreted
$diagnostics = [ordered]@{
    Timestamp          = (Get-Date).ToString('o')
    Method             = $Request.Method
    Url                = $Request.Url
    QueryKeys          = @($Request.Query.Keys)
    SecretName         = $null
    Workload           = $null
    CertHeaderPresent  = $false
    CertHeaderName     = $null
    CertHeaderLength   = $null
    CertThumb          = $null
    AllowedConfigured  = $allowed.Count
    WhitelistEnabled   = $false
    IssuersConfigured  = $issuerThumbs.Count
    ChainStatus        = $null
    Phase              = 'init'
    LastMessage        = $null
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

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $code
        Body       = [pscustomobject]@{
            Message      = $message
            Diagnostics  = $diagnostics
        }
    })
}

# -------- Parameter parsing (pre-auth) --------

$secretName = $Request.Query.SecretName
if (-not $secretName) {
    $body = $Request.Body | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($body) { $secretName = $body.SecretName }
}

$workload = ($env:WORKLOAD)
if (-not $workload) { $workload = 'AppSettings' }
$workload = $workload.ToUpper()

$diagnostics.SecretName = $secretName
$diagnostics.Workload   = $workload
$diagnostics.Phase      = 'parsed-params'
$diagnostics.WhitelistEnabled = ($allowed.Count -gt 0)

if (-not $issuerValidationRequired -and $allowed.Count -eq 0) {
    Send-Response 500 'When ALLOWED_ISSUER_CERTS is empty, ALLOWED_CLIENT_CERTS must list the authorized client thumbprints.' @{ Phase = 'auth' }
    return
}

if (-not $secretName) {
    Send-Response 400 'SecretName missing (query or JSON body)' @{ Phase = 'parsed-params' }
    return
}

# -------- Client certificate extraction --------

function Get-ClientCertificate {
    param(
        [System.Net.Http.HttpRequestMessage]$req
    )

    $raw = $req.Headers['X-ARR-ClientCert']
    if (-not $raw -and $req.Content -and $req.Content.Headers) {
        $raw = $req.Content.Headers['X-ARR-ClientCert']
    }
    $diagnostics.CertHeaderName    = 'X-ARR-ClientCert'
    $diagnostics.CertHeaderPresent = [bool]$raw
    if (-not $raw) { return $null }

    $raw = [string]$raw
    $diagnostics.CertHeaderLength = $raw.Length

    try {
        $bytes = [Convert]::FromBase64String($raw)
        return [X509Certificate2]::new($bytes)
    }
    catch {
        $diagnostics.CertParseError = $_.Exception.Message
        return $null
    }
}

$clientCert = Get-ClientCertificate -req $Request
if (-not $clientCert) {
    Send-Response 401 'Client certificate missing or unreadable (check forwarding header and format)' @{ Phase = 'auth' }
    return
}

$thumbprint = $clientCert.Thumbprint.ToUpper()
$diagnostics.CertThumb = $thumbprint

if ($allowed.Count -gt 0 -and ($thumbprint -notin $allowed)) {
    Send-Response 401 "Unauthorized certificate: $thumbprint" @{ Phase = 'auth' }
    return
}

if ($issuerValidationRequired) {
    $issuerCerts = @()
    foreach ($t in $issuerThumbs) {
        $c = Get-ChildItem -Path Cert:\CurrentUser\My\$t -ErrorAction SilentlyContinue
        if ($c) { $issuerCerts += $c }
    }

    if ($issuerCerts.Count -eq 0) {
        Send-Response 500 'Configured issuer certificates not found in Cert:\CurrentUser\My (ensure WEBSITE_LOAD_CERTIFICATES includes them)' @{ Phase = 'auth' }
        return
    }

    $chain = [X509Chain]::new()
    $chain.ChainPolicy.RevocationMode  = [X509RevocationMode]::NoCheck
    $chain.ChainPolicy.RevocationFlag  = [X509RevocationFlag]::EndCertificateOnly
    $chain.ChainPolicy.VerificationFlags = [X509VerificationFlags]::NoFlag

    foreach ($ic in $issuerCerts) { [void]$chain.ChainPolicy.CustomTrustStore.Add($ic) }

    # Use custom root trust so only uploaded issuers are trusted
    try {
        $chain.ChainPolicy.TrustMode = [X509ChainTrustMode]::CustomRootTrust
    }
    catch {
        Send-Response 500 'Platform does not support CustomRootTrust; cannot enforce issuer validation' @{ Phase = 'auth' }
        return
    }

    $isTrusted = $chain.Build($clientCert)
    if (-not $isTrusted) {
        $status = ($chain.ChainStatus | ForEach-Object { $_.Status.ToString() + ':' + $_.StatusInformation.Trim() }) -join '; '
        $diagnostics.ChainStatus = $status
        Send-Response 401 "Certificate chain not trusted. Status: $status" @{ Phase = 'auth' }
        return
    }

    # Ensure the chain actually anchors to one of the configured issuers
    $anchors = $chain.ChainElements | Select-Object -Last 1
    if ($anchors.Certificate.Thumbprint.ToUpper() -notin $issuerThumbs) {
        Send-Response 401 'Certificate chain does not anchor to a configured issuer' @{ Phase = 'auth' }
        return
    }
    $diagnostics.ChainStatus = 'trusted (custom issuer)'
}
else {
    # Issuer validation skipped; trust is based solely on the allowlist of client thumbprints
    $diagnostics.ChainStatus = 'skipped (no ALLOWED_ISSUER_CERTS configured)'
}
$diagnostics.Phase = 'authorized'

# -------- Workload helpers --------

function Get-SecretFromAppSettings([string]$name) {
    [Environment]::GetEnvironmentVariable($name)
}

function Get-MsiToken([string]$resource) {
    $uri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=$([uri]::EscapeDataString($resource))"
    (Invoke-RestMethod -Method Get -Uri $uri -Headers @{ Metadata = 'true' } -ErrorAction Stop).access_token
}

function Get-SecretFromKeyVault([string]$name) {
    $vaultName = $env:KEYVAULT_NAME
    $vaultUri  = $env:KEYVAULT_URI
    if (-not $vaultUri) {
        if (-not $vaultName) { throw "KEYVAULT_NAME or KEYVAULT_URI must be set." }
        $vaultUri = "https://$vaultName.vault.azure.net"
    }
    $token = Get-MsiToken -resource 'https://vault.azure.net'
    $secretUri = "$vaultUri/secrets/$name?api-version=7.3"
    (Invoke-RestMethod -Method Get -Uri $secretUri -Headers @{ Authorization = "Bearer $token" } -ErrorAction Stop).value
}

function Get-SecretFromTable([string]$name) {
    $tableEndpoint = $env:TABLE_ENDPOINT  # e.g. https://account.table.core.windows.net/Secrets
    $sasToken      = $env:TABLE_SAS_TOKEN # starting with ?sv=...
    $valueField    = $env:TABLE_VALUE_FIELD
    if (-not $valueField) { $valueField = 'Value' }
    if (-not $tableEndpoint -or -not $sasToken) { throw "TABLE_ENDPOINT and TABLE_SAS_TOKEN must be set for table workload." }

    $rowUrl = "{0}(PartitionKey='secret',RowKey='{1}'){2}" -f $tableEndpoint, $name, $sasToken
    $resp = Invoke-RestMethod -Method Get -Uri $rowUrl -Headers @{ Accept = 'application/json;odata=nometadata' } -ErrorAction Stop
    $resp.$valueField
}

# -------- Secret retrieval --------

try {
    switch ($workload) {
        'APPSETTINGS' {
            $secretValue = Get-SecretFromAppSettings -name $secretName
        }
        'KEYVAULT' {
            $secretValue = Get-SecretFromKeyVault -name $secretName
        }
        'TABLE' {
            $secretValue = Get-SecretFromTable -name $secretName
        }
        default {
            throw "Unsupported WORKLOAD '$workload'."
        }
    }
}
catch {
    Send-Response 500 $_.Exception.Message @{ Phase = 'workload' }
    return
}

if (-not $secretValue) {
    Send-Response 404 "Secret '$secretName' not found for workload '$workload'" @{ Phase = 'workload' }
    return
}

$diagnostics.Phase       = 'completed'
$diagnostics.LastMessage = 'Success'

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = 200
    Body       = [pscustomobject]@{
        SecretName   = $secretName
        SecretValue  = $secretValue
        CertThumb    = $thumbprint
        Workload     = $workload
        Diagnostics  = $diagnostics
    }
})
