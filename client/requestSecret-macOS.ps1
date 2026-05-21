param(
    [Parameter(Mandatory)]
    [string]$FunctionUrl,

    [Parameter(Mandatory)]
    [string]$SecretName,

    [string]$Thumbprint,

    [string]$CertificatePath,

    [string]$CertificatePassword,

    [switch]$VerboseLogging
)

# --- Certificate loading ---

function Get-CertFromPfx {
    if (-not (Test-Path $CertificatePath)) {
        Write-Error "Certificate file not found: $CertificatePath"; exit 1
    }
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
    if ($CertificatePassword) {
        $pwd = ConvertTo-SecureString $CertificatePassword -AsPlainText -Force
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            (Resolve-Path $CertificatePath).Path, $pwd, $flags)
    }
    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        (Resolve-Path $CertificatePath).Path, $null, $flags)
}

function Get-CertFromKeychain {
    $storeLocations = @(
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )

    $allCerts = foreach ($loc in $storeLocations) {
        try {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                [System.Security.Cryptography.X509Certificates.StoreName]::My, $loc)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $store.Certificates
            $store.Close()
        } catch { }
    }

    if ($Thumbprint) {
        $cert = $allCerts | Where-Object { $_.Thumbprint -eq $Thumbprint } | Select-Object -First 1
        if (-not $cert) {
            Write-Error "Certificate with thumbprint $Thumbprint not found in Keychain"; exit 1
        }
        return $cert
    }

    # Auto-discover by hostname
    $hostnames = @(
        [System.Environment]::MachineName
        try { [System.Net.Dns]::GetHostEntry('').HostName } catch { }
        try { (scutil --get LocalHostName) } catch { }
    ) | Where-Object { $_ } | Select-Object -Unique

    $certs = $allCerts | Where-Object {
        $_.HasPrivateKey -and (
            $_.Subject -match ($hostnames -join '|') -or
            ($_.DnsNameList.Unicode | Where-Object { $_ -in $hostnames })
        )
    }

    $cert = $certs | Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $cert) {
        Write-Error "No client certificate found for hostnames: $($hostnames -join ', '). Use -CertificatePath to load a PFX file instead."
        exit 1
    }
    $cert
}

# Resolve certificate
$cert = if ($CertificatePath) { Get-CertFromPfx } else { Get-CertFromKeychain }
Write-Host "Certificate: $($cert.Subject) [$($cert.Thumbprint)]"

# --- Build request URI ---

$uriBuilder = [System.UriBuilder]$FunctionUrl
$params = [System.Web.HttpUtility]::ParseQueryString($uriBuilder.Query)
$params['SecretName'] = $SecretName
$uriBuilder.Query = $params.ToString()
$uri = $uriBuilder.Uri.AbsoluteUri

if ($VerboseLogging) {
    Write-Host "Endpoint: $uri" -ForegroundColor Cyan
}

# --- Invoke the Azure Function with mTLS ---

try {
    $response = Invoke-RestMethod -Uri $uri -Method Get -Certificate $cert -ErrorAction Stop
    Write-Host "Success" -ForegroundColor Green
    Write-Host "SecretName : $($response.SecretName)"
    Write-Host "SecretValue: $($response.SecretValue)"
    Write-Host "CertThumb  : $($response.CertThumb)"
    if ($response.Workload) { Write-Host "Workload   : $($response.Workload)" }
}
catch {
    Write-Error "Request failed: $($_.Exception.Message)"
    if ($VerboseLogging -and $_.Exception.Response) {
        try {
            $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
            Write-Host $reader.ReadToEnd() -ForegroundColor Yellow
            $reader.Dispose()
        } catch { }
    }
    exit 1
}
