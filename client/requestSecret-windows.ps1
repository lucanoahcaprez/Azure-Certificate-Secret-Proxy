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
    if ($CertificatePassword) {
        $pwd = ConvertTo-SecureString $CertificatePassword -AsPlainText -Force
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath, $pwd)
    }
    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
}

function Get-CertFromStore {
    $stores = @('Cert:\LocalMachine\My', 'Cert:\CurrentUser\My')

    if ($Thumbprint) {
        foreach ($s in $stores) {
            $c = Get-ChildItem "$s\$Thumbprint" -ErrorAction SilentlyContinue
            if ($c) { return $c }
        }
        Write-Error "Certificate with thumbprint $Thumbprint not found"; exit 1
    }

    # Auto-discover by hostname
    $hostnames = @(
        $env:COMPUTERNAME
        try { [System.Net.Dns]::GetHostEntry('').HostName } catch { }
    ) | Where-Object { $_ } | Select-Object -Unique

    $certs = foreach ($s in $stores) {
        Get-ChildItem $s -ErrorAction SilentlyContinue | Where-Object {
            $_.HasPrivateKey -and (
                $_.Subject -match ($hostnames -join '|') -or
                ($_.DnsNameList.Unicode | Where-Object { $_ -in $hostnames })
            )
        }
    }

    $cert = $certs | Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $cert) {
        Write-Error "No client certificate found for hostnames: $($hostnames -join ', ')"; exit 1
    }
    $cert
}

# Resolve certificate
$cert = if ($CertificatePath) { Get-CertFromPfx } else { Get-CertFromStore }
Write-Host "Certificate: $($cert.Subject) [$($cert.Thumbprint)]"

# --- Build request URI ---

Add-Type -AssemblyName System.Web
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
