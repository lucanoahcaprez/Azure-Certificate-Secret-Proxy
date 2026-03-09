param(
    [Parameter(Mandatory = $true)]
    [string]$FunctionUrl,            # e.g. https://<func>.azurewebsites.net/api/azfunctioncertificatesecretproxy

    [Parameter(Mandatory = $true)]
    [string]$SecretName,             # e.g. MyStorageAccountKey

    [string]$Thumbprint,             # Optional; if omitted the script picks a cert that matches the device hostname

    [string]$CertificatePath,        # Optional; path to PFX file (use with -CertificatePassword)

    [string]$CertificatePassword,    # Optional; password for PFX file (use with -CertificatePath)

    [switch]$VerboseLogging          # Emit detailed request/response diagnostics
)

function Get-HostnameCandidates {
    $hosts = @()
    if ($env:COMPUTERNAME) { $hosts += $env:COMPUTERNAME }
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry('').HostName
        if ($fqdn -and $fqdn -notin $hosts) { $hosts += $fqdn }
    }
    catch { }
    $hosts | Where-Object { $_ } | Select-Object -Unique
}

function Find-CertByThumbprint([string]$thumb) {
    foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        $c = Get-ChildItem -Path "$store\$thumb" -ErrorAction SilentlyContinue
        if ($c) { return $c }
    }
    $null
}

function Find-CertByHostname([string[]]$hostnames) {
    $candidates = @()
    foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        foreach ($h in $hostnames) {
            try {
                $candidates += Get-ChildItem -Path $store -DnsName $h -ErrorAction Stop
            }
            catch [System.Management.Automation.ParameterBindingException] {
                # Older PowerShell versions may not support -DnsName; fall back to subject/SAN checks below
            }
            catch {
                # Ignore missing store or other non-terminating errors
            }
        }
        if (-not $candidates) {
            $candidates += Get-ChildItem -Path $store -ErrorAction SilentlyContinue | Where-Object {
                $subject = $_.Subject
                $dnsMatch = $false
                if ($_.DnsNameList) {
                    foreach ($n in $_.DnsNameList) {
                        if ($hostnames -contains $n.Unicode) { $dnsMatch = $true; break }
                    }
                }
                $cnMatch = $hostnames | ForEach-Object { $hn = $_; $subject -match "(^|,\\s*)CN=$([regex]::Escape($hn))(,|$)" } | Where-Object { $_ } | Select-Object -First 1
                $dnsMatch -or [bool]$cnMatch
            }
        }
    }

    $candidates = $candidates | Where-Object {
        $_.HasPrivateKey -and (
            $_.EnhancedKeyUsageList.Count -eq 0 -or
            ($_.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -eq 'Client Authentication' -or $_.Value -eq '1.3.6.1.5.5.7.3.2' })
        )
    }

    $candidates = $candidates | Sort-Object Thumbprint -Unique | Sort-Object NotAfter -Descending
    $candidates | Select-Object -First 1
}

function Get-ClientCertificate {
    # Load from PFX file if path provided
    if ($CertificatePath) {
        if (-not (Test-Path $CertificatePath)) {
            Write-Error "Certificate file not found: $CertificatePath"
            exit 1
        }
        try {
            if ($CertificatePassword) {
                $securePwd = ConvertTo-SecureString -String $CertificatePassword -AsPlainText -Force
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath, $securePwd)
            } else {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
            }
            Write-Host "Loaded certificate from PFX: $($cert.Subject) [$($cert.Thumbprint)]"
            return $cert
        }
        catch {
            Write-Error "Failed to load PFX certificate: $($_.Exception.Message)"
            exit 1
        }
    }
    
    # Load from certificate store (by thumbprint or hostname)
    if ($Thumbprint) {
        $cert = Find-CertByThumbprint -thumb $Thumbprint
        if (-not $cert) {
            Write-Error "Certificate with thumbprint $Thumbprint not found in CurrentUser\\My or LocalMachine\\My"
            exit 1
        }
    }
    else {
        $hosts = Get-HostnameCandidates
        $cert = Find-CertByHostname -hostnames $hosts
        if (-not $cert) {
            Write-Error "No client certificate found with CN or SAN matching hostname(s): $($hosts -join ', ')"
            exit 1
        }
        Write-Host "Auto-selected certificate $($cert.Subject) [$($cert.Thumbprint)] based on hostname"
    }
    
    $cert
}

$cert = Get-ClientCertificate

Add-Type -AssemblyName System.Web
$uriBuilder = [System.UriBuilder]$FunctionUrl
$query = [System.Web.HttpUtility]::ParseQueryString($uriBuilder.Query)
$query['SecretName'] = $SecretName
$uriBuilder.Query = $query.ToString()
$uri = $uriBuilder.Uri.AbsoluteUri

# Call the Azure Function with client certificate for mTLS
# The client certificate is sent via TLS client certificate negotiation (not as data in headers)
try {
    $response = Invoke-RestMethod -Uri $uri -Method Get -Certificate $cert -ErrorAction Stop
    Write-Host "SecretName : $($response.SecretName)"
    Write-Host "SecretValue: $($response.SecretValue)"
    Write-Host "CertThumb  : $($response.CertThumb)"
}
catch {
    Write-Error "Request failed: $($_.Exception.Message)"
    exit 1
}
