param(
    [Parameter(Mandatory = $true)]
    [string]$FunctionUrl,            # e.g. https://<func>.azurewebsites.net/api/azfunctioncertificatesecretproxy

    [Parameter(Mandatory = $true)]
    [string]$SecretName,             # e.g. MyStorageAccountKey

    [Parameter(Mandatory = $true)]
    [string]$Thumbprint,             # Thumbprint of the client cert in CurrentUser\My

    [switch]$SkipCertCheck           # Optional for lab/local testing
)

$cert = Get-ChildItem -Path Cert:\CurrentUser\My\$Thumbprint -ErrorAction SilentlyContinue
if (-not $cert) {
    Write-Error "Certificate with thumbprint $Thumbprint not found in Cert:\CurrentUser\My"
    exit 1
}

$uri = "$FunctionUrl?SecretName=$([uri]::EscapeDataString($SecretName))"

try {
    $response = Invoke-RestMethod -Uri $uri -Method Get -Certificate $cert -SkipCertificateCheck:$SkipCertCheck
    Write-Host "SecretName : $($response.SecretName)"
    Write-Host "SecretValue: $($response.SecretValue)"
    Write-Host "CertThumb  : $($response.CertThumb)"
}
catch {
    Write-Error "Request failed: $($_.Exception.Message)"
    if ($_.Exception.Response -and $_.Exception.Response.ContentLength -gt 0) {
        $reader = New-Object IO.StreamReader $_.Exception.Response.GetResponseStream()
        Write-Error "Server response: $($reader.ReadToEnd())"
    }
    exit 1
}
