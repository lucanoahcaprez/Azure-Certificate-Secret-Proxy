#!/usr/bin/env powershell

$thumb = "22E4D9050A50F3AC0A6588C641BD4BE869F788CD"
$uri = "https://func-lnc-lab-certificatesecretproxy-test-01-gbc7aua9gnegf9a5.switzerlandnorth-01.azurewebsites.net/api/certificatesecretproxy?code=Yn7HJ5Ll0ynoTYYO-sofnpT51SbjdkBIrU7jiLzhY7LeAzFucN6n4g==&SecretName=Secret12345"

$cert = Get-ChildItem -Path "Cert:\LocalMachine\My\$thumb" -ErrorAction SilentlyContinue
if (-not $cert) {
    $cert = Get-ChildItem -Path "Cert:\CurrentUser\My\$thumb" -ErrorAction SilentlyContinue
}

if (-not $cert) {
    Write-Host "Certificate not found" -ForegroundColor Red
    exit 1
}

Write-Host "Using certificate: $($cert.Subject)" -ForegroundColor Green
Write-Host "Calling: $uri" -ForegroundColor Cyan

try {
    $response = Invoke-RestMethod -Uri $uri -Method Get -Certificate $cert -ErrorAction Stop
    Write-Host "`nSUCCESS" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 10
}
catch {
    Write-Host "`nFAILED" -ForegroundColor Red
    Write-Host "StatusCode: $($_.Exception.Response.StatusCode)" -ForegroundColor Yellow
    
    $stream = $_.Exception.Response.GetResponseStream()
    $reader = [System.IO.StreamReader]::new($stream)
    $body = $reader.ReadToEnd()
    $reader.Dispose()
    
    Write-Host "`nResponse:" -ForegroundColor Yellow
    Write-Host $body
}

