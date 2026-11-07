#requires -Version 5.1
$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    exit
}

$sourceDirectory = $PSScriptRoot
$driverSource = Join-Path $sourceDirectory 'FuriousWfpCallout.sys'
$serviceSource = Join-Path $sourceDirectory 'FuriousWfpService.exe'
$certificateSource = Join-Path $sourceDirectory 'FuriousWfpCallout.cer'
foreach ($path in @($driverSource, $serviceSource, $certificateSource)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required WFP package file is missing: $path" }
}

$installDirectory = Join-Path $env:ProgramFiles 'Furious\Wfp'
New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null
Copy-Item -LiteralPath $driverSource -Destination (Join-Path $installDirectory 'FuriousWfpCallout.sys') -Force
Copy-Item -LiteralPath $serviceSource -Destination (Join-Path $installDirectory 'FuriousWfpService.exe') -Force
Copy-Item -LiteralPath $certificateSource -Destination (Join-Path $installDirectory 'FuriousWfpCallout.cer') -Force

$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificateSource)
$driverSignature = Get-AuthenticodeSignature -FilePath $driverSource
if ($driverSignature.Status -ne 'Valid' -or $null -eq $driverSignature.SignerCertificate -or $driverSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
    throw 'The WFP driver signature is invalid or does not match the bundled test certificate.'
}
Import-Certificate -FilePath $certificateSource -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
Import-Certificate -FilePath $certificateSource -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null

$bootConfig = (& bcdedit.exe /enum '{current}' 2>&1 | Out-String)
$testSigningEnabled = $bootConfig -match '(?im)^\s*testsigning\s+Yes\s*$'
$rebootRequired = $false
if (-not $testSigningEnabled) {
    & bcdedit.exe /set testsigning on
    if ($LASTEXITCODE -ne 0) { throw 'Could not enable TESTSIGNING. Secure Boot or device policy may block it. This installer will not disable Secure Boot.' }
    $rebootRequired = $true
}

$servicePath = Join-Path $installDirectory 'FuriousWfpService.exe'
$quotedServicePath = '"' + $servicePath + '"'
& sc.exe query FuriousWfpService *> $null
if ($LASTEXITCODE -eq 0) {
    & sc.exe config FuriousWfpService "binPath= $quotedServicePath" 'start= auto' 'obj= LocalSystem' | Out-Host
} else {
    & sc.exe create FuriousWfpService "binPath= $quotedServicePath" 'start= auto' 'obj= LocalSystem' 'DisplayName= Furious WFP Service' | Out-Host
}
if ($LASTEXITCODE -ne 0) { throw 'Could not register the Furious WFP user-mode service.' }

if ($rebootRequired) {
    Write-Host 'WFP test files and certificate are installed. Restart Windows to activate TESTSIGNING; the WFP service is configured to start automatically after reboot.' -ForegroundColor Yellow
} else {
    & sc.exe start FuriousWfpService | Out-Host
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1056) { throw 'The WFP service could not be started. Check test-signing status and Windows Code Integrity events.' }
    Write-Host 'WFP service start requested. Verify with: sc query FuriousWfpService' -ForegroundColor Green
}
