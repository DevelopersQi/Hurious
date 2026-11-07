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

& sc.exe stop FuriousWfpService | Out-Host
Start-Sleep -Seconds 2
& sc.exe delete FuriousWfpService | Out-Host
& sc.exe stop FuriousWfpCallout | Out-Host
Start-Sleep -Seconds 2
& sc.exe delete FuriousWfpCallout | Out-Host

$installDirectory = Join-Path $env:ProgramFiles 'Furious\Wfp'
$certificatePath = Join-Path $installDirectory 'FuriousWfpCallout.cer'
if (Test-Path -LiteralPath $certificatePath -PathType Leaf) {
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath)
    foreach ($store in @('Root', 'TrustedPublisher')) {
        $storePath = "Cert:\LocalMachine\$store"
        Get-ChildItem -Path $storePath | Where-Object Thumbprint -eq $certificate.Thumbprint | Remove-Item -Force
    }
}
Remove-Item -LiteralPath $installDirectory -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'Furious WFP service, driver service entry, and test certificate have been removed.' -ForegroundColor Green
Write-Warning 'TESTSIGNING is a system-wide boot option and was intentionally left unchanged. If no other test-signed drivers are used, disable it manually with: bcdedit /set testsigning off, then restart Windows.'
