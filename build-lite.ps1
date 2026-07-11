$ErrorActionPreference = "Stop"

$project = Join-Path $PSScriptRoot "CloudflareProxyLite\CloudflareProxyLite.csproj"
$source = Join-Path $PSScriptRoot "CloudflareProxyLite\bin\Release\net48\CloudflareProxy.exe"
$output = Join-Path $PSScriptRoot "dist-lite"

dotnet build $project --configuration Release
if ($LASTEXITCODE -ne 0) {
    throw "dotnet build failed with exit code $LASTEXITCODE"
}

New-Item -ItemType Directory -Path $output -Force | Out-Null
Copy-Item -LiteralPath $source -Destination (Join-Path $output "CloudflareProxy.exe") -Force

Write-Host "Single-file Lite build published to $output"
