# 文件加密工具 — Windows 构建脚本
# 用法: powershell -ExecutionPolicy Bypass -File scripts\build.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$dotnet = "C:\Program Files\dotnet\dotnet.exe"
if (-not (Test-Path $dotnet)) {
    $dotnet = "dotnet"
}

Write-Host "==> Build Core" -ForegroundColor Cyan
& $dotnet build src/YuexuanCrypto.Core/YuexuanCrypto.Core.csproj --no-restore -c Release
if ($LASTEXITCODE -ne 0) { throw "Core build failed" }

Write-Host "==> Build Tests" -ForegroundColor Cyan
& $dotnet build tests/YuexuanCrypto.Core.Tests/YuexuanCrypto.Core.Tests.csproj --no-restore -c Release
if ($LASTEXITCODE -ne 0) { throw "Tests build failed" }

Write-Host "==> Run Tests" -ForegroundColor Cyan
& $dotnet run --project tests/YuexuanCrypto.Core.Tests/YuexuanCrypto.Core.Tests.csproj --no-build -c Release
if ($LASTEXITCODE -ne 0) { throw "Tests failed" }

Write-Host "==> Publish self-contained single-file" -ForegroundColor Cyan
& $dotnet publish src/YuexuanCrypto.App/YuexuanCrypto.App.csproj --no-restore -c Release `
    -r win-x64 --self-contained true `
    /p:PublishSingleFile=true `
    /p:IncludeNativeLibrariesForSelfExtract=true `
    /p:EnableCompressionInSingleFile=true `
    /p:PublishTrimmed=false `
    -o dist
if ($LASTEXITCODE -ne 0) { throw "Publish failed" }

$exe = Join-Path $root "dist\YuexuanCrypto.exe"
Write-Host "==> Done: $exe ($([math]::Round((Get-Item $exe).Length/1MB,1)) MB)" -ForegroundColor Green
