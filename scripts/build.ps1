# 构建发布脚本（相对仓库根，不依赖固定用户名）
# 用法: powershell -ExecutionPolicy Bypass -File scripts\build.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$dotnet = "C:\Program Files\dotnet\dotnet.exe"
if (-not (Test-Path $dotnet)) { $dotnet = "dotnet" }

$env:NUGET_PACKAGES = Join-Path $root ".nuget-packages"
New-Item -ItemType Directory -Path $env:NUGET_PACKAGES -Force | Out-Null

Write-Host "==> Build Core" -ForegroundColor Cyan
& $dotnet build src/YuexuanCrypto.Core/YuexuanCrypto.Core.csproj --no-restore -c Release
if ($LASTEXITCODE -ne 0) { throw "Core build failed" }

Write-Host "==> Build + Run Tests" -ForegroundColor Cyan
& $dotnet build tests/YuexuanCrypto.Core.Tests/YuexuanCrypto.Core.Tests.csproj --no-restore -c Release
if ($LASTEXITCODE -ne 0) { throw "Tests build failed" }
Copy-Item (Join-Path $root "lib\*.dll") (Join-Path $root "tests\YuexuanCrypto.Core.Tests\bin\Release\net9.0\") -Force
& $dotnet run --project tests/YuexuanCrypto.Core.Tests/YuexuanCrypto.Core.Tests.csproj --no-build -c Release
if ($LASTEXITCODE -ne 0) { throw "Tests failed" }

Write-Host "==> Publish self-contained single-file (icon baked in at compile)" -ForegroundColor Cyan
& $dotnet publish src/YuexuanCrypto.App/YuexuanCrypto.App.csproj --no-restore -c Release `
    -r win-x64 --self-contained true `
    /p:PublishSingleFile=true `
    /p:IncludeNativeLibrariesForSelfExtract=true `
    /p:EnableCompressionInSingleFile=true `
    /p:PublishTrimmed=false `
    -o dist
if ($LASTEXITCODE -ne 0) { throw "Publish failed" }

$exe = Join-Path $root "dist\YuexuanCrypto.exe"
if (-not (Test-Path $exe)) { throw "missing exe" }
Write-Host "==> Done: $exe ($([math]::Round((Get-Item $exe).Length/1MB,1)) MB)" -ForegroundColor Green
Write-Host "请勿用 rcedit 等工具二次改 PE 图标，会破坏单文件包。"
