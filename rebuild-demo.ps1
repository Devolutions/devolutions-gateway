# Rebuild the IronVNC H.264 gateway-webapp demo end-to-end.
#   pwsh ./rebuild-demo.ps1            # full rebuild (wasm + webapp)
#   pwsh ./rebuild-demo.ps1 -SkipWasm  # reuse existing wasm tarball, rebuild webapp only
# After it finishes, run:  node ./serve-demo.cjs
param([switch]$SkipWasm)
$ErrorActionPreference = 'Stop'
$IRONVNC = 'C:\DevDrive\IronVNC'
$DEMO    = 'C:\DevDrive\dgw-vnc-demo'
$env:RUSTUP_TOOLCHAIN = '1.96.0'
$env:CARGO_INCREMENTAL = '0'

if (-not $SkipWasm) {
    Write-Host '== [1/4] building IronVNC web wasm + packing tarball ==' -ForegroundColor Cyan
    Push-Location "$IRONVNC\web-client\iron-remote-desktop-vnc"
    npm run build
    Push-Location dist; npm pack; Pop-Location
    Pop-Location
}

Write-Host '== [2/4] installing tarball into the webapp (force re-extract) ==' -ForegroundColor Cyan
Push-Location "$DEMO\webapp"; pnpm install --force; Pop-Location

Write-Host '== [3/4] ng build gateway-ui ==' -ForegroundColor Cyan
Push-Location "$DEMO\webapp\apps\gateway-ui"; npx ng build --configuration development; Pop-Location

Write-Host '== [4/4] injecting entry scripts + H.264 bridge ==' -ForegroundColor Cyan
node "$DEMO\inject-entry.cjs"

Write-Host ''
Write-Host 'Done. Serve with:  node serve-demo.cjs' -ForegroundColor Green
Write-Host 'App: http://localhost:4300/jet/webapp/client/' -ForegroundColor Green
