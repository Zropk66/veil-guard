param([string]$BuildDir = "build")

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root

try {
    node tests/gen_vectors.mjs
    if ($LASTEXITCODE -ne 0) { throw "vector generation failed" }

    & "$root/$BuildDir/vectors_test.exe"
    if ($LASTEXITCODE -ne 0) { throw "cross implementation vectors diverged" }
} finally {
    Pop-Location
}
