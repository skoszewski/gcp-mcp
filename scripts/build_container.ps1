#Requires -Version 7.0
<#
.SYNOPSIS
Builds the gcp-mcp container image with Docker.

.DESCRIPTION
IMAGE overrides the image name (default: gcp-mcp:latest). ARCH selects the architectures:
amd64, arm64 or amd64,arm64 (default: the host's).
#>

$ErrorActionPreference = 'Stop'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    [Console]::Error.WriteLine('Error: docker is not installed')
    exit 1
}

Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    $image = $env:IMAGE ? $env:IMAGE : 'gcp-mcp:latest'
    $version = git describe --tags --always --dirty 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $version) {
        $version = 'dev'
    }

    $platform = $env:ARCH ? @('--platform', (($env:ARCH -split ',' | ForEach-Object { "linux/$_" }) -join ',')) : @()
    docker build @platform --build-arg "VERSION=$version" -t $image .
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
