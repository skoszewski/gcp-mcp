#Requires -Version 7.0
<#
.SYNOPSIS
Runs bin/gcp-mcp over the stdio transport, for an MCP client that starts the server itself.

.DESCRIPTION
Arguments are passed to gcp-mcp; --transport http serves Streamable HTTP instead. The variables
in .env in the repository root are set for the server when the file exists.
#>

$ErrorActionPreference = 'Stop'

$root = Split-Path $PSScriptRoot -Parent
$binary = Join-Path $root 'bin' ($IsWindows ? 'gcp-mcp.exe' : 'gcp-mcp')
if (-not (Test-Path $binary)) {
    [Console]::Error.WriteLine("Error: $binary not found; run scripts/build.ps1 first")
    exit 1
}

# Sets the variables of the Docker environment file .env for the server.
$saved = @{}
$envFile = Join-Path $root '.env'
if (Test-Path $envFile) {
    foreach ($line in Get-Content -LiteralPath $envFile) {
        if ($line.Contains('=') -and -not $line.StartsWith('#')) {
            $name, $value = $line -split '=', 2
            $saved[$name] = [Environment]::GetEnvironmentVariable($name)
            [Environment]::SetEnvironmentVariable($name, $value)
        }
    }
}

try {
    & $binary --transport stdio @args
    $status = $LASTEXITCODE
}
finally {
    foreach ($name in $saved.Keys) {
        [Environment]::SetEnvironmentVariable($name, $saved[$name])
    }
}
exit $status
