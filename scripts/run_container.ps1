#Requires -Version 7.0
<#
.SYNOPSIS
Runs the gcp-mcp container image with Docker.

.DESCRIPTION
Arguments are passed to gcp-mcp. The Application Default Credentials file,
GOOGLE_APPLICATION_CREDENTIALS or else the gcloud well-known file, is mounted read-only into the
container. Variables come from .env in the repository root when it exists, and from
GOOGLE_CLOUD_PROJECT, GCLOUD_PROJECT and GOOGLE_CLOUD_QUOTA_PROJECT when they are set. IMAGE
overrides the image name (default: gcp-mcp:latest) and PORT the host port published on 127.0.0.1
(default: 8889).
#>

$ErrorActionPreference = 'Stop'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    [Console]::Error.WriteLine('Error: docker is not installed')
    exit 1
}

$root = Split-Path $PSScriptRoot -Parent
$image = $env:IMAGE ? $env:IMAGE : 'gcp-mcp:latest'
$port = $env:PORT ? $env:PORT : '8889'
$wellKnown = $IsWindows ? (Join-Path $env:APPDATA 'gcloud' 'application_default_credentials.json') : (Join-Path $HOME '.config' 'gcloud' 'application_default_credentials.json')
$credentials = $env:GOOGLE_APPLICATION_CREDENTIALS ? $env:GOOGLE_APPLICATION_CREDENTIALS : $wellKnown
$target = '/var/run/gcp/credentials.json'

$runArgs = @('--rm', '-i', '-p', "127.0.0.1:${port}:8889")
$envFile = Join-Path $root '.env'
if (Test-Path $envFile) {
    $runArgs += '--env-file', $envFile
}
if (Test-Path $credentials) {
    $runArgs += '--mount', "type=bind,source=$credentials,target=$target,readonly", '-e', "GOOGLE_APPLICATION_CREDENTIALS=$target"
}
foreach ($name in 'GOOGLE_CLOUD_PROJECT', 'GCLOUD_PROJECT', 'GOOGLE_CLOUD_QUOTA_PROJECT') {
    if ([Environment]::GetEnvironmentVariable($name)) {
        $runArgs += '-e', $name
    }
}

docker run @runArgs $image @args
exit $LASTEXITCODE
