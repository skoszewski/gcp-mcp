#Requires -Version 7.0
<#
.SYNOPSIS
Runs the gcp-mcp container image with Docker.

.DESCRIPTION
Arguments are passed to gcp-mcp. The Application Default Credentials file,
GOOGLE_APPLICATION_CREDENTIALS or else the gcloud well-known file in CLOUDSDK_CONFIG or the gcloud
default configuration directory, is mounted read-only into the container, and so is the file
named by CLOUDSDK_AUTH_ACCESS_TOKEN_FILE. Variables come from .env in the repository root when it
exists, and from CLOUDSDK_AUTH_ACCESS_TOKEN, GOOGLE_CLOUD_PROJECT, GCLOUD_PROJECT and
GOOGLE_CLOUD_QUOTA_PROJECT when they are set. IMAGE overrides the image name (default:
gcp-mcp:latest) and PORT the host port published on 127.0.0.1 (default: 8889).
#>

$ErrorActionPreference = 'Stop'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    [Console]::Error.WriteLine('Error: docker is not installed')
    exit 1
}

$root = Split-Path $PSScriptRoot -Parent
$image = $env:IMAGE ? $env:IMAGE : 'gcp-mcp:latest'
$port = $env:PORT ? $env:PORT : '8889'
$configDir = $env:CLOUDSDK_CONFIG ? $env:CLOUDSDK_CONFIG : ($IsWindows ? (Join-Path $env:APPDATA 'gcloud') : (Join-Path $HOME '.config' 'gcloud'))
$wellKnown = Join-Path $configDir 'application_default_credentials.json'
$credentials = $env:GOOGLE_APPLICATION_CREDENTIALS ? $env:GOOGLE_APPLICATION_CREDENTIALS : $wellKnown
$target = '/var/run/gcp/credentials.json'
$tokenTarget = '/var/run/gcp/access_token'

$runArgs = @('--rm', '-i', '-p', "127.0.0.1:${port}:8889")
$envFile = Join-Path $root '.env'
if (Test-Path $envFile) {
    $runArgs += '--env-file', $envFile
}
if (Test-Path $credentials) {
    $runArgs += '--mount', "type=bind,source=$credentials,target=$target,readonly", '-e', "GOOGLE_APPLICATION_CREDENTIALS=$target"
}
if ($env:CLOUDSDK_AUTH_ACCESS_TOKEN_FILE -and (Test-Path $env:CLOUDSDK_AUTH_ACCESS_TOKEN_FILE)) {
    $runArgs += '--mount', "type=bind,source=$($env:CLOUDSDK_AUTH_ACCESS_TOKEN_FILE),target=$tokenTarget,readonly", '-e', "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE=$tokenTarget"
}
foreach ($name in 'CLOUDSDK_AUTH_ACCESS_TOKEN', 'GOOGLE_CLOUD_PROJECT', 'GCLOUD_PROJECT', 'GOOGLE_CLOUD_QUOTA_PROJECT') {
    if ([Environment]::GetEnvironmentVariable($name)) {
        $runArgs += '-e', $name
    }
}

docker run @runArgs $image @args
exit $LASTEXITCODE
