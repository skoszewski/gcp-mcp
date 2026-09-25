#!/usr/bin/env bash
#
# Runs the gcp-mcp container image with Docker, or with Apple container when Docker is not
# installed. Arguments are passed to gcp-mcp. The Application Default Credentials file,
# GOOGLE_APPLICATION_CREDENTIALS or else the gcloud well-known file in CLOUDSDK_CONFIG or the
# gcloud default configuration directory, is mounted read-only into the container, and so is the
# file named by CLOUDSDK_AUTH_ACCESS_TOKEN_FILE. Variables come from .env in the repository root
# when it exists, and from CLOUDSDK_AUTH_ACCESS_TOKEN, GOOGLE_CLOUD_PROJECT, GCLOUD_PROJECT and
# GOOGLE_CLOUD_QUOTA_PROJECT when they are set. IMAGE overrides the image name (default:
# gcp-mcp:latest) and PORT the host port published on 127.0.0.1 (default: 8889).

set -euo pipefail

cd "$(dirname "$0")/.."
image="${IMAGE:-gcp-mcp:latest}"
port="${PORT:-8889}"
credentials="${GOOGLE_APPLICATION_CREDENTIALS:-${CLOUDSDK_CONFIG:-${HOME}/.config/gcloud}/application_default_credentials.json}"
target=/var/run/gcp/credentials.json
token_target=/var/run/gcp/access_token

run_args=(run --rm -i -p "127.0.0.1:${port}:8889")
if [[ -f .env ]]; then
    run_args+=(--env-file .env)
fi
if [[ -f "${credentials}" ]]; then
    run_args+=(--mount "type=bind,source=${credentials},target=${target},readonly" -e "GOOGLE_APPLICATION_CREDENTIALS=${target}")
fi
if [[ -f "${CLOUDSDK_AUTH_ACCESS_TOKEN_FILE:-}" ]]; then
    run_args+=(--mount "type=bind,source=${CLOUDSDK_AUTH_ACCESS_TOKEN_FILE},target=${token_target},readonly" -e "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE=${token_target}")
fi
for name in CLOUDSDK_AUTH_ACCESS_TOKEN GOOGLE_CLOUD_PROJECT GCLOUD_PROJECT GOOGLE_CLOUD_QUOTA_PROJECT; do
    if [[ -n "${!name:-}" ]]; then
        run_args+=(-e "${name}")
    fi
done

if command -v docker >/dev/null 2>&1; then
    exec docker "${run_args[@]}" "${image}" "$@"
elif command -v container >/dev/null 2>&1; then
    # Starts the Apple container services when they are stopped.
    container system status >/dev/null 2>&1 || container system start

    # Stops the container on INT and TERM.
    name="gcp-mcp-$$"
    trap 'container stop "${name}" >/dev/null' INT TERM
    container "${run_args[0]}" --name "${name}" "${run_args[@]:1}" "${image}" "$@" <&0 &
    client=$!
    status=0
    while kill -0 "${client}" 2>/dev/null; do
        wait "${client}" || status=$?
    done
    exit "${status}"
else
    echo "Error: neither docker nor Apple container is installed" >&2
    exit 1
fi
