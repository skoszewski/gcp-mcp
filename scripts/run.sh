#!/usr/bin/env bash
#
# Runs bin/gcp-mcp over the stdio transport, for an MCP client that starts the server itself.
# Arguments are passed to gcp-mcp; --transport http serves Streamable HTTP instead. The variables
# in .env in the repository root are exported to the server when the file exists.

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
binary="${root}/bin/gcp-mcp"

if [[ ! -x "${binary}" ]]; then
    echo "Error: ${binary} not found; run scripts/build.sh first" >&2
    exit 1
fi

# Exports the variables of the Docker environment file .env.
env_file="${root}/.env"
if [[ -f "${env_file}" ]]; then
    while IFS= read -r line || [[ -n "${line}" ]]; do
        if [[ "${line}" == *=* && "${line}" != \#* ]]; then
            export "${line}"
        fi
    done < "${env_file}"
fi

exec "${binary}" --transport stdio "$@"
