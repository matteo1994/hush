#!/usr/bin/env bash
# Checks that VS Code started by `hush run` sends a bound key the way its
# extensions would: Node https, fetch, a child process, curl, and the
# integrated terminal. See "VS Code and its extensions" in the README.
#
#   scripts/vscode-check/run.sh [SECRET] [URL]
#
# SECRET (default HUSH_CHECK) must be bound to the echo service at URL
# (default https://postman-echo.com/headers), for instance:
#   HUSH_SECRET_VALUE=not-a-real-key hush secret add HUSH_CHECK --host postman-echo.com
# Uses a temporary VS Code profile, so it runs beside your usual VS Code,
# and the settings the README recommends. VSCODE_BIN and HUSH_BIN override
# where VS Code and hush are found.
set -euo pipefail

secret=${1:-HUSH_CHECK}
url=${2:-https://postman-echo.com/headers}
vscode=${VSCODE_BIN:-/Applications/Visual Studio Code.app/Contents/MacOS/Code}
hush=${HUSH_BIN:-hush}
here=$(cd "$(dirname "$0")" && pwd)

# Short, because VS Code's socket in the user-data dir must fit in 103 bytes.
profile=$(mktemp -d /tmp/hush-vscode.XXXXXX)
trap 'rm -rf "$profile"' EXIT
mkdir -p "$profile/User"
echo '{ "http.fetchAdditionalSupport": false }' > "$profile/User/settings.json"

CHECK_SECRET=$secret CHECK_URL=$url CHECK_OUT=$profile/results \
    "$hush" run --secret "$secret" -- "$vscode" --new-window --user-data-dir "$profile" \
    --extensions-dir "$profile/extensions" --extensionDevelopmentPath="$here/extension" \
    --skip-welcome --disable-workspace-trust > "$profile/vscode.log" 2>&1 \
    || { tail -5 "$profile/vscode.log" >&2; exit 1; }

if [ ! -s "$profile/results" ]; then
    echo "VS Code quit without results; its output was:" >&2
    tail -20 "$profile/vscode.log" >&2
    exit 1
fi
cat "$profile/results"
! grep -qv ': ok$' "$profile/results"
