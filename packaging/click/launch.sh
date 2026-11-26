#!/bin/sh
set -eu
cd "${0%/*}"
export DOTNET_EnableDiagnostics=0
export RESOURCE_NAME="${APP_ID:-utcieid.milattanzio_utcieid}"
if [ "${UTCIEID_BACKEND:-x11}" = wayland ]; then
    unset DISPLAY
    exec ./app/UTCIEID --wayland "$@"
fi
exec ./app/UTCIEID "$@"
