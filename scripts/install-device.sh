#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
package_version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$repo_dir/packaging/click/manifest.json")"
[[ "$package_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
package_name="utcieid.milattanzio_${package_version}_arm64.click"
package="$repo_dir/artifacts/click/$package_name"
test -f "$package"
adb shell mkdir -p /home/phablet/utcieid-verification
adb push "$package" /home/phablet/utcieid-verification/
adb shell "gdbus call --system --dest com.lomiri.click --object-path /com/lomiri/click --method com.lomiri.click.Install /home/phablet/utcieid-verification/$package_name"
adb shell "uid=\$(id -u); export XDG_RUNTIME_DIR=/run/user/\$uid; export DBUS_SESSION_BUS_ADDRESS=unix:path=\$XDG_RUNTIME_DIR/bus; lomiri-app-launch utcieid.milattanzio_utcieid_$package_version"
