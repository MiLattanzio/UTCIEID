#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
package_version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$repo_dir/packaging/click/manifest.json")"
[[ "$package_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
output_dir="$repo_dir/artifacts/click"
mkdir -p "$output_dir"
stage_dir="$(mktemp -d "$output_dir/stage.XXXXXX")"
trap 'rm -rf -- "$stage_dir"' EXIT
dotnet publish "$repo_dir/src/UTCIEID.App/UTCIEID.App.csproj" -c Release -r linux-arm64 --self-contained true \
    -p:PublishTrimmed=false -p:PublishAot=false -p:PublishSingleFile=false -p:UseSharedCompilation=false \
    --disable-build-servers -m:1 -o "$stage_dir/app" "$@"
if rg -q 'UTDotNet' "$stage_dir/app/UTCIEID.deps.json"; then
    echo 'Unexpected UTDotNet dependency.' >&2
    exit 1
fi
migration_build=false
for argument in "$@"; do
    if [[ "$argument" == '-p:EnableLegacyMigration=true' ]]; then migration_build=true; fi
done
if $migration_build; then
    echo 'Development migration build: do not upload to OpenStore.' >&2
elif rg -a -q 'SecretServicePinStore' "$stage_dir/app/UTCie.Linux.dll"; then
    echo 'Unexpected Secret Service backend in the release build.' >&2
    exit 1
fi
# Debug symbols contain workstation source paths and are not needed on devices.
find "$stage_dir/app" -type f -name '*.pdb' -delete
cp "$repo_dir"/packaging/click/* "$stage_dir/"
cp -R "$repo_dir/licenses" "$stage_dir/"
docker run --rm --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$repo_dir/native,dst=/src,readonly" \
    --mount "type=bind,src=$stage_dir/app,dst=/out" \
    --entrypoint aarch64-linux-gnu-gcc "${CLICK_BUILD_IMAGE:-clickable/amd64-ut24.04-2.x-arm64:latest}" \
    -std=c11 -O2 -Wall -Wextra -Werror -shared -fPIC /src/portrait.c -o /out/libutcieid-portrait.so -Wl,-z,relro,-z,now -Wl,-l:libopenjp2.so.7
docker run --rm --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$repo_dir/native,dst=/src,readonly" \
    --mount "type=bind,src=$stage_dir/app,dst=/out" \
    --entrypoint aarch64-linux-gnu-gcc "${CLICK_BUILD_IMAGE:-clickable/amd64-ut24.04-2.x-arm64:latest}" \
    -std=c11 -O2 -Wall -Wextra -Werror /src/camera.c -o /out/utcieid-camera -Wl,-z,relro,-z,now -ldl -pthread
chmod +x "$stage_dir/launch.sh" "$stage_dir/app/UTCIEID"
docker run --rm --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$output_dir,dst=/work" --workdir /work \
    --entrypoint click "${CLICK_BUILD_IMAGE:-clickable/amd64-ut24.04-2.x-arm64:latest}" build --no-validate "${stage_dir##*/}"
sha256sum "$output_dir/utcieid.milattanzio_${package_version}_arm64.click"
