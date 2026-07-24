#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

single_build=false
if [ "${1:-}" = "--single" ]; then
  single_build=true
  shift
fi

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 [--single] VERSION [OUTPUT_DIR]" >&2
  exit 2
fi

version="${1#v}"
output_dir="${2:-dist}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "VERSION must be a stable SemVer such as 1.2.3" >&2
  exit 2
fi

# shellcheck disable=SC1091
source reproducible.env

for command_name in docker sha256sum; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required command not found: $command_name" >&2
    exit 1
  fi
done

release_tmp="$(mktemp -d "${TMPDIR:-/tmp}/barely-ap-release.XXXXXX")"
cleanup() {
  rm -rf -- "$release_tmp"
}
trap cleanup EXIT

result="${release_tmp}/result"
mkdir -p "$result"

build_target=artifact
if $single_build; then
  build_target=artifact-single
  echo "Building one Linux ARM64 release stage..."
else
  echo "Building two independent Linux ARM64 release stages..."
fi
docker buildx build \
  --file Dockerfile.release \
  --target "$build_target" \
  --platform linux/arm64 \
  --no-cache \
  --provenance=false \
  --sbom=false \
  --build-arg "RUST_IMAGE=${RUST_IMAGE}" \
  --build-arg "VERSION=${version}" \
  --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
  --output "type=local,dest=${result}" \
  .

asset="barely-ap-v${version}-${RUST_TARGET}.tar.gz"
mkdir -p "$output_dir"
install -m 0644 "${result}/${asset}" "${output_dir}/${asset}"
install -m 0644 "${result}/SHA256SUMS" "${output_dir}/SHA256SUMS"

if $single_build; then
  echo "Release checksum verified:"
else
  echo "Bit-for-bit reproducibility verified:"
fi
(cd "$output_dir" && sha256sum -c SHA256SUMS)
