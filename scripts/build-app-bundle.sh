#!/usr/bin/env bash
# ==============================================================================
# SuperLexicon App Store Bundle Builder (`scripts/build-app-bundle.sh`)
# ==============================================================================
# Compiles an optional Halt-Free Subroutine (`.wasm`) + bundles a multi-file UI
# (`index.html` + local `.css` / `.js` / assets) into a bit-for-bit reproducible
# RFC 1952 `.html.gz` archive (`mtime=0`, `level=9`) + `<slug>.manifest.json`
# ready for direct drag-and-drop upload to the SuperLexicon Decentralized App Store.
#
# Usage examples:
#   1) Inside a full-stack HFS + UI project scaffolded via `cargo hps new my-app --with-ui`:
#      /path/to/haltproof-subroutines/scripts/build-app-bundle.sh .
#
#   2) Package a standalone UI folder (composing shared HFSes without a new .wasm):
#      ./scripts/build-app-bundle.sh --no-wasm --ui ./my-ui/index.html --slug my-app --title "My App"
#
#   3) Forward any `cargo hps bundle` flags directly:
#      ./scripts/build-app-bundle.sh --help
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_HPS_MANIFEST="${REPO_ROOT}/Cargo.toml"

if [[ "${1:-}" != "" && -d "${1}" && "${1}" != -* ]]; then
  TARGET_PROJECT="$(cd "${1}" && pwd)"
  shift
  cd "${TARGET_PROJECT}"
fi

exec cargo run --quiet --release --manifest-path "${CARGO_HPS_MANIFEST}" -p cargo-hps -- bundle "$@"
