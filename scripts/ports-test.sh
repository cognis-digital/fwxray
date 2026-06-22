#!/usr/bin/env bash
# Run every language port of the fwxray core check against a demo image.
set -e
IMG="${1:-demos/05-debug-backdoor/new.bin}"
echo "== Python ==";     PYTHONPATH="$PWD" python -m fwxray inspect "$IMG" --format json | head -8 || echo "python: skipped"
echo "== JavaScript =="; node ports/javascript/index.js "$IMG" || echo "node: skipped"
echo "== Shell ==";      bash ports/shell/fwxray.sh "$IMG" || echo "shell: skipped"
echo "== Go ==";         ( cd ports/go && go run . "../../$IMG" ) || echo "go: skipped (toolchain — see CI)"
echo "== Rust ==";       ( cd ports/rust && cargo run --quiet -- "../../$IMG" ) || echo "rust: skipped (toolchain — see CI)"
