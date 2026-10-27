#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 -m venv "$work/venv"
"$work/venv/bin/pip" install -q ruff==0.14.14 shellcheck-py==0.11.0.1 PyYAML==6.0.3
export PATH="$work/venv/bin:$PATH"
ruff check scripts
ruff format --check scripts
shellcheck scripts/check.sh
case $(uname -m) in
    x86_64)
        arch=amd64
        checksum=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
        ;;
    aarch64)
        arch=arm64
        checksum=325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6
        ;;
    *) exit 1 ;;
esac
curl -fsSL "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_$arch.tar.gz" \
    -o "$work/actionlint.tar.gz"
printf '%s  %s\n' "$checksum" "$work/actionlint.tar.gz" | sha256sum -c -
tar -xzf "$work/actionlint.tar.gz" -C "$work" actionlint
"$work/actionlint" .github/workflows/*
python3 -m unittest discover -s scripts -p 'test_*.py' -v
