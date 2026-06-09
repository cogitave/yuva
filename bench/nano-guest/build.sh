#!/usr/bin/env bash
# Build the Axis-A nano-guest ELF from nano-guest.S + nano-guest.ld using a
# plain LLVM toolchain (clang as the assembler, ld.lld as the linker). This is
# the CANONICAL, PORTABLE build path: it needs NO nightly Rust / rustup /
# -Zbuild-std, so it runs identically on a stable-only host AND on the CI runner
# (ubuntu-latest ships clang + lld), producing a deterministic, well-formed
# dual-note ELF (verified: PT_NOTE Xen PHYS32_ENTRY type 18 + TABOS type
# 0x54420001, ET_EXEC at 1 MiB). The nightly Rust crate (src/main.rs +
# `cargo nbuild`) embeds this SAME nano-guest.S byte-for-byte and is kept as an
# alternative, but the bench lane builds via THIS script to avoid any
# cargo-config linker-script inheritance from the repo-root .cargo/config.toml.
#
# Usage:  bench/nano-guest/build.sh [OUT_ELF]
#   OUT_ELF defaults to bench/nano-guest/nano-guest.elf
#
# Honours these env overrides (auto-detected if unset):
#   CC   — a clang that targets x86_64 ELF       (default: first of clang,clang-*)
#   LLD  — the LLVM ELF linker                    (default: first of ld.lld,lld)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/nano-guest.S"
LDS="$HERE/nano-guest.ld"
OUT="${1:-$HERE/nano-guest.elf}"
OBJ="$(mktemp --suffix=.o 2>/dev/null || echo "$HERE/nano-guest.o")"

# Pick a clang + an lld, tolerating version-suffixed names on CI runners.
pick() { for c in "$@"; do if command -v "$c" >/dev/null 2>&1; then echo "$c"; return 0; fi; done; return 1; }
CC="${CC:-$(pick clang clang-19 clang-18 clang-17 clang-16 clang-15 cc)}"
LLD="${LLD:-$(pick ld.lld ld.lld-19 ld.lld-18 ld.lld-17 lld)}"
[ -n "$CC" ]  || { echo "build.sh: no clang found (set CC=...)" >&2; exit 127; }
[ -n "$LLD" ] || { echo "build.sh: no ld.lld found (set LLD=...)" >&2; exit 127; }

# Assemble: x86_64 bare-metal ELF object. -ffreestanding/-nostdlib keep libc out;
# the .code32/.code64 directives in the source pick the per-entry bitness.
"$CC" --target=x86_64-unknown-none -ffreestanding -nostdlib -fno-pic \
      -Wa,--noexecstack -c "$SRC" -o "$OBJ"

# Link: ET_EXEC, our linker script, no std, no dynamic linker, gc unused.
"$LLD" -m elf_x86_64 -nostdlib --no-dynamic-linker --gc-sections \
       -T "$LDS" -o "$OUT" "$OBJ"

rm -f "$OBJ"
echo "built $OUT  (CC=$CC LLD=$LLD)"
