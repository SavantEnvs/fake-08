#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# 1) The emulator core, sanitized. Upstream has only hand-rolled per-platform makefiles; the headless
#    source set is test/Makefile's: source/*.cpp minus logger.cpp / main.cpp / hostCommonFunctions.cpp
#    (platform glue), plus libs/z8lua, lodepng and miniz. z8lua's .c files are C++ (fix32 is a C++
#    class; upstream sets CC=$(CXX)), so they are compiled with -x c++. test/stubhost.cpp is upstream's
#    headless Host implementation and test/nooplogger.cpp its no-op logger.
#    Objects go to mayhem/build/ (gitignored by upstream's `build/` rule), rebuilt on every run.
OBJ="$SRC/mayhem/build/fuzz"
mkdir -p "$OBJ"
# -fsanitize=fuzzer-no-link: SanCov on the emulator itself, not just the harness TU (also with empty SANITIZER_FLAGS).
# UBSan relaxation (the ONLY one): -fno-sanitize=shift-base. z8lua's fix32 (libs/z8lua/fix32.h) is a
# 16.16 fixed-point type built on `int32_t(x << 16)` for negative x and wrapping shifts — UB before C++20,
# defined since, and the design of PICO-8 number semantics. Every cart hits it on its first number, so
# without this every input halts there. shift-exponent and the rest of UBSan stay on and halting.
UBSAN_RELAX=""
case "$SANITIZER_FLAGS" in *undefined*|*shift*) UBSAN_RELAX="-fno-sanitize=shift-base" ;; esac
# On the z8lua VM sources only, also -fno-sanitize=signed-integer-overflow: fix32's operator+/-/* wrap
# int32 by design (PICO-8 numbers wrap at 32767.99; upstream's test/carts/loop_max_val.p8 tests it), and
# the VM's arithmetic opcodes are where every cart's math runs. Emulator code (source/) keeps the check.
Z8LUA_RELAX=""
case "$SANITIZER_FLAGS" in *undefined*|*signed-integer-overflow*) Z8LUA_RELAX="-fno-sanitize=signed-integer-overflow" ;; esac
FUZZ_CXXFLAGS="-std=c++17 -O1 -fexceptions -w -fsanitize=fuzzer-no-link $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS"
INC=(-I"$SRC/source" -I"$SRC/libs/z8lua" -I"$SRC/libs/lodepng" -I"$SRC/libs/simpleini" -I"$SRC/libs/miniz" -I"$SRC/test")
srcs=()
for f in "$SRC"/source/*.cpp; do
  case "$(basename "$f")" in logger.cpp|main.cpp|hostCommonFunctions.cpp) continue ;; esac
  srcs+=("$f")
done
srcs+=("$SRC"/libs/z8lua/*.c "$SRC/libs/lodepng/lodepng.cpp" "$SRC/libs/miniz/miniz.c"
       "$SRC/test/stubhost.cpp" "$SRC/test/nooplogger.cpp" "$SRC/mayhem/lsan_off.cc")
export FUZZ_CXXFLAGS OBJ Z8LUA_RELAX
printf '%s\n' "${srcs[@]}" | INCS="${INC[*]}" xargs -P "$MAYHEM_JOBS" -I{} bash -c '
  f="$1"; o="$OBJ/$(basename "$f").o"; extra=""
  case "$f" in */libs/z8lua/*) extra="$Z8LUA_RELAX" ;; esac
  # shellcheck disable=SC2086
  $CXX -x c++ $FUZZ_CXXFLAGS $extra $INCS -c "$f" -o "$o"' _ {}
objs=()
for f in "${srcs[@]}"; do objs+=("$OBJ/$(basename "$f").o"); done

# 2) Each harness twice: the libFuzzer binary and the run-once -standalone reproducer.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
for h in fuzz_cart_run fuzz_cart_load fuzz_cart_file; do
  # shellcheck disable=SC2086
  $CXX $FUZZ_CXXFLAGS "${INC[@]}" -c "$SRC/mayhem/harnesses/$h.cpp" -o "$OBJ/$h.o"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OBJ/$h.o" "${objs[@]}" -o "/mayhem/$h"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS "$OBJ/standalone_main.o" "$OBJ/$h.o" "${objs[@]}" -o "/mayhem/$h-standalone"
done

# 3) Upstream's own doctest suite (`make tests` = make -C test), with its NORMAL flags, unsanitized.
#    test/Makefile sets its own CFLAGS; DEFINES/LIBS are its hooks for extra compile/link flags.
#    Output: test/testrunner.a (gitignored), run from test/ by mayhem/test.sh.
make -C "$SRC/test" -j"$MAYHEM_JOBS" CXX="$CXX" DEFINES="$COVERAGE_FLAGS" LIBS="$COVERAGE_FLAGS"
test -x "$SRC/test/testrunner.a"
echo "build.sh: OK"
