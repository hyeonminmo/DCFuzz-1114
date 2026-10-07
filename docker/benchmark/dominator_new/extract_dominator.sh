#!/bin/bash
set -euo pipefail

. $(dirname "$0")/build_bench_common.sh

function require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[dominator-build] ERROR: required command not found: $cmd" >&2
        exit 1
    fi
}

function find_precodegen_bc() {
    local project="$1"
    local bin_name="$2"
    local rundir="/benchmark/RUNDIR-$project"

    if find "$rundir" -name "*${bin_name}*precodegen.bc" | grep -q .; then
        find "$rundir" -name "*${bin_name}*precodegen.bc" | head -n 1
        return 0
    fi

    if find "$rundir" -name "*precodegen.bc" | grep -q .; then
        find "$rundir" -name "*precodegen.bc" -printf '%s %p\n' \
            | sort -nr | head -n 1 | cut -d' ' -f2-
        return 0
    fi

    return 1
}


function count_dominators() {
    local map="$1"

    awk -F'\t' '
        NF >= 3 {
            id = $1 + 0
            if (!seen || id > max) max = id
            seen = 1
        }
        END {
            if (seen) print max + 1
            else print 0
        }
    ' "$map"
}

# Capture only the final link invocation that produces BIN_NAME.
# The capture is NUL-separated so paths/arguments containing spaces remain intact.
function make_link_capture_wrapper() {
    local out="$1"
    local real="$2"
    local capture="$3"
    local bin_name="$4"

    cat > "$out" <<EOF
#!/bin/bash
set -e

REAL="$real"
CAPTURE="$capture"
BIN_NAME="$bin_name"

is_link=1
out_path=""
prev=""

for a in "\$@"; do
    case "\$a" in
        -c|-S|-E|-M|-MM)
            is_link=0
            ;;
    esac

    if [ "\$prev" = "-o" ]; then
        out_path="\$a"
    elif [[ "\$a" == -o* ]] && [ "\$a" != "-o" ]; then
        out_path="\${a#-o}"
    fi

    prev="\$a"
done

if [ "\$is_link" -eq 1 ] && [ -n "\$out_path" ]; then
    if [ "\$(basename "\$out_path")" = "\$BIN_NAME" ]; then
        {
            printf '%s\\0' "\$PWD"
            printf '%s\\0' "\$REAL"
            printf '%s\\0' "\$@"
        } > "\$CAPTURE"
    fi
fi

exec "\$REAL" "\$@"
EOF

    chmod +x "$out"
}

function dump_link_capture() {
    local capture="$1"
    local out_txt="$2"

    python3 - "$capture" "$out_txt" <<'PY_DUMP'
import shlex
import sys
from pathlib import Path

capture = Path(sys.argv[1])
out_txt = Path(sys.argv[2])
parts = [x.decode('utf-8', errors='surrogateescape')
         for x in capture.read_bytes().split(b'\0') if x]
if len(parts) < 2:
    raise SystemExit(f"invalid link capture: {capture}")
pwd, real, *args = parts
with out_txt.open('w', encoding='utf-8') as f:
    f.write(f"cwd: {pwd}\n")
    f.write("command: ")
    f.write(" ".join(shlex.quote(x) for x in [real, *args]))
    f.write("\n")
PY_DUMP
}

# Replay the captured final link without recompiling source files.
# All LLVM-bitcode inputs that participated in LTO are replaced by the single
# instrumented whole-program object. Native objects/libraries and ordinary
# linker flags are preserved.
function relink_from_capture() {
    local capture="$1"
    local dom_obj="$2"
    local runtime_obj="$3"

    python3 - \
        "$capture" \
        "$dom_obj" \
        "$runtime_obj" \
        "$LLVM_BCANALYZER" \
        "$LLVM_AR" <<'PY_RELINK'
from __future__ import annotations

import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

capture = Path(sys.argv[1])
dom_obj = str(Path(sys.argv[2]).resolve())
runtime_obj = str(Path(sys.argv[3]).resolve())
bcanalyzer = sys.argv[4]
llvm_ar = sys.argv[5]

parts = [x.decode('utf-8', errors='surrogateescape')
         for x in capture.read_bytes().split(b'\0') if x]
if len(parts) < 3:
    raise SystemExit(f"[dominator-relink] invalid capture: {capture}")

cwd, real, *args = parts
cwd_path = Path(cwd)

if not cwd_path.is_dir():
    raise SystemExit(f"[dominator-relink] captured cwd does not exist: {cwd}")


def resolve_file(arg: str) -> Path:
    p = Path(arg)
    if not p.is_absolute():
        p = cwd_path / p
    return p


def is_bitcode_file(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        r = subprocess.run(
            [bcanalyzer, str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return r.returncode == 0
    except OSError:
        return False


def archive_has_bitcode(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        r = subprocess.run(
            [llvm_ar, 't', str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except OSError:
        return False
    if r.returncode != 0:
        return False

    members = [x.strip() for x in r.stdout.splitlines() if x.strip()]
    if not members:
        return False

    # A uniform LTO build normally yields all-bitcode local archives. Seeing
    # any bitcode member is enough to classify the archive as an LTO input.
    for member in members:
        try:
            p = subprocess.run(
                [llvm_ar, 'p', str(path), member],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError:
            return False
        if p.returncode != 0 or not p.stdout:
            continue
        with tempfile.NamedTemporaryFile(prefix='dom-ar-', suffix='.o') as tf:
            tf.write(p.stdout)
            tf.flush()
            if is_bitcode_file(Path(tf.name)):
                return True
    return False


def is_lto_input_arg(arg: str) -> bool:
    if arg.startswith('-'):
        return False
    p = resolve_file(arg)
    suffix = p.suffix.lower()
    if suffix in {'.bc', '.o', '.lo', '.obj'}:
        return is_bitcode_file(p)
    if suffix == '.a':
        return archive_has_bitcode(p)
    return False


def is_lto_only_flag(arg: str) -> bool:
    if arg == '-flto' or arg.startswith('-flto='):
        return True
    if arg == '-fno-fat-lto-objects':
        return True
    if arg.startswith('-Wl,-plugin-opt') or arg.startswith('-Wl,--plugin-opt'):
        return True
    if arg.startswith('-Wl,-plugin=') or arg.startswith('-Wl,--plugin='):
        return True
    return False

new_args: list[str] = []
removed_inputs: list[str] = []
removed_flags: list[str] = []
inserted = False

i = 0
while i < len(args):
    arg = args[i]

    if arg == '-o' and i + 1 < len(args):
        new_args.extend([arg, args[i + 1]])
        i += 2
        continue

    if is_lto_only_flag(arg):
        removed_flags.append(arg)
        i += 1
        continue

    if is_lto_input_arg(arg):
        removed_inputs.append(arg)
        if not inserted:
            new_args.extend([dom_obj, runtime_obj])
            inserted = True
        i += 1
        continue

    new_args.append(arg)
    i += 1

if not inserted:
    raise SystemExit(
        "[dominator-relink] no LLVM bitcode object/archive was found in the "
        "captured final link command; refusing to guess how to replace LTO inputs"
    )

print(f"[dominator-relink] cwd={cwd}")
print("[dominator-relink] removed LTO inputs:")
for x in removed_inputs:
    print(f"  - {x}")
if removed_flags:
    print("[dominator-relink] removed LTO-only flags:")
    for x in removed_flags:
        print(f"  - {x}")
print("[dominator-relink] replay command:")
print("  " + " ".join(shlex.quote(x) for x in [real, *new_args]))

r = subprocess.run([real, *new_args], cwd=cwd, check=False)
if r.returncode != 0:
    raise SystemExit(r.returncode)
PY_RELINK
}

# arg1 : Target project
# arg2~: Fuzzing targets
function build_with_Dominator() {
    for TARG in "$@"; do
        local str_array=($TARG)
        local BIN_NAME=${str_array[0]}

        cd /benchmark

        CC="/fuzzer/AFLGo/afl-clang-fast"
        CXX="/fuzzer/AFLGo/afl-clang-fast++"
        TMP_DIR=/benchmark/temp_$1

        for BUG_NAME in "${str_array[@]:1}"; do
            echo "[dominator-build] ==================================================" >&2
            echo "[dominator-build] project=$1 bin=$BIN_NAME bug=$BUG_NAME" >&2
            echo "[dominator-build] ==================================================" >&2

            mkdir -p $TMP_DIR

            cp "/benchmark/target/line/$BIN_NAME/$BUG_NAME" "$TMP_DIR/BBtargets.txt"

            ###################################################################
            # 1. AFLGo 1차 build 수행: BBnames / BBcalls 생성 목적
            ###################################################################
            CC_AFLGO="/fuzzer/AFLGo/afl-clang-fast"
            CXX_AFLGO="/fuzzer/AFLGo/afl-clang-fast++"

            ADDITIONAL_AFLGO="-g -targets=$TMP_DIR/BBtargets.txt \
                                -outdir=$TMP_DIR -flto -fuse-ld=gold \
                                -Wl,-plugin-opt=save-temps"

            build_target $1 $CC_AFLGO $CXX_AFLGO "$ADDITIONAL_AFLGO"

            # AFLGo 산출물 정리
            if [ -f "$TMP_DIR/BBnames.txt" ]; then
                cp "$TMP_DIR/BBnames.txt" "$TMP_DIR/BBnames.raw.txt"
                rev "$TMP_DIR/BBnames.txt" | cut -d: -f2- | rev | sort | uniq \
                    > "$TMP_DIR/BBnames2.txt"
                mv "$TMP_DIR/BBnames2.txt" "$TMP_DIR/BBnames.txt"
            fi

            if [ -f "$TMP_DIR/BBcalls.txt" ]; then
                cp "$TMP_DIR/BBcalls.txt" "$TMP_DIR/BBcalls.raw.txt"
                sort "$TMP_DIR/BBcalls.txt" | uniq > "$TMP_DIR/BBcalls2.txt"
                mv "$TMP_DIR/BBcalls2.txt" "$TMP_DIR/BBcalls.txt"
            fi

            # AFLGo build directory 제거
            rm -rf /benchmark/RUNDIR-$1

            ###################################################################
            # 2. SVF 분석용 clean LLVM/LTO build 수행
            #
            #    이 빌드에서 생성된 whole-program precodegen.bc를 이후
            #    Dominator 분석과 instrumentation 양쪽에 동일하게 사용한다.
            #    또한 source 재컴파일 없이 최종 executable만 다시 link할 수
            #    있도록 최종 link invocation을 캡처한다.
            ###################################################################
            local LINK_CAPTURE="$TMP_DIR/final_link.args0"
            local LINK_CAPTURE_TXT="$TMP_DIR/final_link.txt"
            local CC_SVF="$TMP_DIR/capture-clang"
            local CXX_SVF="$TMP_DIR/capture-clang++"
            local REAL_CC="$(command -v clang-12)"
            local REAL_CXX="$(command -v clang++-12)"
            local LINK_BIN_NAME=""
            case "$1" in
                libming*)
                    LINK_BIN_NAME="$BIN_NAME"
                    ;;
                binutils*)
                    if [ "$BIN_NAME" = "nm" ]; then
                        LINK_BIN_NAME="nm-new"
                    else
                        LINK_BIN_NAME="$BIN_NAME"
                    fi
                    ;;
            esac

            rm -f "$LINK_CAPTURE" "$LINK_CAPTURE_TXT"

            make_link_capture_wrapper \
                "$CC_SVF" "$REAL_CC" "$LINK_CAPTURE" "$LINK_BIN_NAME"
            make_link_capture_wrapper \
                "$CXX_SVF" "$REAL_CXX" "$LINK_CAPTURE" "$LINK_BIN_NAME"

            ADDITIONAL_SVF="-g -flto -fuse-ld=gold \
                            -Wl,-plugin-opt=save-temps"

            build_target "$1" "$CC_SVF" "$CXX_SVF" "$ADDITIONAL_SVF"

            if [ ! -s "$LINK_CAPTURE" ]; then
                echo "[dominator-build] ERROR: final link command was not captured for $BIN_NAME-$BUG_NAME" >&2
                exit 1
            fi

            dump_link_capture "$LINK_CAPTURE" "$LINK_CAPTURE_TXT"

            local BCFILE=""
            BCFILE="$(find_precodegen_bc "$1" "$BIN_NAME" || true)"
            echo "$BCFILE" > "$TMP_DIR/bcfile.txt"

            if [ -z "$BCFILE" ] || [ ! -f "$BCFILE" ]; then
                echo "[dominator-build] ERROR: clean precodegen.bc not found for $BIN_NAME-$BUG_NAME" >&2
                exit 1
            fi

            cp "$BCFILE" "$TMP_DIR/module.bc"
            llvm-dis-12 "$TMP_DIR/module.bc" -o "$TMP_DIR/module.ll"

            # Dominator 분석과 계측이 같은 bitcode를 사용한다는 것을 검증한다.
            sha256sum "$TMP_DIR/module.bc" > "$TMP_DIR/module.bc.sha256"

            ###################################################################
            # 3. SVF wpa 실행
            ###################################################################
            require_cmd wpa
            mkdir -p "$TMP_DIR/svf"

            (
                cd "$TMP_DIR/svf"
                wpa -ander -dump-icfg -dump-callgraph "$TMP_DIR/module.bc" \
                    > "$TMP_DIR/svf_wpa.log" 2>&1
            ) || {
                echo "[dominator-build] ERROR: SVF wpa failed" >&2
                cat "$TMP_DIR/svf_wpa.log" >&2
                exit 1
            }

            ###################################################################
            # 4. normalize_svf_icfg.py 실행
            # module.ll 또는 bitcode에서 ICFG 입력 데이터(nodes, intra edges, call edges, return edges, call-return mapping φ) 를 생성하도록 변경
            ###################################################################
            echo "[dominator-build] ===== PHASE 4: normalize_svf START =====" >&2

            python3 "$DOM_SCRIPT_DIR/normalize_svf_icfg.py" \
                --svf-dir "$TMP_DIR/svf" \
                --module-bc "$TMP_DIR/module.bc" \
                --module-ll "$TMP_DIR/module.ll" \
                --bbnames "$TMP_DIR/BBnames.txt" \
                --bbcalls "$TMP_DIR/BBcalls.txt" \
                --targets "$TMP_DIR/BBtargets.txt" \
                --outdir "$TMP_DIR" \
                > "$TMP_DIR/normalize_svf_icfg.log" 2>&1

            echo "[dominator-build] ===== PHASE 4: normalize_svf DONE =====" >&2

            ###################################################################
            # 5. DeepType SMLTA 분석
            #    Phase 5/6 patched kanalyzer writes machine-readable targets.
            ###################################################################
            echo "[dominator-build] ===== PHASE 5: deepType SMLTA analysis START =====" >&2
            local DEEPTYPE_BIN="/opt/DeepType/build/lib/kanalyzer"

            if [ ! -x "$DEEPTYPE_BIN" ]; then
                echo "[dominator-build] ERROR: DeepType kanalyzer not found: $DEEPTYPE_BIN" >&2
                exit 1
            fi

            "$DEEPTYPE_BIN" \
                -targets-out="$TMP_DIR/deeptype_targets.tsv" \
                "$TMP_DIR/module.bc" \
                > "$TMP_DIR/deeptype.log" 2>&1 || {
                    echo "[dominator-build] ERROR: DeepType SMLTA analysis failed" >&2
                    cat "$TMP_DIR/deeptype.log" >&2 || true
                    exit 1
                }

            if [ ! -f "$TMP_DIR/deeptype_targets.tsv" ]; then
                echo "[dominator-build] ERROR: DeepType output not found: $TMP_DIR/deeptype_targets.tsv" >&2
                exit 1
            fi

            echo "[dominator-build] ===== PHASE 5: deepType SMLTA analysis DONE =====" >&2

            ###################################################################
            # 6. DeepType callsite <-> SVF callsite_id mapping
            #
            # Stable key:
            #   caller_func + src_file + src_line + src_col + call_ordinal
            ###################################################################
            echo "[dominator-build] ===== PHASE 6: deepType mapping START =====" >&2

            python3 "$DEEPTYPE_SCRIPT_DIR/map_smlta_callsites.py" \
                --icfg-callsites "$TMP_DIR/icfg_callsites.tsv" \
                --deeptype-targets "$TMP_DIR/deeptype_targets.tsv" \
                --out "$TMP_DIR/smlta_callsite_map.tsv" \
                --unmatched-out "$TMP_DIR/smlta_unmatched_targets.tsv" \
                --summary-out "$TMP_DIR/smlta_callsite_map_summary.txt" \
                > "$TMP_DIR/map_smlta_callsites.log" 2>&1 || {
                    echo "[dominator-build] ERROR: SMLTA callsite mapping failed" >&2
                    cat "$TMP_DIR/map_smlta_callsites.log" >&2 || true
                    exit 1
                }

            if [ ! -f "$TMP_DIR/smlta_callsite_map.tsv" ]; then
                echo "[dominator-build] ERROR: SMLTA callsite map not found" >&2
                exit 1
            fi

            echo "[dominator-build] ===== PHASE 6: deepType mapping DONE =====" >&2

            ###################################################################
            # 7. Phase 7: SMLTA target set으로 normalized ICFG 보정
            #
            # 원본 "$TMP_DIR/icfg_*.tsv"는 유지하고,
            # "$TMP_DIR/icfg_smlta"에 별도 refined ICFG를 생성한다.
            ###################################################################
            echo "[dominator-build] ===== PHASE 7: refine_icfg_smlta START =====" >&2
            local SMLTA_ICFG_DIR="$TMP_DIR/icfg_smlta"

            python3 "$DEEPTYPE_SCRIPT_DIR/refine_icfg_smlta.py" \
                --icfg-dir "$TMP_DIR" \
                --smlta-map "$TMP_DIR/smlta_callsite_map.tsv" \
                --outdir "$SMLTA_ICFG_DIR" \
                --diff-out "$TMP_DIR/smlta_refine_diff.tsv" \
                --summary-out "$TMP_DIR/smlta_refine_summary.txt" \
                > "$TMP_DIR/refine_icfg_smlta.log" 2>&1 || {
                    echo "[dominator-build] ERROR: SMLTA ICFG refinement failed" >&2
                    cat "$TMP_DIR/refine_icfg_smlta.log" >&2 || true
                    exit 1
                }

            for refined_file in \
                icfg_nodes.tsv \
                icfg_edges.tsv \
                icfg_call_edges.tsv \
                icfg_return_edges.tsv \
                icfg_phi.tsv \
                icfg_callsites.tsv \
                icfg_functions.tsv; do
                if [ ! -f "$SMLTA_ICFG_DIR/$refined_file" ]; then
                    echo "[dominator-build] ERROR: refined ICFG file missing: $SMLTA_ICFG_DIR/$refined_file" >&2
                    exit 1
                fi
            done
            echo "[dominator-build] ===== PHASE 7: refine_icfg_smlta  DONE =====" >&2

            # ###################################################################
            # # 8. Phase 8: refined ICFG 검증
            # ###################################################################
            # echo "[dominator-build] ===== PHASE 8: validate refined ICFG START =====" >&2

            # python3 "$DEEPTYPE_SCRIPT_DIR/validate_smlta_icfg.py" \
            #     --original-icfg-dir "$TMP_DIR" \
            #     --refined-icfg-dir "$SMLTA_ICFG_DIR" \
            #     --smlta-map "$TMP_DIR/smlta_callsite_map.tsv" \
            #     --unmatched "$TMP_DIR/smlta_unmatched_targets.tsv" \
            #     --report "$TMP_DIR/smlta_icfg_validation.txt" \
            #     --details "$TMP_DIR/smlta_icfg_validation.tsv" \
            #     > "$TMP_DIR/validate_smlta_icfg.log" 2>&1 || {
            #         echo "[dominator-build] ERROR: SMLTA ICFG validation failed" >&2
            #         cat "$TMP_DIR/validate_smlta_icfg.log" >&2 || true
            #         if [ -f "$TMP_DIR/smlta_icfg_validation.txt" ]; then
            #             cat "$TMP_DIR/smlta_icfg_validation.txt" >&2 || true
            #         fi
            #         exit 1
            #     }

            # echo "[dominator-build] ===== PHASE 8: validate refined ICFG  DONE =====" >&2


            ###################################################################
            # 9. extract_dominator.py 실행 - ICFG 기반 dominator 추출
            ###################################################################
            echo "[dominator-build] ===== PHASE 9: extract_dominator START =====" >&2

            : > "$TMP_DIR/dominator_nodes.txt"
            : > "$TMP_DIR/extract_dominator.log"

            local TARGET_LINE
            TARGET_LINE="$(grep -v '^[[:space:]]*$' "$TMP_DIR/BBtargets.txt" \
                | grep -v '^[[:space:]]*#' \
                | head -n 1 \
                | xargs)"

            if [ -z "$TARGET_LINE" ]; then
                echo "[dominator-build] ERROR: target line is empty" >&2
                echo "[dominator-build] BBtargets.txt:" >&2
                cat "$TMP_DIR/BBtargets.txt" >&2 || true
                exit 1
            fi

            echo "[dominator-build] extract dominators for target=$TARGET_LINE" >&2
            echo "[dominator-build] ICFG dir=$SMLTA_ICFG_DIR" >&2
            echo "[dominator-build] module.ll=$TMP_DIR/module.ll" >&2

            python3 "$DOM_SCRIPT_DIR/extract_dominator.py" \
                --icfg-dir "$SMLTA_ICFG_DIR" \
                --module-ll "$TMP_DIR/module.ll" \
                --target "$TARGET_LINE" \
                > "$TMP_DIR/dominator_nodes.txt" \
                2> "$TMP_DIR/extract_dominator.log" || {
                    rc=$?

                    echo >&2
                    echo "[dominator-build] ================================================" >&2
                    echo "[dominator-build] ERROR: PHASE 9 extract_dominator failed" >&2
                    echo "[dominator-build] exit code: $rc" >&2
                    echo "[dominator-build] target: $TARGET_LINE" >&2
                    echo "[dominator-build] ================================================" >&2

                    echo >&2
                    echo "[dominator-build] ---- extract_dominator.log (stderr) ----" >&2
                    if [ -s "$TMP_DIR/extract_dominator.log" ]; then
                        cat "$TMP_DIR/extract_dominator.log" >&2
                    else
                        echo "[dominator-build] <empty>" >&2
                    fi

                    echo >&2
                    echo "[dominator-build] ---- dominator_nodes.txt (stdout) ----" >&2
                    if [ -s "$TMP_DIR/dominator_nodes.txt" ]; then
                        cat "$TMP_DIR/dominator_nodes.txt" >&2
                    else
                        echo "[dominator-build] <empty>" >&2
                    fi

                    echo >&2
                    echo "[dominator-build] ================================================" >&2
                    exit "$rc"
                }

            echo "[dominator-build] ===== PHASE 9: extract_dominator DONE =====" >&2

            ###################################################################
            # 10. make_dominator.py 실행
            ###################################################################
            python3 "$DOM_SCRIPT_DIR/make_dominator.py" \
                "$TMP_DIR/dominator_nodes.txt" \
                "$TMP_DIR/dominator_map.tsv" \
                > "$TMP_DIR/make_dominator.log" 2>&1

            local DOM_MAP="$TMP_DIR/dominator_map.tsv"
            local DOM_NUM
            DOM_NUM="$(count_dominators "$DOM_MAP")"

            if [ "$DOM_NUM" -le 0 ]; then
                echo "[dominator-build] ERROR: empty dominator map: $DOM_MAP" >&2
                exit 1
            fi

            ###################################################################
            # 11. 동일한 whole-program module.bc에 Dominator pass 적용
            ###################################################################
            echo "[dominator-build] ===== PHASE 11: same-BC dominator instrumentation START =====" >&2

            (
                cd "$TMP_DIR"
                sha256sum -c module.bc.sha256
            ) > "$TMP_DIR/module_bc_verify.log" 2>&1 || {
                echo "[dominator-build] ERROR: module.bc changed after dominator analysis" >&2
                cat "$TMP_DIR/module_bc_verify.log" >&2 || true
                exit 1
            }

            local PASS_SO="/fuzzer/Dominator/libDominatorCoveragePass.so"
            local DOM_BC="$TMP_DIR/module.dominator.bc"

            if [ ! -f "$PASS_SO" ]; then
                echo "[dominator-build] ERROR: Dominator pass not found: $PASS_SO" >&2
                exit 1
            fi

            # Requires the updated DominatorCoveragePass.cpp exact-module mode.
            opt-12 \
                -enable-new-pm=0 \
                -load "$PASS_SO" \
                -dominator-cov \
                -dominator-map="$DOM_MAP" \
                -dominator-exact-module \
                "$TMP_DIR/module.bc" \
                -o "$DOM_BC" \
                > "$TMP_DIR/dominator_instrument.log" 2>&1 || {
                    echo "[dominator-build] ERROR: same-BC dominator instrumentation failed" >&2
                    cat "$TMP_DIR/dominator_instrument.log" >&2 || true
                    exit 1
                }

            if [ ! -s "$DOM_BC" ]; then
                echo "[dominator-build] ERROR: instrumented bitcode not generated: $DOM_BC" >&2
                exit 1
            fi

            ###################################################################
            # 12. 모든 manifest entry가 exact BB로 1:1 매칭됐는지 검증
            ###################################################################
            echo "[dominator-build] ===== PHASE 12: exact-match validation START =====" >&2

            local MANIFEST_COUNT
            MANIFEST_COUNT="$(awk 'NF {count++} END {print count + 0}' "$DOM_MAP")"

            local EXACT_MATCHED_UNIQUE
            EXACT_MATCHED_UNIQUE="$(
                awk '
                    /\[dominator-pass\] match:/ && /method=exact-bb/ {
                        if (match($0, / id=[0-9]+/)) {
                            id = substr($0, RSTART + 4, RLENGTH - 4)
                            seen[id] = 1
                        }
                    }
                    END {
                        count = 0
                        for (id in seen) count++
                        print count + 0
                    }
                ' "$TMP_DIR/dominator_instrument.log"
            )"

            local UNMATCHED_EXACT=$((MANIFEST_COUNT - EXACT_MATCHED_UNIQUE))

            {
                echo "manifest_dominators: $MANIFEST_COUNT"
                echo "exact_bb_matched_unique_dominators: $EXACT_MATCHED_UNIQUE"
                echo "exact_bb_unmatched_dominators: $UNMATCHED_EXACT"
            } > "$TMP_DIR/dominator_same_bc_summary.txt"

            if [ "$EXACT_MATCHED_UNIQUE" -ne "$MANIFEST_COUNT" ]; then
                echo "[dominator-build] ERROR: exact same-BC dominator matching is not 100%" >&2
                echo "[dominator-build] manifest=$MANIFEST_COUNT exact_matched=$EXACT_MATCHED_UNIQUE" >&2
                cat "$TMP_DIR/dominator_instrument.log" >&2 || true
                exit 1
            fi

            echo "[dominator-build] exact same-BC match: $EXACT_MATCHED_UNIQUE/$MANIFEST_COUNT" >&2
            echo "[dominator-build] ===== PHASE 12: exact-match validation DONE =====" >&2

            ###################################################################
            # 13. Dominator runtime compile + instrumented BC code generation
            ###################################################################
            echo "[dominator-build] ===== PHASE 13: code generation START =====" >&2

            local RUNTIME_SRC="/fuzzer/Dominator/dominator_runtime.c"
            local RUNTIME_OBJ="$TMP_DIR/dominator_runtime.o"
            local DOM_OBJ="$TMP_DIR/module.dominator.o"

            if [ ! -f "$RUNTIME_SRC" ]; then
                echo "[dominator-build] ERROR: runtime source not found: $RUNTIME_SRC" >&2
                exit 1
            fi

            clang-12 -O2 -c \
                -DDOMINATOR_NUM="$DOM_NUM" \
                "$RUNTIME_SRC" \
                -o "$RUNTIME_OBJ"

            "$LLVM_LLC" \
                -filetype=obj \
                "$DOM_BC" \
                -o "$DOM_OBJ" \
                > "$TMP_DIR/llc_dominator.log" 2>&1 || {
                    echo "[dominator-build] ERROR: llc failed for instrumented module" >&2
                    cat "$TMP_DIR/llc_dominator.log" >&2 || true
                    exit 1
                }

            if [ ! -s "$DOM_OBJ" ]; then
                echo "[dominator-build] ERROR: native instrumented object not generated: $DOM_OBJ" >&2
                exit 1
            fi

            echo "[dominator-build] ===== PHASE 13: code generation DONE =====" >&2

            ###################################################################
            # 14. Source 재컴파일 없이 기존 final link만 replay
            ###################################################################
            echo "[dominator-build] ===== PHASE 14: final relink START =====" >&2
            local RELINK_BIN=""
            local FINAL_BIN="/benchmark/RUNDIR-$1/$BIN_NAME"

            case "$1" in
                libming*)
                    RELINK_BIN="/benchmark/RUNDIR-$1/BUILD/util/$LINK_BIN_NAME"
                    ;;
                binutils*)
                    RELINK_BIN="/benchmark/RUNDIR-$1/$1/binutils/$LINK_BIN_NAME"
                    ;;
                *)
                    echo "[dominator-build] ERROR: unsupported project for relink binary: $1" >&2
                    exit 1
                    ;;
            esac

            echo "[dominator-build] captured final link:" >&2
            cat "$LINK_CAPTURE_TXT" >&2

            relink_from_capture \
                "$LINK_CAPTURE" \
                "$DOM_OBJ" \
                "$RUNTIME_OBJ" \
                > "$TMP_DIR/relink_dominator.log" 2>&1 || {
                    echo "[dominator-build] ERROR: final relink failed" >&2
                    cat "$TMP_DIR/relink_dominator.log" >&2 || true
                    exit 1
                }
            
            
            rm -rf "$FINAL_BIN"
            cp -f "$RELINK_BIN" "$FINAL_BIN" 


            echo "[dominator-build] ===== PHASE 14: final relink DONE =====" >&2

            ###################################################################
            # 15. DCFuzz에서 공통 measurement binary로 사용할 결과 복사
            ###################################################################
            copy_build_result "$1" "$BIN_NAME" "$BUG_NAME" "Dominator"

            ###################################################################
            # 16. 분석/계측 결과 저장
            ###################################################################
            local INFO_RUN="/info/dominator_new/run_${BIN_NAME}-${BUG_NAME}"
            local INFO_TMP="/info/dominator_new/temp_${BIN_NAME}-${BUG_NAME}"

            cp -r "/benchmark/RUNDIR-$1" "$INFO_RUN"
            cp -r "$TMP_DIR" "$INFO_TMP"

            rm -rf "$TMP_DIR"
            rm -rf "/benchmark/RUNDIR-$1"
        done
    done
}

export DOM_SCRIPT_DIR="/benchmark/script"
export DEEPTYPE_SCRIPT_DIR="/benchmark/deeptype"

require_cmd llvm-dis-12
require_cmd opt-12
require_cmd clang-12
require_cmd python3
require_cmd sha256sum

export LLVM_LLC="/usr/lib/llvm-12/bin/llc"
export LLVM_BCANALYZER="/usr/lib/llvm-12/bin/llvm-bcanalyzer"
export LLVM_AR="/usr/lib/llvm-12/bin/llvm-ar"

for llvm_tool in "$LLVM_LLC" "$LLVM_BCANALYZER" "$LLVM_AR"; do
    if [ ! -x "$llvm_tool" ]; then
        echo "[dominator-build] ERROR: required LLVM tool not found: $llvm_tool" >&2
        exit 1
    fi
done

for script in normalize_svf_icfg.py extract_dominator.py make_dominator.py; do
    if [ ! -f "$DOM_SCRIPT_DIR/$script" ]; then
        echo "[dominator-build] ERROR: missing script: $DOM_SCRIPT_DIR/$script" >&2
        exit 1
    fi
done

mkdir -p /benchmark/bin/Dominator
mkdir -p /info/dominator_new

# build_with_Dominator "libming-4.7" \
#     "objdump 2017-8392 2017-8396 2017-8397 2017-8398"

# build_with_Dominator "libming-4.7" \
#     "swftophp 2016-9827 2016-9829 2016-9831 2017-9988 2017-11728 2017-11729"
# build_with_Dominator "libming-4.8" \
#     "swftophp 2018-7868 2018-8807 2018-8962 2018-11225 2018-11226 2020-6628 2018-20427 2019-12982"
# build_with_Dominator "libming-4.8.1" \
#     "swftophp 2019-9114"
# build_with_Dominator "binutils-2.26" \
#     "cxxfilt 2016-4489 2016-4490 2016-4491 2016-4492 2016-6131"
build_with_Dominator "binutils-2.28" \
   "objdump 2017-8392 2017-8396" #2017-8397 2017-8398"
# build_with_Dominator "binutils-2.29" \
#     "nm 2017-14940"


wait
