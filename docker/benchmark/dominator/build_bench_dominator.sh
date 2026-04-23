#!/bin/bash
. $(dirname $0)/build_bench_common.sh

# arg1 : Target project
# arg2~: Fuzzing targets
function build_with_Dominator() {
    for TARG in "${@:2}"; do
        str_array=($TARG)
        BIN_NAME=${str_array[0]}

        cd /benchmark
        
        # 1st build: AFLGo instrumentation build for BBnames/BBcalls/bitcode extraction
        CC="/fuzzer/AFLGo/afl-clang-fast"
        CXX="/fuzzer/AFLGo/afl-clang-fast++"

        # 2nd build: plain clang build for dominator-only custom LLVM pass
        # CC_DOM="clang"
        # CXX_DOM="clang++"

        TMP_DIR=/benchmark/temp_$1

        for BUG_NAME in "${str_array[@]:1}"; do
            ### Draw CFG and CG with BBtargets
	        #TMP_DIR=/benchmark/temp_$1-$BUG_NAME

            mkdir -p $TMP_DIR
            
            cp /benchmark/target/line/$BIN_NAME/$BUG_NAME $TMP_DIR/BBtargets.txt

            ADDITIONAL="-g -targets=$TMP_DIR/BBtargets.txt \
                        -outdir=$TMP_DIR -flto -fuse-ld=gold \
                        -Wl,-plugin-opt=save-temps"
                                    
            build_target $1 $CC $CXX "$ADDITIONAL"

            cp "$TMP_DIR/BBnames.txt" "$TMP_DIR/BBnames.raw.txt"

            cat "$TMP_DIR/BBnames.txt" | rev | cut -d: -f2- | rev | sort | uniq > "$TMP_DIR/BBnames2.txt" \
            && mv "$TMP_DIR/BBnames2.txt" "$TMP_DIR/BBnames.txt"

            cp "$TMP_DIR/BBcalls.txt" "$TMP_DIR/BBcalls.raw.txt"
            cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt \
            && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt

            ### find LLVM bitcode
            # find /benchmark/RUNDIR-$1 -name "*.bc" | sort > "$TMP_DIR/bc.list"

            ### find whole-program bc 
            BCFILE=""
            if find /benchmark/RUNDIR-$1 -name "*${BIN_NAME}*precodegen.bc" | grep -q .; then
                BCFILE="$(find /benchmark/RUNDIR-$1 -name "*${BIN_NAME}*precodegen.bc" | head -n 1)"
            elif find /benchmark/RUNDIR-$1 -name "*precodegen.bc" | grep -q .; then
                BCFILE="$(find /benchmark/RUNDIR-$1 -name "*precodegen.bc" -printf '%s %p\n' \
                    | sort -nr | head -n 1 | cut -d' ' -f2-)"
            fi
            echo "$BCFILE" > "$TMP_DIR/bcfile.txt"

            ### IR dump
            llvm-dis-12 "$BCFILE" -o "$TMP_DIR/module.ll" || true

            ### dominator tree dump
            opt-12 -enable-new-pm=0 -analyze -domtree "$BCFILE" > "$TMP_DIR/domtree.txt" 2>&1 || \
            opt-12 -passes='print<domtree>' -disable-output "$BCFILE" > "$TMP_DIR/domtree.txt" 2>&1

            # ### extract dominator nodes for the target site(file:line)
            # TARGET_LINE="$(head -n 1 "$TMP_DIR/BBtargets.txt")"
            # TARGET_FUNC="$(head -n 1 "$TMP_DIR/Ftargets.txt")"

            # # python3 $DOM_SCRIPT_DIR/extract_dominator.py \
            # #     "$TMP_DIR/module.ll" \
            # #     "$TMP_DIR/domtree.txt" \
            # #     "$TARGET_LINE" \
            # #     --function "$TARGET_FUNC" \
            # #     --strict \
            # #     > "$TMP_DIR/dominator_nodes.txt" 2>&1
            # python3 $DOM_SCRIPT_DIR/extract_dominator.py \
            #     "$TMP_DIR/module.ll" \
            #     "$TMP_DIR/domtree.txt" \
            #     "$TARGET_LINE" \
            #     --function "$TARGET_FUNC" \
            #     > "$TMP_DIR/dominator_nodes.txt" 2>&1

            # ### Build with dominator nodes, with dominator coverage, with dominator counts

            # # make dominator manifest (ID <-> function,bb)
            # python3 $DOM_SCRIPT_DIR/make_dominator.py \
            #     "$TMP_DIR/dominator_nodes.txt" \
            #     "$TMP_DIR/dominator_manifest.tsv"
            
            # DOM_N=$(wc -l < "$TMP_DIR/dominator_manifest.tsv")

            # clang -O2 -DDOMINATOR_NUM=$DOM_N \
            #     -c /fuzzer/Dominator/dominator_runtime.c \
            #     -o $TMP_DIR/dominator_runtime.o

            # ar rcs $TMP_DIR/libdominator_rt.a $TMP_DIR/dominator_runtime.o

            
            # # optional: human-readable BB id map
            # awk -F'\t' '{print "ID=" $1 ",FUNC=" $2 ",BB=" $3}' \
            #     "$TMP_DIR/dominator_manifest.tsv" \
            #     > "$TMP_DIR/dominator_id_map.txt"

            # # instrument the SAME BCFILE used for dominator extraction
            # opt-12 -enable-new-pm=0 \
            #     -load /fuzzer/Dominator/libDominatorCoveragePass.so \
            #     -dominator-cov \
            #     -dominator-map="$TMP_DIR/dominator_manifest.tsv" \
            #     "$BCFILE" \
            #     -o "$TMP_DIR/instrumented.bc" 2> "$TMP_DIR/opt.instrument.log"

            # # # verify instrumentation
            # llvm-dis-12 "$TMP_DIR/instrumented.bc" -o "$TMP_DIR/instrumented.ll" || true

            # # final link: replace with the original executable link line
            # # swftophp target program
            # clang -fuse-ld=gold \
            #     "$TMP_DIR/instrumented.bc" \
            #     "$TMP_DIR/libdominator_rt.a" \
            #     -lpng -lm -lz \
            #     -o "/benchmark/bin/Dominator/${BIN_NAME}-${BUG_NAME}"
            # # # nm target program
            # # clang -fuse-ld=gold \
            # #     "$TMP_DIR/instrumented.bc" \
            # #     /benchmark/RUNDIR-$1/binutils-2.26/binutils/bucomm.o /benchmark/RUNDIR-$1/binutils-2.26/binutils/version.o /benchmark/RUNDIR-$1/binutils-2.26/binutils/filemode.o \
            # #     "$TMP_DIR/libdominator_rt.a" \
            # #     /benchmark/RUNDIR-$1/binutils-2.26/bfd/.libs/libbfd.a \
            # #     /benchmark/RUNDIR-$1/binutils-2.26/libiberty/libiberty.a \
            # #     -ldl -lz \
            # #     -o "/benchmark/bin/Dominator/${BIN_NAME}-${BUG_NAME}"

            # # clang -fuse-ld=gold \
            # #     "$TMP_DIR/instrumented.bc" \
            # #     /benchmark/RUNDIR-$1/binutils-2.26/binutils/bucomm.o /benchmark/RUNDIR-$1/binutils-2.26/binutils/version.o /benchmark/RUNDIR-$1/binutils-2.26/binutils/filemode.o \
            # #     "$TMP_DIR/libdominator_rt.a" \
            # #     /benchmark/RUNDIR-$1/binutils-2.26/bfd/.libs/libbfd.a \
            # #     -L /benchmark/RUNDIR-$1/binutils-2.26/zlib \
            # #     -lz \
            # #     /benchmark/RUNDIR-$1/binutils-2.26/libiberty/libiberty.a \
            # #     -ldl \
            # #     -o "/benchmark/bin/Dominator/${BIN_NAME}-${BUG_NAME}"

            ### save build outputs
            mv /benchmark/RUNDIR-$1 /info/dominator/run_$BIN_NAME-$BUG_NAME
            mv $TMP_DIR /info/dominator/temp_$BIN_NAME-$BUG_NAME

            ### Cleanup
            rm -rf $TMP_DIR
            rm -rf /benchmark/RUNDIR-$1

        done
    done
}

export DOM_PASS_SO="/fuzzer/Dominator/libDominatorCoveragePass.so"
# export DOM_SCRIPT_DIR="/fuzzer/Dominator/script"
export DOM_SCRIPT_DIR="/benchmark/script"


# Build with native only
mkdir -p /benchmark/bin/Dominator
build_with_Dominator "libming-4.7" \
    "swftophp 2016-9827 2016-9829 2017-11728" 
# build_with_Dominator "libming-4.7" \
#     "swftophp 2016-9827 2016-9829 2016-9831 2017-9988 2017-11728 2017-11729" 
# build_with_Dominator "libming-4.8" \
#     "swftophp 2018-7868 2018-8807 2018-8962 2018-11225 2018-11226 2020-6628 2018-20427 2019-12982" 
# build_with_Dominator "libming-4.8.1" \
#     "swftophp 2019-9114" 
# wait

# build_with_Dominator "binutils-2.26" \
#     "cxxfilt 2016-4489 2016-4490 2016-4491 2016-4492 2016-6131" 
# build_with_Dominator "binutils-2.28" \
#     "objdump 2017-8392 2017-8396 2017-8397 2017-8398" 
# build_with_Dominator "binutils-2.29" "nm 2017-14940" 

wait