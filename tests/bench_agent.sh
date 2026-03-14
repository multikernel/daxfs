#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# DAXFS AI Agent Speculative Branching Benchmark
#
# Measures branch creation, parallel workload execution, commit/merge,
# and sibling invalidation — the core operations for AI agent speculative
# execution where N agents fork from shared filesystem state.
#
# Usage: sudo ./tests/bench_agent.sh [options]
#
# Options:
#   -n NUM    Maximum agent count (powers of 2 up to this, default: 64)
#   -d NUM    Maximum nesting depth (default: 8)
#   -w SIZE   Workload: small, medium, large (default: medium)
#   -r NUM    Repetitions per measurement (default: 3)
#   -o DIR    Output directory (default: ./bench_results)
#   -v        Verbose output
#
# Requirements:
#   - Root privileges
#   - daxfs.ko module built
#   - mkdaxfs, daxfs-branch, daxfs-inspect tools built
#   - /dev/dma_heap/system available (or modify HEAP_DEV)

set -e

# ── Configuration ────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
MKDAXFS="$PROJECT_DIR/tools/mkdaxfs"
DAXFS_BRANCH="$PROJECT_DIR/tools/daxfs-branch"
DAXFS_INSPECT="$PROJECT_DIR/tools/daxfs-inspect"
MODULE="$PROJECT_DIR/daxfs/daxfs.ko"
HEAP_DEV="/dev/dma_heap/system"

# Defaults
MAX_AGENTS=64
MAX_DEPTH=8
WORKLOAD="medium"
REPS=3
OUTPUT_DIR="./bench_results"
VERBOSE=0

# Runtime state
TEST_DIR=""
MODULE_LOADED_BY_US=0

# ── Output helpers ───────────────────────────────────────────────────

log() { echo -e "$@"; }

log_verbose() {
    if [ "$VERBOSE" -eq 1 ]; then
        echo -e "  [v] $*" >&2
    fi
}

die() {
    echo "ERROR: $1" >&2
    exit 1
}

# ── Timing ───────────────────────────────────────────────────────────

# Returns nanosecond wall-clock timestamp
now_ns() {
    date +%s%N
}

# Converts nanosecond delta to microseconds
ns_to_us() {
    echo $(( $1 / 1000 ))
}

# ── TSV output ───────────────────────────────────────────────────────

TSV_FILE=""

tsv_init() {
    TSV_FILE="$OUTPUT_DIR/agents.tsv"
    mkdir -p "$OUTPUT_DIR"
    printf "experiment\tparameter\titeration\toperation\tlatency_us\tops_count\tdelta_bytes\tnotes\n" \
        > "$TSV_FILE"
}

tsv_row() {
    # args: experiment parameter iteration operation latency_us ops_count delta_bytes notes
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" \
        >> "$TSV_FILE"
}

# ── Source tree generation ───────────────────────────────────────────

# Generates a C-like source file of approximately the given size (bytes)
generate_c_file() {
    local path="$1" target_size="$2"
    local written=0
    {
        echo "/* Auto-generated source file */"
        echo "#include <stdio.h>"
        echo "#include <stdlib.h>"
        echo ""
        local func_num=0
        while [ "$written" -lt "$target_size" ]; do
            cat <<CFUNC

static int compute_${func_num}(int x, int y) {
    int result = 0;
    for (int i = 0; i < x; i++) {
        result += (i * y) ^ (i >> 2);
        if (result > 1000000) result %= 997;
    }
    return result;
}
CFUNC
            func_num=$((func_num + 1))
            written=$(( written + 180 ))
        done
    } > "$path"
}

# Generates a header file of approximately the given size
generate_h_file() {
    local path="$1" target_size="$2"
    local guard
    guard=$(basename "$path" | tr '[:lower:].' '[:upper:]_')
    {
        echo "#ifndef ${guard}"
        echo "#define ${guard}"
        echo ""
        local decl_num=0 written=0
        while [ "$written" -lt "$target_size" ]; do
            echo "int compute_${decl_num}(int x, int y);"
            echo "struct data_${decl_num} { int field_a; long field_b; char name[64]; };"
            echo ""
            decl_num=$((decl_num + 1))
            written=$((written + 100))
        done
        echo "#endif /* ${guard} */"
    } > "$path"
}

# Creates ~30-file realistic C project in the given directory
create_source_tree() {
    local dir="$1"
    mkdir -p "$dir/src" "$dir/include" "$dir/tests" "$dir/docs" "$dir/config"

    # src/module_{1..10}.c  — 2-8KB each
    for i in $(seq 1 10); do
        local size=$(( 2048 + (i * 600) ))
        generate_c_file "$dir/src/module_${i}.c" "$size"
    done

    # include/module_{1..5}.h  — 512-1536 bytes each
    for i in $(seq 1 5); do
        local size=$(( 512 + (i * 200) ))
        generate_h_file "$dir/include/module_${i}.h" "$size"
    done

    # tests/test_{1..3}.c  — 1-2KB each
    for i in $(seq 1 3); do
        generate_c_file "$dir/tests/test_${i}.c" $(( 1024 + i * 300 ))
    done

    # docs/ARCHITECTURE.md
    {
        echo "# Architecture"
        echo ""
        echo "This project consists of 10 modules that implement a data processing pipeline."
        echo "Each module handles a specific stage of the computation."
        echo ""
        for i in $(seq 1 10); do
            echo "## Module $i"
            echo ""
            echo "Handles stage $i of the pipeline. Dependencies: module_$((i > 1 ? i-1 : 1))."
            echo ""
        done
    } > "$dir/docs/ARCHITECTURE.md"

    # config/settings.json
    cat > "$dir/config/settings.json" <<'JSON'
{
    "version": "1.0.0",
    "modules": 10,
    "optimization_level": 2,
    "debug": false,
    "paths": {
        "input": "/data/input",
        "output": "/data/output",
        "cache": "/tmp/cache"
    }
}
JSON

    # Makefile
    {
        echo "CC = gcc"
        echo "CFLAGS = -Wall -Wextra -O2 -Iinclude"
        echo "SRCS = \$(wildcard src/*.c)"
        echo "OBJS = \$(SRCS:.c=.o)"
        echo ""
        echo "all: libproject.a"
        echo ""
        echo "libproject.a: \$(OBJS)"
        echo "	ar rcs \$@ \$^"
        echo ""
        echo "clean:"
        echo "	rm -f src/*.o libproject.a"
    } > "$dir/Makefile"

    # README.md
    {
        echo "# Project"
        echo ""
        echo "A data processing pipeline with 10 modules."
        echo ""
        echo "## Build"
        echo ""
        echo '```'
        echo "make"
        echo '```'
    } > "$dir/README.md"
}

# ── Workload ─────────────────────────────────────────────────────────

# Runs the AI agent workload on a mounted branch.
# Simulates an AI agent editing a code project.
#
# Args: $1 = mount path, $2 = workload size (small|medium|large)
# Returns: number of operations performed (via global WORKLOAD_OPS)
WORKLOAD_OPS=0

run_agent_workload() {
    local mnt="$1" size="$2"
    local n_reads n_creates n_modifies n_mkdirs n_deletes n_renames
    local ops=0

    case "$size" in
        small)   n_reads=5;  n_creates=3;  n_modifies=1; n_mkdirs=1; n_deletes=0; n_renames=0 ;;
        medium)  n_reads=10; n_creates=10; n_modifies=5; n_mkdirs=3; n_deletes=2; n_renames=1 ;;
        large)   n_reads=20; n_creates=50; n_modifies=20; n_mkdirs=10; n_deletes=5; n_renames=3 ;;
        *)       die "Unknown workload size: $size" ;;
    esac

    # Reads — cat existing files
    for i in $(seq 1 "$n_reads"); do
        local idx=$(( (i % 10) + 1 ))
        cat "$mnt/src/module_${idx}.c" > /dev/null 2>&1 || true
        ops=$((ops + 1))
    done

    # Mkdirs — create new directories
    for i in $(seq 1 "$n_mkdirs"); do
        mkdir -p "$mnt/agent_dir_${i}/sub" 2>/dev/null || true
        ops=$((ops + 1))
    done

    # Creates — write new files (1-4KB of generated C content)
    for i in $(seq 1 "$n_creates"); do
        local fsize=$(( 1024 + (i * 73 % 3072) ))
        generate_c_file "$mnt/agent_file_${i}.c" "$fsize"
        ops=$((ops + 1))
    done

    # Modifies — overwrite existing source files
    for i in $(seq 1 "$n_modifies"); do
        local idx=$(( (i % 10) + 1 ))
        local fsize=$(( 2048 + (i * 500) ))
        generate_c_file "$mnt/src/module_${idx}.c" "$fsize"
        ops=$((ops + 1))
    done

    # Deletes — remove some created files
    for i in $(seq 1 "$n_deletes"); do
        rm -f "$mnt/agent_file_${i}.c" 2>/dev/null || true
        ops=$((ops + 1))
    done

    # Renames — rename some files
    for i in $(seq 1 "$n_renames"); do
        local src_idx=$(( n_creates - i + 1 ))
        if [ -f "$mnt/agent_file_${src_idx}.c" ]; then
            mv "$mnt/agent_file_${src_idx}.c" "$mnt/agent_file_${src_idx}_renamed.c" 2>/dev/null || true
        fi
        ops=$((ops + 1))
    done

    WORKLOAD_OPS=$ops
}

# ── Environment setup / teardown ─────────────────────────────────────

# Creates a fresh daxfs image and mounts it as main.
# Args: $1 = source dir, $2 = image size, $3 = delta size, $4 = main mount point
setup_fresh_image() {
    local src="$1" img_size="$2" delta_size="$3" mnt_main="$4"
    mkdir -p "$mnt_main"

    "$MKDAXFS" -d "$src" -H "$HEAP_DEV" -s "$img_size" -m "$mnt_main" -b -D "$delta_size" \
        || die "mkdaxfs failed (size=$img_size delta=$delta_size)"
}

# Unmount all mounts under TEST_DIR, unload module if we loaded it
full_cleanup() {
    log_verbose "Full cleanup..."

    # Unmount everything under TEST_DIR
    if [ -n "$TEST_DIR" ] && [ -d "$TEST_DIR" ]; then
        # Find and unmount in reverse order
        local mnts
        mnts=$(mount | grep "$TEST_DIR" | awk '{print $3}' | sort -r) || true
        for m in $mnts; do
            umount "$m" 2>/dev/null || umount -l "$m" 2>/dev/null || true
        done
        rm -rf "$TEST_DIR"
    fi

    if [ "$MODULE_LOADED_BY_US" = "1" ]; then
        rmmod daxfs 2>/dev/null || true
    fi
}

# Quick teardown: just unmount everything under TEST_DIR (between experiments)
teardown_mounts() {
    if [ -n "$TEST_DIR" ] && [ -d "$TEST_DIR" ]; then
        local mnts
        mnts=$(mount | grep "$TEST_DIR" | awk '{print $3}' | sort -r) || true
        for m in $mnts; do
            umount "$m" 2>/dev/null || umount -l "$m" 2>/dev/null || true
        done
    fi
}

check_prerequisites() {
    if [ "$(id -u)" -ne 0 ]; then
        die "Must run as root"
    fi
    for tool in "$MKDAXFS" "$DAXFS_BRANCH" "$DAXFS_INSPECT" "$MODULE"; do
        if [ ! -f "$tool" ]; then
            die "$(basename "$tool") not found at $tool — run 'make' first"
        fi
    done
    if [ ! -e "$HEAP_DEV" ]; then
        die "DMA heap not found at $HEAP_DEV"
    fi
}

load_module() {
    MODULE_LOADED_BY_US=0
    if ! lsmod | grep -q "^daxfs"; then
        log_verbose "Loading daxfs module..."
        insmod "$MODULE" || die "Failed to load module"
        MODULE_LOADED_BY_US=1
    fi
}

# ── Experiment 1: Agent Scalability ──────────────────────────────────

scale_agents() {
    log "Experiment 1: Agent Scalability (scale_agents)"

    local n=1
    while [ "$n" -le "$MAX_AGENTS" ]; do
        log "  N=$n agents..."
        local iter
        for iter in $(seq 1 "$REPS"); do
            log_verbose "Iteration $iter/$REPS for N=$n"

            # Fresh image: delta = (N+2)*1M + 64M headroom
            local delta_mb=$(( (n + 2) + 64 ))
            local img_mb=$(( delta_mb + 128 ))
            local mnt_main="$TEST_DIR/main"
            local source="$TEST_DIR/source"

            teardown_mounts
            rm -rf "$TEST_DIR/main" "$TEST_DIR/branch_"*
            mkdir -p "$mnt_main"

            setup_fresh_image "$source" "${img_mb}M" "${delta_mb}M" "$mnt_main"

            # ── Branch creation (sequential, branch_lock serializes) ──
            local t0 t1 branch_total_us=0
            local branch_mnts=()
            for b in $(seq 1 "$n"); do
                local bmnt="$TEST_DIR/branch_${b}"
                mkdir -p "$bmnt"
                branch_mnts+=("$bmnt")

                t0=$(now_ns)
                "$DAXFS_BRANCH" create "agent_${b}" -m "$bmnt" -p main \
                    || die "Failed to create branch agent_${b}"
                t1=$(now_ns)

                local lat_us
                lat_us=$(ns_to_us $((t1 - t0)))
                branch_total_us=$((branch_total_us + lat_us))
                log_verbose "  branch agent_${b} created in ${lat_us} us"
            done
            tsv_row "scale_agents" "$n" "$iter" "branch_create_total" "$branch_total_us" "$n" "" ""
            tsv_row "scale_agents" "$n" "$iter" "branch_create_avg" "$((branch_total_us / n))" "$n" "" ""

            # ── Parallel workload on all branches ──
            t0=$(now_ns)
            local pids=()
            for b in $(seq 1 "$n"); do
                (
                    run_agent_workload "${branch_mnts[$((b-1))]}" "$WORKLOAD"
                ) &
                pids+=($!)
            done
            # Wait for all
            local workload_fail=0
            for pid in "${pids[@]}"; do
                wait "$pid" 2>/dev/null || workload_fail=$((workload_fail + 1))
            done
            t1=$(now_ns)
            local workload_us
            workload_us=$(ns_to_us $((t1 - t0)))
            tsv_row "scale_agents" "$n" "$iter" "parallel_workload" "$workload_us" "$n" "" \
                "fails=$workload_fail"

            # ── Commit winner (branch 1) ──
            t0=$(now_ns)
            "$DAXFS_BRANCH" commit -m "${branch_mnts[0]}" \
                || die "Commit failed for agent_1"
            t1=$(now_ns)
            local commit_us
            commit_us=$(ns_to_us $((t1 - t0)))
            tsv_row "scale_agents" "$n" "$iter" "commit" "$commit_us" "1" "" ""

            # ── Detect ESTALE on sibling (branch 2, if it exists) ──
            if [ "$n" -ge 2 ]; then
                t0=$(now_ns)
                # Any operation on an invalidated sibling should fail with ESTALE
                local estale_rc=0
                cat "${branch_mnts[1]}/src/module_1.c" > /dev/null 2>&1 || estale_rc=$?
                t1=$(now_ns)
                local estale_us
                estale_us=$(ns_to_us $((t1 - t0)))
                tsv_row "scale_agents" "$n" "$iter" "estale_detect" "$estale_us" "1" "" \
                    "rc=$estale_rc"
            fi

            # ── End-to-end cleanup time ──
            t0=$(now_ns)
            teardown_mounts
            t1=$(now_ns)
            local cleanup_us
            cleanup_us=$(ns_to_us $((t1 - t0)))
            tsv_row "scale_agents" "$n" "$iter" "cleanup" "$cleanup_us" "$n" "" ""

        done
        n=$((n * 2))
    done
}

# ── Experiment 2: Nesting Depth ──────────────────────────────────────

scale_depth() {
    log "Experiment 2: Nesting Depth (scale_depth)"

    local d=1
    while [ "$d" -le "$MAX_DEPTH" ]; do
        log "  D=$d levels..."
        local iter
        for iter in $(seq 1 "$REPS"); do
            log_verbose "Iteration $iter/$REPS for D=$d"

            # Fresh image: need d+2 branches worth of delta + headroom
            local delta_mb=$(( (d + 4) + 64 ))
            local img_mb=$(( delta_mb + 128 ))
            local mnt_main="$TEST_DIR/main"
            local source="$TEST_DIR/source"

            teardown_mounts
            rm -rf "$TEST_DIR/main" "$TEST_DIR/level_"*
            mkdir -p "$mnt_main"

            setup_fresh_image "$source" "${img_mb}M" "${delta_mb}M" "$mnt_main"

            # ── Create chain: main → L1 → L2 → ... → LD ──
            local t0 t1
            t0=$(now_ns)
            local parent="main"
            local level_mnts=()
            for lvl in $(seq 1 "$d"); do
                local lmnt="$TEST_DIR/level_${lvl}"
                mkdir -p "$lmnt"
                level_mnts+=("$lmnt")
                "$DAXFS_BRANCH" create "level_${lvl}" -m "$lmnt" -p "$parent" \
                    || die "Failed to create level_${lvl}"
                parent="level_${lvl}"
            done
            t1=$(now_ns)
            local chain_us
            chain_us=$(ns_to_us $((t1 - t0)))
            tsv_row "scale_depth" "$d" "$iter" "chain_create" "$chain_us" "$d" "" ""

            # ── Workload at deepest level ──
            local deepest="${level_mnts[$((d-1))]}"
            t0=$(now_ns)
            run_agent_workload "$deepest" "$WORKLOAD"
            t1=$(now_ns)
            local work_us
            work_us=$(ns_to_us $((t1 - t0)))
            tsv_row "scale_depth" "$d" "$iter" "workload" "$work_us" "$WORKLOAD_OPS" "" ""

            # ── Get delta bytes before commit ──
            local delta_bytes=""
            delta_bytes=$("$DAXFS_INSPECT" info -m "$deepest" -b "level_${d}" 2>/dev/null \
                | grep -i "delta.*used" | head -1 | grep -oP '\d+' | tail -1) || true
            log_verbose "  delta_bytes at level_${d}: $delta_bytes"

            # ── Commit from deepest level (walks up D levels) ──
            t0=$(now_ns)
            "$DAXFS_BRANCH" commit -m "$deepest" \
                || die "Commit from depth $d failed"
            t1=$(now_ns)
            local commit_us
            commit_us=$(ns_to_us $((t1 - t0)))
            tsv_row "scale_depth" "$d" "$iter" "commit" "$commit_us" "$d" "$delta_bytes" ""

            teardown_mounts
        done
        d=$((d * 2))
    done
}

# ── Experiment 3: Commit Cost vs Delta Size ──────────────────────────

commit_cost() {
    log "Experiment 3: Commit Cost vs Delta Size (commit_cost)"

    local ops_counts="10 50 100 500 1000 5000"

    for ops_target in $ops_counts; do
        log "  ops=$ops_target..."
        local iter
        for iter in $(seq 1 "$REPS"); do
            log_verbose "Iteration $iter/$REPS for ops=$ops_target"

            # Fresh image with generous delta
            local delta_mb=128
            local img_mb=256
            local mnt_main="$TEST_DIR/main"
            local bmnt="$TEST_DIR/branch_cost"
            local source="$TEST_DIR/source"

            teardown_mounts
            rm -rf "$TEST_DIR/main" "$TEST_DIR/branch_cost"
            mkdir -p "$mnt_main" "$bmnt"

            setup_fresh_image "$source" "${img_mb}M" "${delta_mb}M" "$mnt_main"

            "$DAXFS_BRANCH" create "cost_test" -m "$bmnt" -p main \
                || die "Failed to create cost_test branch"

            # ── Run exactly ops_target write operations ──
            local t0 t1
            t0=$(now_ns)
            local op=0
            while [ "$op" -lt "$ops_target" ]; do
                local fsize=$(( 1024 + (op * 37 % 3072) ))
                generate_c_file "$bmnt/cost_file_${op}.c" "$fsize"
                op=$((op + 1))
            done
            t1=$(now_ns)
            local workload_us
            workload_us=$(ns_to_us $((t1 - t0)))
            tsv_row "commit_cost" "$ops_target" "$iter" "workload" "$workload_us" "$ops_target" "" ""

            # ── Read delta_bytes via daxfs-inspect ──
            local delta_bytes=""
            delta_bytes=$("$DAXFS_INSPECT" info -m "$bmnt" -b "cost_test" 2>/dev/null \
                | grep -i "delta.*used" | head -1 | grep -oP '\d+' | tail -1) || true
            log_verbose "  delta_bytes: $delta_bytes"

            # ── Commit and time it ──
            t0=$(now_ns)
            "$DAXFS_BRANCH" commit -m "$bmnt" \
                || die "Commit failed for ops=$ops_target"
            t1=$(now_ns)
            local commit_us
            commit_us=$(ns_to_us $((t1 - t0)))
            tsv_row "commit_cost" "$ops_target" "$iter" "commit" "$commit_us" "$ops_target" \
                "$delta_bytes" ""

            teardown_mounts
        done
    done
}

# ── Experiment 4: tmpfs Baseline ─────────────────────────────────────

baseline_tmpfs() {
    log "Experiment 4: tmpfs Baseline (baseline_tmpfs)"

    local source="$TEST_DIR/source"
    local tmpfs_base="$TEST_DIR/tmpfs_base"

    local n=1
    while [ "$n" -le "$MAX_AGENTS" ]; do
        log "  N=$n agents (tmpfs)..."
        local iter
        for iter in $(seq 1 "$REPS"); do
            log_verbose "Iteration $iter/$REPS for N=$n"

            # Fresh tmpfs base
            rm -rf "$tmpfs_base"
            mkdir -p "$tmpfs_base"
            mount -t tmpfs -o size=512M tmpfs "$tmpfs_base"
            cp -a "$source"/. "$tmpfs_base/"

            # ── "Branch" creation = cp -a (O(source_size)) ──
            local t0 t1 branch_total_us=0
            local branch_dirs=()
            for b in $(seq 1 "$n"); do
                local bdir="$TEST_DIR/tmpfs_branch_${b}"
                t0=$(now_ns)
                cp -a "$tmpfs_base" "$bdir"
                t1=$(now_ns)
                branch_dirs+=("$bdir")
                local lat_us
                lat_us=$(ns_to_us $((t1 - t0)))
                branch_total_us=$((branch_total_us + lat_us))
            done
            tsv_row "baseline_tmpfs" "$n" "$iter" "branch_create_total" "$branch_total_us" "$n" "" ""
            tsv_row "baseline_tmpfs" "$n" "$iter" "branch_create_avg" "$((branch_total_us / n))" "$n" "" ""

            # ── Parallel workload ──
            t0=$(now_ns)
            local pids=()
            for b in $(seq 1 "$n"); do
                (
                    run_agent_workload "${branch_dirs[$((b-1))]}" "$WORKLOAD"
                ) &
                pids+=($!)
            done
            for pid in "${pids[@]}"; do
                wait "$pid" 2>/dev/null || true
            done
            t1=$(now_ns)
            local workload_us
            workload_us=$(ns_to_us $((t1 - t0)))
            tsv_row "baseline_tmpfs" "$n" "$iter" "parallel_workload" "$workload_us" "$n" "" ""

            # ── "Commit" = cp -a winner back to base ──
            t0=$(now_ns)
            rm -rf "$tmpfs_base"
            cp -a "${branch_dirs[0]}" "$tmpfs_base"
            t1=$(now_ns)
            local commit_us
            commit_us=$(ns_to_us $((t1 - t0)))
            tsv_row "baseline_tmpfs" "$n" "$iter" "commit" "$commit_us" "1" "" ""

            # ── Cleanup branches ──
            t0=$(now_ns)
            for bdir in "${branch_dirs[@]}"; do
                rm -rf "$bdir"
            done
            umount "$tmpfs_base" 2>/dev/null || true
            rm -rf "$tmpfs_base"
            t1=$(now_ns)
            local cleanup_us
            cleanup_us=$(ns_to_us $((t1 - t0)))
            tsv_row "baseline_tmpfs" "$n" "$iter" "cleanup" "$cleanup_us" "$n" "" ""
        done
        n=$((n * 2))
    done
}

# ── Experiment 5: OverlayFS Baseline ─────────────────────────────────

baseline_overlayfs() {
    log "Experiment 5: OverlayFS Baseline (baseline_overlayfs)"

    local source="$TEST_DIR/source"

    local n=1
    while [ "$n" -le "$MAX_AGENTS" ]; do
        log "  N=$n agents (overlayfs)..."
        local iter
        for iter in $(seq 1 "$REPS"); do
            log_verbose "Iteration $iter/$REPS for N=$n"

            # ── "Branch" creation = overlayfs mount with upper/work dirs ──
            local t0 t1 branch_total_us=0
            local overlay_mnts=()
            for b in $(seq 1 "$n"); do
                local upper="$TEST_DIR/ovl_upper_${b}"
                local work="$TEST_DIR/ovl_work_${b}"
                local merged="$TEST_DIR/ovl_merged_${b}"
                mkdir -p "$upper" "$work" "$merged"

                t0=$(now_ns)
                mount -t overlay overlay \
                    -o "lowerdir=${source},upperdir=${upper},workdir=${work}" \
                    "$merged" 2>/dev/null \
                    || { log_verbose "overlayfs mount failed for branch $b"; break; }
                t1=$(now_ns)
                overlay_mnts+=("$merged")
                local lat_us
                lat_us=$(ns_to_us $((t1 - t0)))
                branch_total_us=$((branch_total_us + lat_us))
            done
            local actual_n=${#overlay_mnts[@]}
            if [ "$actual_n" -eq 0 ]; then
                log_verbose "No overlayfs mounts succeeded, skipping"
                continue
            fi
            tsv_row "baseline_overlayfs" "$n" "$iter" "branch_create_total" "$branch_total_us" \
                "$actual_n" "" ""
            tsv_row "baseline_overlayfs" "$n" "$iter" "branch_create_avg" \
                "$((branch_total_us / actual_n))" "$actual_n" "" ""

            # ── Parallel workload ──
            t0=$(now_ns)
            local pids=()
            for b in $(seq 1 "$actual_n"); do
                (
                    run_agent_workload "${overlay_mnts[$((b-1))]}" "$WORKLOAD"
                ) &
                pids+=($!)
            done
            for pid in "${pids[@]}"; do
                wait "$pid" 2>/dev/null || true
            done
            t1=$(now_ns)
            local workload_us
            workload_us=$(ns_to_us $((t1 - t0)))
            tsv_row "baseline_overlayfs" "$n" "$iter" "parallel_workload" "$workload_us" \
                "$actual_n" "" ""

            # ── "Commit" = copy upper dir to source ──
            t0=$(now_ns)
            cp -a "$TEST_DIR/ovl_upper_1"/. "$source/" 2>/dev/null || true
            t1=$(now_ns)
            local commit_us
            commit_us=$(ns_to_us $((t1 - t0)))
            tsv_row "baseline_overlayfs" "$n" "$iter" "commit" "$commit_us" "1" "" ""

            # ── Cleanup ──
            t0=$(now_ns)
            for b in $(seq 1 "$actual_n"); do
                umount "$TEST_DIR/ovl_merged_${b}" 2>/dev/null || true
            done
            rm -rf "$TEST_DIR"/ovl_upper_* "$TEST_DIR"/ovl_work_* "$TEST_DIR"/ovl_merged_*
            t1=$(now_ns)
            local cleanup_us
            cleanup_us=$(ns_to_us $((t1 - t0)))
            tsv_row "baseline_overlayfs" "$n" "$iter" "cleanup" "$cleanup_us" "$actual_n" "" \
                "no_nesting"
        done
        n=$((n * 2))
    done
}

# ── Argument parsing ─────────────────────────────────────────────────

parse_args() {
    while getopts "n:d:w:r:o:v" opt; do
        case $opt in
            n) MAX_AGENTS="$OPTARG" ;;
            d) MAX_DEPTH="$OPTARG" ;;
            w) WORKLOAD="$OPTARG" ;;
            r) REPS="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            v) VERBOSE=1 ;;
            *) echo "Usage: $0 [-n agents] [-d depth] [-w small|medium|large] [-r reps] [-o dir] [-v]"
               exit 1 ;;
        esac
    done

    # Validate workload
    case "$WORKLOAD" in
        small|medium|large) ;;
        *) die "Invalid workload: $WORKLOAD (must be small, medium, or large)" ;;
    esac

    # Validate max_agents is reasonable
    if [ "$MAX_AGENTS" -lt 1 ] || [ "$MAX_AGENTS" -gt 256 ]; then
        die "Agent count must be between 1 and 256"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    log "DAXFS AI Agent Speculative Branching Benchmark"
    log "==============================================="
    log "  max_agents=$MAX_AGENTS  max_depth=$MAX_DEPTH  workload=$WORKLOAD"
    log "  reps=$REPS  output=$OUTPUT_DIR"
    log ""

    check_prerequisites
    load_module
    tsv_init

    # Create persistent test directory and source tree
    TEST_DIR=$(mktemp -d /tmp/daxfs_bench.XXXXXX)
    trap full_cleanup EXIT

    local source="$TEST_DIR/source"
    log "Generating source tree..."
    create_source_tree "$source"
    local src_files
    src_files=$(find "$source" -type f | wc -l)
    log "  $src_files files in source tree"
    log ""

    # ── Run experiments ──

    scale_agents
    log ""

    scale_depth
    log ""

    commit_cost
    log ""

    baseline_tmpfs
    log ""

    baseline_overlayfs
    log ""

    # ── Summary ──
    local rows
    rows=$(tail -n +2 "$TSV_FILE" | wc -l)
    log "==============================================="
    log "Benchmark complete: $rows data points"
    log "Results: $TSV_FILE"
}

main "$@"
