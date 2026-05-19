#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# DAXFS overlay and page cache tests
#
# Usage: sudo ./test_overlay.sh [options]
#
# Options:
#   -k    Keep test environment on failure (for debugging)
#   -v    Verbose output
#
# Requirements:
#   - Root privileges
#   - daxfs.ko module built
#   - mkdaxfs tool built
#   - /dev/dma_heap/system available (or modify HEAP_DEV)

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
MKDAXFS="$PROJECT_DIR/tools/mkdaxfs"
DAXFS_INSPECT="$PROJECT_DIR/tools/daxfs-inspect"
MODULE="$PROJECT_DIR/daxfs/daxfs.ko"
HEAP_DEV="/dev/dma_heap/system"
IMAGE_SIZE="128M"

# Test directories
TEST_DIR=""
MNT=""
SOURCE_DIR=""
BACKING_FILE=""

# Options
KEEP_ON_FAIL=0
VERBOSE=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

#
# Helper functions
#

log() {
    echo -e "$@"
}

log_verbose() {
    if [ "$VERBOSE" -eq 1 ]; then
        echo -e "$@"
    fi
}

pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    log "${GREEN}PASS${NC}: $1"
}

fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    log "${RED}FAIL${NC}: $1"
    if [ -n "$2" ]; then
        log "      $2"
    fi
}

skip() {
    log "${YELLOW}SKIP${NC}: $1"
}

run_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
    log_verbose "Running: $1"
}

cleanup() {
    log_verbose "Cleaning up..."

    if [ -n "$MNT" ] && mountpoint -q "$MNT" 2>/dev/null; then
        umount "$MNT" 2>/dev/null || true
    fi

    if [ -n "$TEST_DIR" ] && [ -d "$TEST_DIR" ]; then
        rm -rf "$TEST_DIR"
    fi

    if [ "$MODULE_LOADED_BY_US" = "1" ]; then
        rmmod daxfs 2>/dev/null || true
    fi
}

die() {
    log "${RED}ERROR${NC}: $1"
    if [ "$KEEP_ON_FAIL" -eq 0 ]; then
        cleanup
    else
        log "Keeping test environment for debugging"
        log "  Test dir: $TEST_DIR"
    fi
    exit 1
}

ensure_unmounted() {
    if [ -n "$MNT" ] && mountpoint -q "$MNT" 2>/dev/null; then
        umount "$MNT" 2>/dev/null || true
    fi
}

setup() {
    if [ "$(id -u)" -ne 0 ]; then
        die "Must run as root"
    fi

    if [ ! -f "$MKDAXFS" ]; then
        die "mkdaxfs not found at $MKDAXFS - run 'make' first"
    fi

    if [ ! -f "$MODULE" ]; then
        die "daxfs.ko not found at $MODULE - run 'make' first"
    fi

    if [ ! -e "$HEAP_DEV" ]; then
        die "DMA heap not found at $HEAP_DEV"
    fi

    # Load module if needed
    MODULE_LOADED_BY_US=0
    if ! lsmod | grep -q "^daxfs"; then
        log_verbose "Loading daxfs module..."
        insmod "$MODULE" || die "Failed to load module"
        MODULE_LOADED_BY_US=1
    fi

    # Create test directories
    TEST_DIR=$(mktemp -d /tmp/daxfs_test.XXXXXX)
    SOURCE_DIR="$TEST_DIR/source"
    MNT="$TEST_DIR/mnt"
    BACKING_FILE="$TEST_DIR/backing.img"

    mkdir -p "$SOURCE_DIR" "$MNT"

    # Create source content
    echo "Hello from base image" > "$SOURCE_DIR/hello.txt"
    echo "Original content" > "$SOURCE_DIR/modify_me.txt"
    mkdir -p "$SOURCE_DIR/subdir"
    echo "File in subdir" > "$SOURCE_DIR/subdir/nested.txt"
    ln -s hello.txt "$SOURCE_DIR/link_to_hello"

    log_verbose "Test directory: $TEST_DIR"
}

#
# Static image tests (read-only, no overlay)
#

test_static_create() {
    run_test "Static image creation and mount"

    "$MKDAXFS" -d "$SOURCE_DIR" -H "$HEAP_DEV" -s "$IMAGE_SIZE" -m "$MNT" \
        || { fail "Static create" "mkdaxfs failed"; return; }

    if ! mountpoint -q "$MNT"; then
        fail "Static create" "Mount point not active"
        return
    fi

    pass "Static image creation and mount"
}

test_static_read() {
    run_test "Read files from static image"

    local content
    content=$(cat "$MNT/hello.txt") || {
        fail "Static read" "Failed to read hello.txt"
        return
    }
    if [ "$content" != "Hello from base image" ]; then
        fail "Static read" "hello.txt content mismatch: '$content'"
        return
    fi

    content=$(cat "$MNT/subdir/nested.txt") || {
        fail "Static read" "Failed to read nested file"
        return
    }
    if [ "$content" != "File in subdir" ]; then
        fail "Static read" "nested.txt content mismatch"
        return
    fi

    # Symlink
    if [ ! -L "$MNT/link_to_hello" ]; then
        fail "Static read" "Symlink not visible"
        return
    fi
    local target
    target=$(readlink "$MNT/link_to_hello")
    if [ "$target" != "hello.txt" ]; then
        fail "Static read" "Symlink target mismatch: '$target'"
        return
    fi

    pass "Read files from static image"
}

test_static_readonly() {
    run_test "Static image is read-only"

    if echo "test" > "$MNT/newfile.txt" 2>/dev/null; then
        fail "Static readonly" "Write should have failed"
        return
    fi

    if echo "modified" > "$MNT/hello.txt" 2>/dev/null; then
        fail "Static readonly" "Modify should have failed"
        return
    fi

    if mkdir "$MNT/newdir" 2>/dev/null; then
        fail "Static readonly" "mkdir should have failed"
        return
    fi

    pass "Static image is read-only"
}

#
# Split mode tests (overlay + pcache)
#

setup_split() {
    log ""
    log "DAXFS Split Mode Tests (overlay + page cache)"
    log "=============================================="

    ensure_unmounted

    # Create richer source content for split/pcache testing
    SPLIT_SOURCE="$TEST_DIR/split_source"
    mkdir -p "$SPLIT_SOURCE"

    echo "Hello from split base" > "$SPLIT_SOURCE/hello.txt"
    echo "Original split content" > "$SPLIT_SOURCE/modify_me.txt"
    mkdir -p "$SPLIT_SOURCE/subdir"
    echo "Nested split file" > "$SPLIT_SOURCE/subdir/nested.txt"
    ln -s hello.txt "$SPLIT_SOURCE/link_to_hello"

    # Create a multi-page file (at least 4 pages on any page size)
    PAGE_SIZE=$(getconf PAGESIZE)
    dd if=/dev/urandom of="$SPLIT_SOURCE/largefile.bin" bs="$PAGE_SIZE" count=4 2>/dev/null
    LARGE_CKSUM=$(md5sum "$SPLIT_SOURCE/largefile.bin" | awk '{print $1}')

    # Create more files to exercise multiple cache slots
    for i in $(seq 1 10); do
        echo "File number $i with some padding data to fill it out" > "$SPLIT_SOURCE/file_$i.txt"
    done

    log_verbose "Split source: $SPLIT_SOURCE"
    log_verbose "Backing file: $BACKING_FILE"
}

test_split_create() {
    run_test "Split-mode image creation"

    "$MKDAXFS" -d "$SPLIT_SOURCE" -H "$HEAP_DEV" -s "$IMAGE_SIZE" \
        -m "$MNT" -o "$BACKING_FILE" \
        || { fail "Split create" "mkdaxfs failed"; return; }

    if [ ! -f "$BACKING_FILE" ]; then
        fail "Split create" "Backing file not created"
        return
    fi

    local backing_size=$(stat -c %s "$BACKING_FILE")
    if [ "$backing_size" -eq 0 ]; then
        fail "Split create" "Backing file is empty"
        return
    fi

    if ! mountpoint -q "$MNT"; then
        fail "Split create" "Mount point not active"
        return
    fi

    log_verbose "  Backing file size: $backing_size bytes"
    pass "Split-mode image creation"
}

test_split_read_files() {
    run_test "Read files through page cache"

    local content
    content=$(cat "$MNT/hello.txt") || {
        fail "Split read" "Failed to read hello.txt"
        return
    }
    if [ "$content" != "Hello from split base" ]; then
        fail "Split read" "hello.txt content mismatch: '$content'"
        return
    fi

    content=$(cat "$MNT/subdir/nested.txt") || {
        fail "Split read" "Failed to read nested file"
        return
    }
    if [ "$content" != "Nested split file" ]; then
        fail "Split read" "nested.txt content mismatch"
        return
    fi

    # Read numbered files
    for i in $(seq 1 10); do
        content=$(cat "$MNT/file_$i.txt") || {
            fail "Split read" "Failed to read file_$i.txt"
            return
        }
        if [ "$content" != "File number $i with some padding data to fill it out" ]; then
            fail "Split read" "file_$i.txt content mismatch"
            return
        fi
    done

    pass "Read files through page cache"
}

test_split_large_file() {
    run_test "Multi-page file through page cache"

    local mount_cksum
    mount_cksum=$(md5sum "$MNT/largefile.bin" | awk '{print $1}') || {
        fail "Split large file" "Failed to read largefile.bin"
        return
    }

    if [ "$mount_cksum" != "$LARGE_CKSUM" ]; then
        fail "Split large file" "Checksum mismatch: $mount_cksum != $LARGE_CKSUM"
        return
    fi

    pass "Multi-page file through page cache"
}

test_split_symlink() {
    run_test "Symlinks work with page cache"

    if [ ! -L "$MNT/link_to_hello" ]; then
        fail "Split symlink" "Symlink not visible"
        return
    fi

    local target
    target=$(readlink "$MNT/link_to_hello")
    if [ "$target" != "hello.txt" ]; then
        fail "Split symlink" "Symlink target mismatch: '$target'"
        return
    fi

    local content
    content=$(cat "$MNT/link_to_hello") || {
        fail "Split symlink" "Failed to read through symlink"
        return
    }
    if [ "$content" != "Hello from split base" ]; then
        fail "Split symlink" "Content through symlink mismatch"
        return
    fi

    pass "Symlinks work with page cache"
}

#
# Overlay write tests (split mode has overlay auto-enabled)
#

test_overlay_create_file() {
    run_test "Create new file via overlay"

    echo "New overlay file" > "$MNT/overlay_file.txt" \
        || { fail "Overlay create file" "Failed to create file"; return; }

    local content
    content=$(cat "$MNT/overlay_file.txt") || {
        fail "Overlay create file" "Failed to read new file"
        return
    }
    if [ "$content" != "New overlay file" ]; then
        fail "Overlay create file" "Content mismatch: '$content'"
        return
    fi

    pass "Create new file via overlay"
}

test_overlay_modify_file() {
    run_test "Modify existing file via overlay"

    echo "Modified via overlay" > "$MNT/modify_me.txt" \
        || { fail "Overlay modify" "Failed to modify file"; return; }

    local content
    content=$(cat "$MNT/modify_me.txt") || {
        fail "Overlay modify" "Failed to read modified file"
        return
    }
    if [ "$content" != "Modified via overlay" ]; then
        fail "Overlay modify" "Content mismatch: '$content'"
        return
    fi

    # Base image files should still be intact through other paths
    local base_content
    base_content=$(cat "$MNT/hello.txt") || {
        fail "Overlay modify" "Base file corrupted"
        return
    }
    if [ "$base_content" != "Hello from split base" ]; then
        fail "Overlay modify" "Base file content changed"
        return
    fi

    pass "Modify existing file via overlay"
}

test_overlay_mkdir() {
    run_test "mkdir via overlay"

    mkdir "$MNT/newdir" \
        || { fail "Overlay mkdir" "Failed to create directory"; return; }

    if [ ! -d "$MNT/newdir" ]; then
        fail "Overlay mkdir" "Directory not visible"
        return
    fi

    echo "file in new dir" > "$MNT/newdir/file.txt" \
        || { fail "Overlay mkdir" "Failed to create file in new dir"; return; }

    local content
    content=$(cat "$MNT/newdir/file.txt") || {
        fail "Overlay mkdir" "Failed to read file in new dir"
        return
    }
    if [ "$content" != "file in new dir" ]; then
        fail "Overlay mkdir" "File content mismatch"
        return
    fi

    pass "mkdir via overlay"
}

test_overlay_unlink() {
    run_test "unlink via overlay (tombstone)"

    rm "$MNT/subdir/nested.txt" \
        || { fail "Overlay unlink" "Failed to remove file"; return; }

    if [ -f "$MNT/subdir/nested.txt" ]; then
        fail "Overlay unlink" "File still visible after unlink"
        return
    fi

    pass "unlink via overlay (tombstone)"
}

test_overlay_rmdir() {
    run_test "rmdir via overlay"

    # subdir should be empty now (nested.txt was deleted)
    rmdir "$MNT/subdir" \
        || { fail "Overlay rmdir" "Failed to remove directory"; return; }

    if [ -d "$MNT/subdir" ]; then
        fail "Overlay rmdir" "Directory still visible after rmdir"
        return
    fi

    pass "rmdir via overlay"
}

test_overlay_symlink() {
    run_test "Create symlink via overlay"

    ln -s overlay_file.txt "$MNT/link_to_overlay" \
        || { fail "Overlay symlink" "Failed to create symlink"; return; }

    if [ ! -L "$MNT/link_to_overlay" ]; then
        fail "Overlay symlink" "Symlink not visible"
        return
    fi

    local content
    content=$(cat "$MNT/link_to_overlay") || {
        fail "Overlay symlink" "Failed to read through symlink"
        return
    }
    if [ "$content" != "New overlay file" ]; then
        fail "Overlay symlink" "Content through symlink mismatch"
        return
    fi

    pass "Create symlink via overlay"
}

test_overlay_rename() {
    run_test "Rename via overlay"

    mv "$MNT/overlay_file.txt" "$MNT/renamed_file.txt" \
        || { fail "Overlay rename" "Failed to rename file"; return; }

    if [ -f "$MNT/overlay_file.txt" ]; then
        fail "Overlay rename" "Old name still exists"
        return
    fi

    if [ ! -f "$MNT/renamed_file.txt" ]; then
        fail "Overlay rename" "New name doesn't exist"
        return
    fi

    local content
    content=$(cat "$MNT/renamed_file.txt") || {
        fail "Overlay rename" "Failed to read renamed file"
        return
    }
    if [ "$content" != "New overlay file" ]; then
        fail "Overlay rename" "Content changed after rename"
        return
    fi

    pass "Rename via overlay"
}

test_overlay_truncate() {
    run_test "Truncate via overlay"

    truncate -s 5 "$MNT/hello.txt" \
        || { fail "Overlay truncate" "Failed to truncate"; return; }

    local size=$(stat -c %s "$MNT/hello.txt")
    if [ "$size" -ne 5 ]; then
        fail "Overlay truncate" "Size is $size, expected 5"
        return
    fi

    pass "Truncate via overlay"
}

#
# Empty mode tests
#

setup_empty() {
    log ""
    log "DAXFS Empty Mode Tests"
    log "======================"

    ensure_unmounted
}

test_empty_create() {
    run_test "Empty-mode image creation"

    "$MKDAXFS" --empty -H "$HEAP_DEV" -s "$IMAGE_SIZE" -m "$MNT" \
        || { fail "Empty create" "mkdaxfs failed"; return; }

    if ! mountpoint -q "$MNT"; then
        fail "Empty create" "Mount point not active"
        return
    fi

    pass "Empty-mode image creation"
}

test_empty_write() {
    run_test "Write to empty filesystem"

    echo "First file" > "$MNT/first.txt" \
        || { fail "Empty write" "Failed to create first file"; return; }

    mkdir "$MNT/mydir" \
        || { fail "Empty write" "Failed to mkdir"; return; }

    echo "Nested file" > "$MNT/mydir/nested.txt" \
        || { fail "Empty write" "Failed to create nested file"; return; }

    local content
    content=$(cat "$MNT/first.txt") || {
        fail "Empty write" "Failed to read first.txt"
        return
    }
    if [ "$content" != "First file" ]; then
        fail "Empty write" "first.txt content mismatch"
        return
    fi

    content=$(cat "$MNT/mydir/nested.txt") || {
        fail "Empty write" "Failed to read nested file"
        return
    }
    if [ "$content" != "Nested file" ]; then
        fail "Empty write" "nested.txt content mismatch"
        return
    fi

    pass "Write to empty filesystem"
}

test_empty_readdir() {
    run_test "Readdir on empty-mode filesystem"

    local files
    files=$(ls "$MNT" 2>/dev/null) || {
        fail "Empty readdir" "ls failed"
        return
    }

    if ! echo "$files" | grep -q "first.txt"; then
        fail "Empty readdir" "first.txt not listed"
        return
    fi

    if ! echo "$files" | grep -q "mydir"; then
        fail "Empty readdir" "mydir not listed"
        return
    fi

    pass "Readdir on empty-mode filesystem"
}

#
# Inspect tests
#

setup_inspect() {
    log ""
    log "DAXFS Inspect Tests"
    log "==================="

    ensure_unmounted

    # Create a split-mode image for inspection
    "$MKDAXFS" -d "$SPLIT_SOURCE" -H "$HEAP_DEV" -s "$IMAGE_SIZE" \
        -m "$MNT" -o "$BACKING_FILE" \
        || die "Failed to create image for inspection"

    # Make some overlay writes so there's something to inspect
    echo "inspect test" > "$MNT/inspect_file.txt" 2>/dev/null || true
    mkdir "$MNT/inspect_dir" 2>/dev/null || true
}

test_inspect_status() {
    run_test "daxfs-inspect status"

    if [ ! -f "$DAXFS_INSPECT" ]; then
        skip "daxfs-inspect not built"
        return
    fi

    local output
    output=$("$DAXFS_INSPECT" status -m "$MNT" 2>&1) || {
        fail "Inspect status" "daxfs-inspect failed"
        return
    }

    # Should show format info
    if ! echo "$output" | grep -q "Magic:"; then
        fail "Inspect status" "No magic field in output"
        return
    fi

    if ! echo "$output" | grep -q "Version:"; then
        fail "Inspect status" "No version field in output"
        return
    fi

    # Should show overlay section
    if ! echo "$output" | grep -q "Overlay:"; then
        fail "Inspect status" "No overlay section"
        return
    fi

    # Should show page cache section
    if ! echo "$output" | grep -q "Page cache:"; then
        fail "Inspect status" "No page cache section"
        return
    fi

    # Should show slot states
    if ! echo "$output" | grep -q "Slot states:"; then
        fail "Inspect status" "No slot states"
        return
    fi

    log_verbose "  Status output:"
    if [ "$VERBOSE" -eq 1 ]; then
        echo "$output" | while read -r line; do
            log_verbose "    $line"
        done
    fi

    pass "daxfs-inspect status"
}

test_inspect_overlay() {
    run_test "daxfs-inspect overlay"

    if [ ! -f "$DAXFS_INSPECT" ]; then
        skip "daxfs-inspect not built"
        return
    fi

    local output
    output=$("$DAXFS_INSPECT" overlay -m "$MNT" 2>&1) || {
        fail "Inspect overlay" "daxfs-inspect overlay failed"
        return
    }

    # Should show header info
    if ! echo "$output" | grep -q "Bucket count:"; then
        fail "Inspect overlay" "No bucket count in output"
        return
    fi

    if ! echo "$output" | grep -q "Pool size:"; then
        fail "Inspect overlay" "No pool size in output"
        return
    fi

    if ! echo "$output" | grep -q "Pool usage:"; then
        fail "Inspect overlay" "No pool usage in output"
        return
    fi

    # Should show bucket utilization
    if ! echo "$output" | grep -q "Bucket utilization:"; then
        fail "Inspect overlay" "No bucket utilization section"
        return
    fi

    # Should show entry types
    if ! echo "$output" | grep -q "Entry types:"; then
        fail "Inspect overlay" "No entry types section"
        return
    fi

    log_verbose "  Overlay output:"
    if [ "$VERBOSE" -eq 1 ]; then
        echo "$output" | while read -r line; do
            log_verbose "    $line"
        done
    fi

    pass "daxfs-inspect overlay"
}

#
# Main
#

parse_args() {
    while getopts "kv" opt; do
        case $opt in
            k) KEEP_ON_FAIL=1 ;;
            v) VERBOSE=1 ;;
            *) echo "Usage: $0 [-k] [-v]"; exit 1 ;;
        esac
    done
}

main() {
    parse_args "$@"

    log "DAXFS Overlay & Page Cache Tests"
    log "================================"

    trap cleanup EXIT

    setup

    # Static image tests (read-only, no overlay)
    log ""
    log "Static Image Tests"
    log "=================="
    test_static_create
    test_static_read
    test_static_readonly

    # Split mode tests (overlay + pcache)
    setup_split
    test_split_create
    test_split_read_files
    test_split_large_file
    test_split_symlink

    # Overlay write tests (on split-mode mount)
    log ""
    log "Overlay Write Tests"
    log "==================="
    test_overlay_create_file
    test_overlay_modify_file
    test_overlay_mkdir
    test_overlay_unlink
    test_overlay_rmdir
    test_overlay_symlink
    test_overlay_rename
    test_overlay_truncate

    # Empty mode tests
    setup_empty
    test_empty_create
    test_empty_write
    test_empty_readdir

    # Inspect tests
    setup_inspect
    test_inspect_status
    test_inspect_overlay

    # Summary
    log ""
    log "================================"
    log "Tests run:    $TESTS_RUN"
    log "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    log "Tests failed: ${RED}$TESTS_FAILED${NC}"

    if [ "$TESTS_FAILED" -gt 0 ]; then
        exit 1
    fi
    exit 0
}

main "$@"
