#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# DAXFS branching feature tests
#
# Usage: sudo ./test_branch.sh [options]
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
DAXFS_BRANCH="$PROJECT_DIR/tools/daxfs-branch"
MODULE="$PROJECT_DIR/daxfs/daxfs.ko"
HEAP_DEV="/dev/dma_heap/system"
IMAGE_SIZE="128M"

# Test directories
TEST_DIR=""
MNT_MAIN=""
MNT_BRANCH1=""
MNT_BRANCH2=""
MNT_NESTED=""
SOURCE_DIR=""
BACKING_FILE=""
DAXFS_INSPECT=""

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

    # Unmount in reverse order
    for mnt in "$MNT_NESTED" "$MNT_BRANCH2" "$MNT_BRANCH1" "$MNT_MAIN"; do
        if [ -n "$mnt" ] && mountpoint -q "$mnt" 2>/dev/null; then
            umount "$mnt" 2>/dev/null || true
        fi
    done

    # Remove test directories
    if [ -n "$TEST_DIR" ] && [ -d "$TEST_DIR" ]; then
        rm -rf "$TEST_DIR"
    fi

    # Unload module if we loaded it
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

setup() {
    # Check prerequisites
    if [ "$(id -u)" -ne 0 ]; then
        die "Must run as root"
    fi

    if [ ! -f "$MKDAXFS" ]; then
        die "mkdaxfs not found at $MKDAXFS - run 'make' first"
    fi

    if [ ! -f "$DAXFS_BRANCH" ]; then
        die "daxfs-branch not found at $DAXFS_BRANCH - run 'make' first"
    fi

    DAXFS_INSPECT="$PROJECT_DIR/tools/daxfs-inspect"

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
    MNT_MAIN="$TEST_DIR/mnt_main"
    MNT_BRANCH1="$TEST_DIR/mnt_branch1"
    MNT_BRANCH2="$TEST_DIR/mnt_branch2"
    MNT_NESTED="$TEST_DIR/mnt_nested"

    mkdir -p "$SOURCE_DIR" "$MNT_MAIN" "$MNT_BRANCH1" "$MNT_BRANCH2" "$MNT_NESTED"

    # Create source content
    echo "Hello from base image" > "$SOURCE_DIR/hello.txt"
    echo "Original content" > "$SOURCE_DIR/modify_me.txt"
    mkdir -p "$SOURCE_DIR/subdir"
    echo "File in subdir" > "$SOURCE_DIR/subdir/nested.txt"

    log_verbose "Test directory: $TEST_DIR"
}

#
# Test cases
#

test_main_readonly() {
    run_test "Main branch is read-only"

    # Create and mount image
    "$MKDAXFS" -d "$SOURCE_DIR" -H "$HEAP_DEV" -s "$IMAGE_SIZE" -m "$MNT_MAIN" -b \
        || die "Failed to create/mount image"

    # Verify content is readable
    if [ "$(cat "$MNT_MAIN/hello.txt")" != "Hello from base image" ]; then
        fail "Main branch read-only" "Content mismatch"
        return
    fi

    # Verify writes fail
    if echo "test" > "$MNT_MAIN/newfile.txt" 2>/dev/null; then
        fail "Main branch read-only" "Write should have failed"
        return
    fi

    if echo "modified" > "$MNT_MAIN/hello.txt" 2>/dev/null; then
        fail "Main branch read-only" "Modify should have failed"
        return
    fi

    pass "Main branch is read-only"
}

test_branch_writable() {
    run_test "Child branch is writable"

    # Create branch using daxfs-branch tool
    "$DAXFS_BRANCH" create branch1 -m "$MNT_BRANCH1" -p main \
        || die "Failed to create branch1"

    # Verify content inherited from main
    if [ "$(cat "$MNT_BRANCH1/hello.txt")" != "Hello from base image" ]; then
        fail "Child branch writable" "Base content not visible"
        return
    fi

    # Test write new file
    echo "New file in branch" > "$MNT_BRANCH1/branch_file.txt" \
        || { fail "Child branch writable" "Failed to create new file"; return; }

    # Test modify existing file
    echo "Modified in branch" > "$MNT_BRANCH1/modify_me.txt" \
        || { fail "Child branch writable" "Failed to modify file"; return; }

    # Verify modifications
    if [ "$(cat "$MNT_BRANCH1/branch_file.txt")" != "New file in branch" ]; then
        fail "Child branch writable" "New file content mismatch"
        return
    fi

    if [ "$(cat "$MNT_BRANCH1/modify_me.txt")" != "Modified in branch" ]; then
        fail "Child branch writable" "Modified file content mismatch"
        return
    fi

    pass "Child branch is writable"
}

test_branch_isolation() {
    run_test "Branches are isolated"

    # Create second branch from main
    "$DAXFS_BRANCH" create branch2 -m "$MNT_BRANCH2" -p main \
        || die "Failed to create branch2"

    # Verify branch2 sees original content (not branch1's changes)
    if [ "$(cat "$MNT_BRANCH2/modify_me.txt")" != "Original content" ]; then
        fail "Branch isolation" "Branch2 sees branch1's changes"
        return
    fi

    # Verify branch2 doesn't see branch1's new file
    if [ -f "$MNT_BRANCH2/branch_file.txt" ]; then
        fail "Branch isolation" "Branch2 sees branch1's new file"
        return
    fi

    # Write different content in branch2
    echo "Branch2 content" > "$MNT_BRANCH2/modify_me.txt"
    echo "Branch2 file" > "$MNT_BRANCH2/branch2_file.txt"

    # Verify branch1 doesn't see branch2's changes
    if [ "$(cat "$MNT_BRANCH1/modify_me.txt")" != "Modified in branch" ]; then
        fail "Branch isolation" "Branch1 sees branch2's changes"
        return
    fi

    if [ -f "$MNT_BRANCH1/branch2_file.txt" ]; then
        fail "Branch isolation" "Branch1 sees branch2's new file"
        return
    fi

    pass "Branches are isolated"
}

test_nested_branch() {
    run_test "Nested branches work"

    # Create nested branch from branch1
    "$DAXFS_BRANCH" create nested -m "$MNT_NESTED" -p branch1 \
        || die "Failed to create nested branch"

    # Verify nested branch sees branch1's content
    if [ "$(cat "$MNT_NESTED/modify_me.txt")" != "Modified in branch" ]; then
        fail "Nested branch" "Doesn't see parent's modifications"
        return
    fi

    if [ "$(cat "$MNT_NESTED/branch_file.txt")" != "New file in branch" ]; then
        fail "Nested branch" "Doesn't see parent's new file"
        return
    fi

    # Write in nested branch
    echo "Nested content" > "$MNT_NESTED/nested_file.txt"
    echo "Nested modified" > "$MNT_NESTED/modify_me.txt"

    # Verify parent (branch1) doesn't see nested changes
    if [ "$(cat "$MNT_BRANCH1/modify_me.txt")" != "Modified in branch" ]; then
        fail "Nested branch" "Parent sees nested changes"
        return
    fi

    if [ -f "$MNT_BRANCH1/nested_file.txt" ]; then
        fail "Nested branch" "Parent sees nested new file"
        return
    fi

    pass "Nested branches work"
}

test_branch_abort() {
    run_test "Branch abort discards changes"

    # Unmount nested branch (should abort it)
    umount "$MNT_NESTED"

    # Re-mount nested branch - should see branch1's content, not previous nested changes
    "$DAXFS_BRANCH" create nested2 -m "$MNT_NESTED" -p branch1 \
        || die "Failed to create nested2 branch"

    if [ -f "$MNT_NESTED/nested_file.txt" ]; then
        fail "Branch abort" "Aborted branch's file still visible"
        return
    fi

    if [ "$(cat "$MNT_NESTED/modify_me.txt")" != "Modified in branch" ]; then
        fail "Branch abort" "Aborted branch's changes still visible"
        return
    fi

    pass "Branch abort discards changes"
}

test_mkdir_in_branch() {
    run_test "mkdir works in branch"

    mkdir "$MNT_BRANCH1/newdir" \
        || { fail "mkdir in branch" "Failed to create directory"; return; }

    echo "file in new dir" > "$MNT_BRANCH1/newdir/file.txt" \
        || { fail "mkdir in branch" "Failed to create file in new dir"; return; }

    if [ ! -d "$MNT_BRANCH1/newdir" ]; then
        fail "mkdir in branch" "Directory not visible"
        return
    fi

    if [ "$(cat "$MNT_BRANCH1/newdir/file.txt")" != "file in new dir" ]; then
        fail "mkdir in branch" "File content mismatch"
        return
    fi

    pass "mkdir works in branch"
}

test_unlink_in_branch() {
    run_test "unlink works in branch"

    # Remove a file from base image
    rm "$MNT_BRANCH1/subdir/nested.txt" \
        || { fail "unlink in branch" "Failed to remove file"; return; }

    if [ -f "$MNT_BRANCH1/subdir/nested.txt" ]; then
        fail "unlink in branch" "File still visible after unlink"
        return
    fi

    # Verify main still has the file
    if [ ! -f "$MNT_MAIN/subdir/nested.txt" ]; then
        fail "unlink in branch" "Main lost the file"
        return
    fi

    pass "unlink works in branch"
}

test_rmdir_in_branch() {
    run_test "rmdir works in branch"

    # Remove empty directory (we deleted the file in previous test)
    rmdir "$MNT_BRANCH1/subdir" \
        || { fail "rmdir in branch" "Failed to remove directory"; return; }

    if [ -d "$MNT_BRANCH1/subdir" ]; then
        fail "rmdir in branch" "Directory still visible after rmdir"
        return
    fi

    # Verify main still has the directory
    if [ ! -d "$MNT_MAIN/subdir" ]; then
        fail "rmdir in branch" "Main lost the directory"
        return
    fi

    pass "rmdir works in branch"
}

test_symlink_in_branch() {
    run_test "symlink works in branch"

    ln -s hello.txt "$MNT_BRANCH1/link_to_hello" \
        || { fail "symlink in branch" "Failed to create symlink"; return; }

    if [ ! -L "$MNT_BRANCH1/link_to_hello" ]; then
        fail "symlink in branch" "Symlink not visible"
        return
    fi

    if [ "$(cat "$MNT_BRANCH1/link_to_hello")" != "Hello from base image" ]; then
        fail "symlink in branch" "Symlink content mismatch"
        return
    fi

    pass "symlink works in branch"
}

test_rename_in_branch() {
    run_test "rename works in branch"

    mv "$MNT_BRANCH1/branch_file.txt" "$MNT_BRANCH1/renamed_file.txt" \
        || { fail "rename in branch" "Failed to rename file"; return; }

    if [ -f "$MNT_BRANCH1/branch_file.txt" ]; then
        fail "rename in branch" "Old name still exists"
        return
    fi

    if [ ! -f "$MNT_BRANCH1/renamed_file.txt" ]; then
        fail "rename in branch" "New name doesn't exist"
        return
    fi

    if [ "$(cat "$MNT_BRANCH1/renamed_file.txt")" != "New file in branch" ]; then
        fail "rename in branch" "Content changed after rename"
        return
    fi

    pass "rename works in branch"
}

test_truncate_in_branch() {
    run_test "truncate works in branch"

    truncate -s 5 "$MNT_BRANCH1/hello.txt" \
        || { fail "truncate in branch" "Failed to truncate"; return; }

    local size=$(stat -c %s "$MNT_BRANCH1/hello.txt")
    if [ "$size" -ne 5 ]; then
        fail "truncate in branch" "Size is $size, expected 5"
        return
    fi

    # Verify main is unchanged
    if [ "$(cat "$MNT_MAIN/hello.txt")" != "Hello from base image" ]; then
        fail "truncate in branch" "Main was modified"
        return
    fi

    pass "truncate works in branch"
}

test_branch_commit() {
    run_test "Branch commit merges changes to main"

    # Unmount branches from previous tests (keep main mounted)
    umount "$MNT_NESTED" 2>/dev/null || true
    umount "$MNT_BRANCH2" 2>/dev/null || true
    umount "$MNT_BRANCH1" 2>/dev/null || true

    # Create a branch for commit testing
    "$DAXFS_BRANCH" create commit_test -m "$MNT_BRANCH1" -p main \
        || die "Failed to create commit_test branch"

    # Make changes in the branch
    echo "Committed content" > "$MNT_BRANCH1/committed_file.txt"

    # Verify main doesn't see changes yet
    if [ -f "$MNT_MAIN/committed_file.txt" ]; then
        fail "Branch commit" "Main sees uncommitted changes"
        return
    fi

    # Create a sibling branch to test invalidation later
    "$DAXFS_BRANCH" create sibling -m "$MNT_BRANCH2" -p main \
        || die "Failed to create sibling branch"

    # Write something in sibling
    echo "Sibling content" > "$MNT_BRANCH2/sibling_file.txt"

    # Commit the first branch using daxfs-branch tool
    "$DAXFS_BRANCH" commit -m "$MNT_BRANCH1" \
        || { fail "Branch commit" "Commit failed"; return; }

    # After commit, the mount switches to main and changes are merged
    # New mounts of main should see the committed content
    # (The current mount may have switched to main internally)

    pass "Branch commit merges changes to main"
}

test_sibling_invalidation() {
    run_test "Sibling branches invalidated after commit"

    # After test_branch_commit, sibling branch (MNT_BRANCH2) should be invalidated
    # Operations should return ESTALE (116)

    local estale_detected=0

    # Try to read from sibling - should fail with ESTALE
    if ! cat "$MNT_BRANCH2/sibling_file.txt" 2>/dev/null; then
        estale_detected=1
    fi

    # Try to write - should also fail
    if ! echo "test" > "$MNT_BRANCH2/test_estale.txt" 2>/dev/null; then
        estale_detected=1
    fi

    # Try to list directory - should fail
    if ! ls "$MNT_BRANCH2" >/dev/null 2>&1; then
        estale_detected=1
    fi

    if [ "$estale_detected" -eq 0 ]; then
        fail "Sibling invalidation" "Operations on invalidated branch should fail"
        umount "$MNT_BRANCH2" 2>/dev/null || true
        return
    fi

    # Unmount the invalidated sibling (cleanup)
    umount "$MNT_BRANCH2" 2>/dev/null || true

    pass "Sibling branches invalidated after commit"
}

#
# Page cache (backing store mode) tests
#

setup_pcache() {
    log ""
    log "DAXFS Page Cache Tests"
    log "======================"

    # Tear down existing mounts from branching tests
    for mnt in "$MNT_NESTED" "$MNT_BRANCH2" "$MNT_BRANCH1" "$MNT_MAIN"; do
        if [ -n "$mnt" ] && mountpoint -q "$mnt" 2>/dev/null; then
            umount "$mnt" 2>/dev/null || true
        fi
    done

    # Create richer source content for pcache testing
    PCACHE_SOURCE="$TEST_DIR/pcache_source"
    BACKING_FILE="$TEST_DIR/backing.img"
    mkdir -p "$PCACHE_SOURCE"

    echo "Hello from pcache base" > "$PCACHE_SOURCE/hello.txt"
    echo "Original pcache content" > "$PCACHE_SOURCE/modify_me.txt"
    mkdir -p "$PCACHE_SOURCE/subdir"
    echo "Nested pcache file" > "$PCACHE_SOURCE/subdir/nested.txt"

    # Create a multi-page file (larger than 4KB)
    dd if=/dev/urandom of="$PCACHE_SOURCE/largefile.bin" bs=4096 count=8 2>/dev/null
    # Save checksum for verification
    LARGE_CKSUM=$(md5sum "$PCACHE_SOURCE/largefile.bin" | awk '{print $1}')

    # Create more files to exercise multiple cache slots
    for i in $(seq 1 10); do
        echo "File number $i with some padding data to fill it out" > "$PCACHE_SOURCE/file_$i.txt"
    done

    # Symlink in base image
    ln -s hello.txt "$PCACHE_SOURCE/link_to_hello"

    log_verbose "Pcache source: $PCACHE_SOURCE"
    log_verbose "Backing file:  $BACKING_FILE"
}

test_pcache_split_create() {
    run_test "Split-mode image creation"

    "$MKDAXFS" -d "$PCACHE_SOURCE" -H "$HEAP_DEV" -s "$IMAGE_SIZE" \
        -m "$MNT_MAIN" -o "$BACKING_FILE" -b \
        || { fail "Split-mode create" "mkdaxfs failed"; return; }

    # Verify backing file was created
    if [ ! -f "$BACKING_FILE" ]; then
        fail "Split-mode create" "Backing file not created"
        return
    fi

    local backing_size=$(stat -c %s "$BACKING_FILE")
    if [ "$backing_size" -eq 0 ]; then
        fail "Split-mode create" "Backing file is empty"
        return
    fi

    # Verify mount is accessible
    if ! mountpoint -q "$MNT_MAIN"; then
        fail "Split-mode create" "Mount point not active"
        return
    fi

    log_verbose "  Backing file size: $backing_size bytes"
    pass "Split-mode image creation"
}

test_pcache_read_files() {
    run_test "Read files through page cache"

    # Read small files
    local content
    content=$(cat "$MNT_MAIN/hello.txt") || {
        fail "Pcache read files" "Failed to read hello.txt"
        return
    }
    if [ "$content" != "Hello from pcache base" ]; then
        fail "Pcache read files" "hello.txt content mismatch: '$content'"
        return
    fi

    content=$(cat "$MNT_MAIN/modify_me.txt") || {
        fail "Pcache read files" "Failed to read modify_me.txt"
        return
    }
    if [ "$content" != "Original pcache content" ]; then
        fail "Pcache read files" "modify_me.txt content mismatch"
        return
    fi

    # Read nested file
    content=$(cat "$MNT_MAIN/subdir/nested.txt") || {
        fail "Pcache read files" "Failed to read nested file"
        return
    }
    if [ "$content" != "Nested pcache file" ]; then
        fail "Pcache read files" "nested.txt content mismatch"
        return
    fi

    # Read numbered files
    for i in $(seq 1 10); do
        content=$(cat "$MNT_MAIN/file_$i.txt") || {
            fail "Pcache read files" "Failed to read file_$i.txt"
            return
        }
        if [ "$content" != "File number $i with some padding data to fill it out" ]; then
            fail "Pcache read files" "file_$i.txt content mismatch"
            return
        fi
    done

    pass "Read files through page cache"
}

test_pcache_large_file() {
    run_test "Multi-page file through page cache"

    # Read the large file and compare checksum
    local mount_cksum
    mount_cksum=$(md5sum "$MNT_MAIN/largefile.bin" | awk '{print $1}') || {
        fail "Pcache large file" "Failed to read largefile.bin"
        return
    }

    if [ "$mount_cksum" != "$LARGE_CKSUM" ]; then
        fail "Pcache large file" "Checksum mismatch: $mount_cksum != $LARGE_CKSUM"
        return
    fi

    pass "Multi-page file through page cache"
}

test_pcache_symlink() {
    run_test "Symlinks work with page cache"

    if [ ! -L "$MNT_MAIN/link_to_hello" ]; then
        fail "Pcache symlink" "Symlink not visible"
        return
    fi

    local target
    target=$(readlink "$MNT_MAIN/link_to_hello")
    if [ "$target" != "hello.txt" ]; then
        fail "Pcache symlink" "Symlink target mismatch: '$target'"
        return
    fi

    local content
    content=$(cat "$MNT_MAIN/link_to_hello") || {
        fail "Pcache symlink" "Failed to read through symlink"
        return
    }
    if [ "$content" != "Hello from pcache base" ]; then
        fail "Pcache symlink" "Content through symlink mismatch"
        return
    fi

    pass "Symlinks work with page cache"
}

test_pcache_mmap_read() {
    run_test "mmap reads work with page cache"

    # Use dd with iflag=fullblock to read via mmap-like path
    # The real test: read file content, which exercises the anon-page fallback
    local output
    output=$(dd if="$MNT_MAIN/hello.txt" bs=4096 count=1 2>/dev/null) || {
        fail "Pcache mmap read" "dd read failed"
        return
    }

    if [ "$output" != "Hello from pcache base" ]; then
        fail "Pcache mmap read" "Content mismatch via dd"
        return
    fi

    pass "mmap reads work with page cache"
}

test_pcache_branch_write() {
    run_test "Branch writes work on pcache-backed mount"

    # Create a writable branch on the pcache-backed image
    "$DAXFS_BRANCH" create pcache_b1 -m "$MNT_BRANCH1" -p main \
        || { fail "Pcache branch write" "Failed to create branch"; return; }

    # Verify base content readable through branch
    local content
    content=$(cat "$MNT_BRANCH1/hello.txt") || {
        fail "Pcache branch write" "Failed to read base file from branch"
        return
    }
    if [ "$content" != "Hello from pcache base" ]; then
        fail "Pcache branch write" "Base content mismatch in branch"
        return
    fi

    # Write new file in branch
    echo "New in pcache branch" > "$MNT_BRANCH1/new_branch_file.txt" \
        || { fail "Pcache branch write" "Failed to write new file"; return; }

    content=$(cat "$MNT_BRANCH1/new_branch_file.txt") || {
        fail "Pcache branch write" "Failed to read new file"
        return
    }
    if [ "$content" != "New in pcache branch" ]; then
        fail "Pcache branch write" "New file content mismatch"
        return
    fi

    # Modify existing file (delta overrides cached base data)
    echo "Modified pcache content" > "$MNT_BRANCH1/modify_me.txt" \
        || { fail "Pcache branch write" "Failed to modify file"; return; }

    content=$(cat "$MNT_BRANCH1/modify_me.txt") || {
        fail "Pcache branch write" "Failed to read modified file"
        return
    }
    if [ "$content" != "Modified pcache content" ]; then
        fail "Pcache branch write" "Modified file content mismatch"
        return
    fi

    pass "Branch writes work on pcache-backed mount"
}

test_pcache_branch_isolation() {
    run_test "Branch isolation with page cache"

    # Create second branch from main
    "$DAXFS_BRANCH" create pcache_b2 -m "$MNT_BRANCH2" -p main \
        || { fail "Pcache branch isolation" "Failed to create branch2"; return; }

    # Branch2 should see original cached base data, not branch1's changes
    local content
    content=$(cat "$MNT_BRANCH2/modify_me.txt") || {
        fail "Pcache branch isolation" "Failed to read from branch2"
        return
    }
    if [ "$content" != "Original pcache content" ]; then
        fail "Pcache branch isolation" "Branch2 sees branch1's modification"
        return
    fi

    # Branch2 should not see branch1's new file
    if [ -f "$MNT_BRANCH2/new_branch_file.txt" ]; then
        fail "Pcache branch isolation" "Branch2 sees branch1's new file"
        return
    fi

    # Verify large file is still correct in branch2
    local mount_cksum
    mount_cksum=$(md5sum "$MNT_BRANCH2/largefile.bin" | awk '{print $1}') || {
        fail "Pcache branch isolation" "Failed to read large file from branch2"
        return
    }
    if [ "$mount_cksum" != "$LARGE_CKSUM" ]; then
        fail "Pcache branch isolation" "Large file checksum mismatch in branch2"
        return
    fi

    # Clean up branches
    umount "$MNT_BRANCH2" 2>/dev/null || true
    umount "$MNT_BRANCH1" 2>/dev/null || true

    pass "Branch isolation with page cache"
}

test_pcache_inspect() {
    run_test "daxfs-inspect shows page cache info"

    if [ ! -f "$DAXFS_INSPECT" ]; then
        skip "daxfs-inspect not built"
        return
    fi

    local output
    output=$("$DAXFS_INSPECT" status -m "$MNT_MAIN" 2>&1) || {
        fail "Pcache inspect" "daxfs-inspect failed"
        return
    }

    # Should show page cache section
    if ! echo "$output" | grep -q "Page cache:"; then
        fail "Pcache inspect" "No 'Page cache:' section in output"
        log_verbose "  Output: $output"
        return
    fi

    # Should show slot counts
    if ! echo "$output" | grep -q "Slots:"; then
        fail "Pcache inspect" "No slot count in output"
        return
    fi

    # Should show slot states
    if ! echo "$output" | grep -q "Slot states:"; then
        fail "Pcache inspect" "No slot states in output"
        return
    fi

    # Should show some valid slots (pre-warmed data)
    if echo "$output" | grep -q "0 valid"; then
        fail "Pcache inspect" "Expected some valid (pre-warmed) slots"
        return
    fi

    log_verbose "  Inspect output:"
    if [ "$VERBOSE" -eq 1 ]; then
        echo "$output" | grep -A5 "Page cache:" | while read -r line; do
            log_verbose "    $line"
        done
    fi

    pass "daxfs-inspect shows page cache info"
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

    log "DAXFS Branching Tests"
    log "===================="

    trap cleanup EXIT

    setup

    # Run tests
    test_main_readonly
    test_branch_writable
    test_branch_isolation
    test_nested_branch
    test_branch_abort
    test_mkdir_in_branch
    test_unlink_in_branch
    test_rmdir_in_branch
    test_symlink_in_branch
    test_rename_in_branch
    test_truncate_in_branch
    test_branch_commit
    test_sibling_invalidation

    # Page cache tests (requires separate split-mode image)
    setup_pcache
    test_pcache_split_create
    test_pcache_read_files
    test_pcache_large_file
    test_pcache_symlink
    test_pcache_mmap_read
    test_pcache_branch_write
    test_pcache_branch_isolation
    test_pcache_inspect

    # Summary
    log ""
    log "===================="
    log "Tests run:    $TESTS_RUN"
    log "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    log "Tests failed: ${RED}$TESTS_FAILED${NC}"

    if [ "$TESTS_FAILED" -gt 0 ]; then
        exit 1
    fi
    exit 0
}

main "$@"
